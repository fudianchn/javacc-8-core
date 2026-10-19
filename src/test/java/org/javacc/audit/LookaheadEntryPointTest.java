package org.javacc.audit;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LookaheadEntryPointTest {
    @TempDir
    Path root;

    private static final String GRAMMAR = "options { STATIC=false; }\n"
            + "PARSER_BEGIN(Commands) public class Commands {} PARSER_END(Commands)\n"
            + "TOKEN: { <OPEN: \"open\"> | <CLOSE: \"close\"> }\n"
            + "void Command():{} { (LOOKAHEAD(<OPEN>) <OPEN> | <CLOSE>) <EOF> }";

    @Test
    void plainGrammarNeedsNoJjtreeAndCustomInputsInvalidateEvidenceOnWarmHit() throws Exception {
        Files.writeString(root.resolve("commands.jj"), GRAMMAR);
        Files.createDirectories(root.resolve("policy"));
        Files.writeString(root.resolve("policy/rules.ini"), "open=true\n");
        git("init", "-q");
        git("add", ".");
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "base");
        Path evidence = root.resolve("review.tsv");
        Files.writeString(evidence, "Command\tstale\tcommand dispatch\tcommand cases\n");
        run("cold", evidence, true);
        assertFalse(Files.exists(root.resolve("cold/base/generated")));
        Files.writeString(evidence, Files.readString(root.resolve("cold/binding-candidates.tsv")));
        String warm = run("warm", evidence, false);
        assertTrue(warm.contains("\"needsReview\":false"));
        assertTrue(warm.contains("\"jjtreeRuns\":0"));
        // Populate a persistent entry, then verify independent CLI invocations use it.
        run("populate", evidence, false);
        Files.writeString(root.resolve("policy/rules.ini"), "open=false\n");
        String changed = run("changed", evidence, false);
        assertTrue(changed.contains("\"frontEndCacheHit\":true"));
        assertTrue(changed.contains("\"javaCCParses\":0"));
        assertTrue(changed.contains("\"needsReview\":true"));
        assertTrue(changed.contains("production-Java-resources-or-build"));
    }

    @Test
    void unsupportedAndEscapingGrammarPathsFailBeforeAnalysis() {
        for (String grammar : List.of("../other.jj", "/tmp/other.jj", "commands.txt")) {
            assertThrows(IllegalArgumentException.class,
                    () -> LookaheadAudit.audit(root, "HEAD", root.resolve("report"),
                            root.resolve("evidence"), grammar, root.resolve("cache"), false, false,
                            List.of()));
        }
    }

    private String run(String output, Path evidence, boolean full) throws Exception {
        GeneratedLookaheadParser.run(root, "UTF-8", LookaheadAudit.class.getName(), root.toString(),
                "HEAD", root.resolve(output).toString(), evidence.toString(), "commands.jj",
                root.resolve("cache").toString(), "false", Boolean.toString(full), "policy");
        return Files.readString(root.resolve(output + "/report.json"));
    }

    private void git(String... args) throws Exception {
        var command = new java.util.ArrayList<>(List.of("git", "-C", root.toString()));
        command.addAll(List.of(args));
        var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), output);
    }
}
