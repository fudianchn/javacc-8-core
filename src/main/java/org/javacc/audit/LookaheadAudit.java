/*-
 * #%L
 * JSQLParser library
 * %%
 * Copyright (C) 2004 - 2019 JSQLParser
 * %%
 * Dual licensed under GNU LGPL 2.1 or Apache License 2.0
 * #L%
 */
package org.javacc.audit;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

/** Repository entry point: read git and files, calculate both snapshots, write a review report. */
public final class LookaheadAudit {
    private static final Set<String> BUILD_INPUTS = AuditSupport.set("build.gradle", "settings.gradle",
            "build.gradle.kts", "settings.gradle.kts", "gradle.properties", "pom.xml", "gradlew",
            "gradlew.bat", "mvnw", "mvnw.cmd");
    private static final List<String> INPUT_DIRECTORIES =
            AuditSupport.list("src/main/java", "src/main/resources", ".mvn", "gradle");

    private LookaheadAudit() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 8) {
            throw new IllegalArgumentException(
                    "root base-ref report-directory evidence.tsv grammar-path cache-directory "
                            + "fail-on-findings full-analysis [additional-watched-path ...]");
        }
        audit(Paths.get(args[0]), args[1], Paths.get(args[2]), Paths.get(args[3]), args[4],
                Paths.get(args[5]), Boolean.parseBoolean(args[6]), Boolean.parseBoolean(args[7]),
                Arrays.asList(args).subList(8, args.length));
    }

    /**
     * Compare a Git baseline with a working grammar, writing inventories and scoped evidence reports.
     * Additional watched paths are repository-relative files or directory trees, including tests
     * and configuration that can affect the parser. No grammar is modified.
     */
    public static void audit(Path repository, String baseRef, Path reportDirectory, Path evidenceFile,
            String grammarPath, Path cacheDirectory, boolean failOnFindings, boolean full,
            List<String> additionalWatchedPaths) throws Exception {
        Path root = repository.toAbsolutePath().normalize();
        Path output = reportDirectory.toAbsolutePath().normalize();
        validatePath(grammarPath);
        if (!grammarPath.endsWith(".jj") && !grammarPath.endsWith(".jjt")) {
            throw new IllegalArgumentException("Expected a .jj or .jjt grammar: " + grammarPath);
        }
        if (Files.isSymbolicLink(root.resolve(grammarPath))) {
            throw new IllegalStateException("Symlink grammar: " + grammarPath);
        }
        List<String> watchedPaths = new ArrayList<>(additionalWatchedPaths);
        for (String path : watchedPaths) {
            validatePath(path);
        }
        Path cache = cacheDirectory.toAbsolutePath().normalize();
        Files.createDirectories(output);
        String base = baseCommit(root, baseRef);
        String engine = engine();
        Map<String, String> beforeInputs = baseInputs(root, base, watchedPaths);
        Map<String, String> afterInputs = workingInputs(root, watchedPaths);

        System.out.println("Calculating base lookahead facts at " + base);
        LookaheadSnapshot before =
                load(git(root, "show", base + ":" + grammarPath), output.resolve("base"),
                        LookaheadAnalysis.sha(LookaheadAnalysis.json(beforeInputs)), engine,
                        cache, null, full, grammarPath);
        System.out.println("Calculating working-tree lookahead facts");
        LookaheadSnapshot after =
                load(AuditSupport.readString(root.resolve(grammarPath)), output.resolve("current"),
                        LookaheadAnalysis.sha(LookaheadAnalysis.json(afterInputs)), engine,
                        cache, before, full, grammarPath);
        Evidence evidence = readEvidence(evidenceFile, after.contexts());
        Map<String, Object> report =
                LookaheadSnapshot.compare(before, after, evidence.bindings, evidence.scopes);
        report.put("baseCommit", base);
        report.put("watchedBefore", beforeInputs);
        report.put("watchedCurrent", afterInputs);
        report.put("analysisBefore", before.statistics);
        report.put("analysisCurrent", after.statistics);
        report.put("guarantee",
                "Tracked-context change detection only; no automatic rewrite or semantic equivalence claim.");
        AuditSupport.writeString(output.resolve("report.json"), LookaheadAnalysis.json(report) + "\n");
        writeInventory(output, after);
        Files.write(output.resolve("binding-candidates.tsv"), evidence.proposed);
        System.out.println("Lookahead report: " + output.resolve("report.json"));
        if (failOnFindings && Boolean.TRUE.equals(report.get("needsReview"))) {
            throw new IllegalStateException("Lookahead contexts require review; see report.json");
        }
    }

    private static void writeInventory(Path output, LookaheadSnapshot snapshot) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("anchor\tproduction\tline\tcolumn\tamount\ttriage\ttokenProbe");
        for (Map<String, Object> site : snapshot.sites) {
            lines.add(AuditSupport.list("anchor", "production", "line", "column", "amount", "triage",
                    "tokenProbe").stream().map(key -> String.valueOf(site.get(key)))
                    .collect(Collectors.joining("\t")));
        }
        Files.write(output.resolve("inventory.tsv"), lines);
        AuditSupport.writeString(output.resolve("inventory.json"),
                LookaheadAnalysis.json(snapshot.sites) + "\n");
    }

    private static String baseCommit(Path root, String argument) throws Exception {
        if (!git(root, "rev-parse", "--show-object-format").trim().equals("sha1")) {
            throw new IllegalArgumentException(
                    "This repository entry point requires Git SHA-1 objects");
        }
        String ref = argument.matches("0+") ? "HEAD" : argument;
        return git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").trim();
    }

    private static Evidence readEvidence(Path path,
            Map<String, List<Map<String, Object>>> contexts) throws IOException {
        Evidence evidence = new Evidence();
        for (String line : Files.readAllLines(path)) {
            if (!AuditSupport.isBlank(line) && !line.startsWith("#")) {
                evidence.bind(line, contexts);
            }
        }
        return evidence;
    }

    private static final class Evidence {
        private final Map<String, String> bindings = new TreeMap<>();
        private final Map<String, String> scopes = new TreeMap<>();
        private final List<String> proposed = new ArrayList<>();

        private void bind(String line, Map<String, List<Map<String, Object>>> contexts) {
            String[] fields = line.split("\t", 5);
            if (fields.length < 4 || AuditSupport.isBlank(fields[2]) || AuditSupport.isBlank(fields[3])) {
                throw new IllegalArgumentException(
                        "Evidence requires key, fingerprint, reason and test reference");
            }
            String scope = scope(fields);
            List<String> matching = contexts.keySet().stream()
                    .filter(k -> k.equals(fields[0]) || k.startsWith(fields[0] + ":"))
                    .collect(Collectors.toList());
            boolean unique = matching.size() == 1;
            String key = unique ? matching.get(0) : "unbound:" + fields[0];
            String fingerprint = scope.equals("token-probe") ? "tokenFingerprint" : "fingerprint";
            validateTokenScope(scope, unique ? contexts.get(key) : AuditSupport.list());
            bindings.put(key, fields[1]);
            scopes.put(key, scope);
            if (unique) {
                propose(fields, contexts.get(key), fingerprint, scope);
            }
        }

        private static String scope(String[] fields) {
            String scope = fields.length == 5 ? fields[4] : "context";
            if (!AuditSupport.set("context", "token-probe").contains(scope)) {
                throw new IllegalArgumentException("Unknown evidence scope: " + scope);
            }
            return scope;
        }

        private static void validateTokenScope(String scope, List<Map<String, Object>> bindings) {
            if (scope.equals("token-probe") && (bindings.size() != 1
                    || !bindings.get(0).containsKey("tokenFingerprint"))) {
                throw new IllegalArgumentException(
                        "token-probe scope requires one complete, positive, unnested token probe");
            }
        }

        private void propose(String[] fields, List<Map<String, Object>> bindings,
                String fingerprint, String scope) {
            if (bindings.size() == 1) {
                proposed.add(fields[0] + "\t" + bindings.get(0).get(fingerprint) + "\t"
                        + fields[2] + "\t" + fields[3]
                        + (fields.length == 5 ? "\t" + scope : ""));
            }
        }

    }

    static boolean watched(String path) {
        return watched(path, AuditSupport.list());
    }

    private static boolean watched(String path, List<String> additional) {
        return BUILD_INPUTS.contains(path) || java.util.stream.Stream
                .concat(INPUT_DIRECTORIES.stream(), additional.stream())
                .anyMatch(directory -> path.equals(directory) || path.startsWith(directory + "/"));
    }

    static LookaheadSnapshot generate(String source, Path directory, String external, String engine)
            throws Exception {
        return generate(source, directory, external, engine, null, "Fixture.jjt");
    }

    static LookaheadSnapshot load(String source, Path directory, String external, String engine,
            Path cache, LookaheadSnapshot previous, boolean full) throws Exception {
        return load(source, directory, external, engine, cache, previous, full, "Fixture.jjt");
    }

    static LookaheadSnapshot load(String source, Path directory, String external, String engine,
            Path cache, LookaheadSnapshot previous, boolean full, String grammarPath) throws Exception {
        long started = System.nanoTime();
        String key = LookaheadCache.key(source, engine + "\n" + grammarPath);
        LookaheadSnapshot snapshot = full ? null : LookaheadCache.read(cache, key);
        if (snapshot == null) {
            snapshot = generate(source, directory, external, engine, full ? null : previous, grammarPath);
            snapshot.statistics.put("frontEndCacheHit", false);
            snapshot.statistics.put("jjtreeRuns", grammarPath.endsWith(".jjt") ? 1 : 0);
            if (!full) {
                LookaheadCache.write(cache, key, snapshot);
            }
        } else {
            // Each read returns a separate value, including when base and current keys match.
            snapshot.externalHash = external;
            snapshot.statistics.put("mode", "content-hit");
            snapshot.statistics.put("frontEndCacheHit", true);
            for (String name : AuditSupport.list("jjtreeRuns", "javaCCParses", "parsedProductions",
                    "firstProductionsRecomputed", "firstComponentsRecomputed",
                    "ruleProductionsRecomputed", "followProductionsRecomputed", "sitesRecomputed",
                    "dependencyContextsRecomputed")) {
                snapshot.statistics.put(name, 0);
            }
            snapshot.statistics.put("firstProductionsReused", snapshot.productions.size());
            snapshot.statistics.put("followProductionsReused", snapshot.productions.size());
            snapshot.statistics.put("sitesReused", snapshot.sites.size());
            snapshot.statistics.put("dependencyContextsReused", snapshot.dependencyCache.size());
        }
        snapshot.statistics.put("elapsedMillis", (int) ((System.nanoTime() - started) / 1_000_000));
        return snapshot;
    }

    private static LookaheadSnapshot generate(String source, Path directory, String external,
            String engine, LookaheadSnapshot previous, String grammarPath) throws Exception {
        Files.createDirectories(directory);
        boolean tree = grammarPath.endsWith(".jjt");
        Path input = directory.resolve(tree ? "Grammar.jjt" : "Grammar.jj");
        Path generated = directory.resolve("generated");

        AuditSupport.writeString(input, source);
        if (!tree) {
            return LookaheadSnapshot.parse(source, external, engine, previous);
        }
        Path java = Paths.get(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java");
        Process process = new ProcessBuilder(java.toString(), "-Dfile.encoding=UTF-8", "-cp",
                System.getProperty("java.class.path"),
                "org.javacc.jjtree.Main", "-GRAMMAR_ENCODING=UTF-8",
                "-OUTPUT_DIRECTORY=" + generated, input.toString())
                .redirectErrorStream(true).redirectOutput(directory.resolve("jjtree.log").toFile())
                .start();
        if (process.waitFor() != 0) {
            throw new IllegalStateException(
                    "JJTree failed; see " + directory.resolve("jjtree.log"));
        }
        return LookaheadSnapshot.parse(AuditSupport.readString(generated.resolve("Grammar.jj")),
                external, engine, previous);
    }

    private static Map<String, String> baseInputs(Path root, String base, List<String> additional) throws Exception {
        Map<String, String> result = new TreeMap<>();
        for (String entry : git(root, "ls-tree", "-r", "-z", "--full-tree", base).split("\u0000")) {
            if (entry.isEmpty()) {
                continue;
            }
            String[] fields = entry.split("\t", 2);
            String[] header = fields[0].split(" ");

            if (watched(fields[1], additional)) {
                if (!header[1].equals("blob") || !header[0].startsWith("100")) {
                    throw new IllegalStateException("Unsupported watched input " + fields[1]);
                }
                result.put(fields[1], header[2]);
            }
        }
        return result;
    }

    static Map<String, String> workingInputs(Path root) throws Exception {
        return workingInputs(root, AuditSupport.list());
    }

    static Map<String, String> workingInputs(Path root, List<String> additional) throws Exception {
        Map<String, String> result = new TreeMap<>();
        List<String> pathsToWatch = new ArrayList<>(INPUT_DIRECTORIES);
        pathsToWatch.addAll(BUILD_INPUTS);
        pathsToWatch.addAll(additional);
        for (String folder : pathsToWatch) {
            Path start = root.resolve(folder);
            if (!Files.exists(start, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            try (java.util.stream.Stream<Path> paths = Files.walk(start)) {
                for (Path path : paths.collect(Collectors.toList())) {
                    if (Files.isSymbolicLink(path)) {
                        throw new IllegalStateException("Symlink in watched inputs: " + path);
                    }
                    if (Files.isRegularFile(path)) {
                        addInput(root, path, result);
                    }
                }
            }
        }
        return result;
    }

    private static void addInput(Path root, Path path, Map<String, String> result)
            throws Exception {
        if (Files.isSymbolicLink(path)) {
            throw new IllegalStateException("Symlink in watched inputs: " + path);
        }
        byte[] bytes = Files.readAllBytes(path);
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.update(("blob " + bytes.length + "\0").getBytes(StandardCharsets.US_ASCII));
        StringBuilder hash = new StringBuilder();
        for (byte b : digest.digest(bytes)) {
            hash.append(String.format(Locale.ROOT, "%02x", b));
        }
        result.put(root.relativize(path).toString().replace('\\', '/'), hash.toString());
    }

    private static void validatePath(String path) {
        Path value = Paths.get(path);
        if (AuditSupport.isBlank(path) || value.isAbsolute() || !value.normalize().equals(value)
                || value.startsWith("..") || path.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("Expected a repository-relative path: " + path);
        }
    }

    private static String engine() throws Exception {
        Map<String, String> inputs = new TreeMap<>();
        for (String property : AuditSupport.list("java.runtime.version", "java.vendor", "os.name")) {
            inputs.put(property, System.getProperty(property, ""));
        }
        inputs.put("jjtree-arguments", "file.encoding=UTF-8;GRAMMAR_ENCODING=UTF-8");
        // Hash actual loaded artifacts, independent of Maven coordinates or JAR filenames.
        Set<Path> artifacts = new TreeSet<>();
        for (Class<?> type : AuditSupport.list(LookaheadAudit.class, org.javacc.parser.Context.class,
                org.javacc.jjtree.Main.class)) {
            artifacts.add(Paths.get(type.getProtectionDomain().getCodeSource().getLocation().toURI()));
        }
        for (org.javacc.parser.CodeGenerator generator :
                ServiceLoader.load(org.javacc.parser.CodeGenerator.class)) {
            artifacts.add(Paths.get(generator.getClass().getProtectionDomain().getCodeSource()
                    .getLocation().toURI()));
        }
        int index = 0;
        for (Path artifact : artifacts) {
            String prefix = "artifact-" + index++ + "/";
            if (Files.isDirectory(artifact)) {
                try (java.util.stream.Stream<Path> files = Files.walk(artifact)) {
                    for (Path path : files.sorted().collect(Collectors.toList())) {
                        if (Files.isSymbolicLink(path)) {
                            throw new IllegalStateException("Symlink in analyzer inputs: " + path);
                        }
                        if (Files.isRegularFile(path)) {
                            inputs.put(prefix + artifact.relativize(path).toString().replace('\\', '/'),
                                    LookaheadAnalysis.sha(Files.readAllBytes(path)));
                        }
                    }
                }
            } else {
                inputs.put(prefix, LookaheadAnalysis.sha(Files.readAllBytes(artifact)));
            }
        }
        return LookaheadAnalysis.sha(LookaheadAnalysis.json(inputs));
    }

    private static String git(Path root, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(AuditSupport.list("git", "-C", root.toString()));
        command.addAll(AuditSupport.list(arguments));
        Process process =
                new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        byte[] output = AuditSupport.readAll(process.getInputStream());
        if (process.waitFor() != 0) {
            throw new IllegalStateException("Git read failed: " + command);
        }
        return new String(output, StandardCharsets.UTF_8);
    }
}
