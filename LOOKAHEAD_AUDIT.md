# Lookahead review reports

`org.javacc.audit.LookaheadAudit` compares explicit lookahead decisions in a Git baseline and working tree. It writes an inventory, changed-context report and proposed evidence bindings. It does not rewrite a grammar or prove semantic equivalence.

Core and the audit CLI preserve the Java 8 bytecode/API target. Tests that compile generated fixtures require JDK 11 or newer. Run with core and the grammar's code generator on the classpath:

```sh
java -Xss4m -cp core.jar:java-generator.jar org.javacc.audit.LookaheadAudit \
  /path/to/repository HEAD /path/to/report /path/to/evidence.tsv \
  grammar/Commands.jjt /path/to/cache false false \
  policy regression/CommandsTest.java
```

Use `;` as the classpath separator on Windows. The arguments are repository, baseline commit/ref, report directory, evidence TSV, repository-relative grammar path, cache directory, fail-on-findings, forced-full-analysis, then optional repository-relative files or directory trees. `.jj` input is parsed directly; `.jjt` input first runs JJTree. Empty evidence files are supported. Generation or validation errors always fail; findings fail only when requested. Git SHA-1 repositories are currently required.

The Java API is `LookaheadAudit.audit(Path repository, String baseRef, Path reportDirectory, Path evidenceFile, String grammarPath, Path cacheDirectory, boolean failOnFindings, boolean full, List<String> additionalWatchedPaths)`. Paths passed as `Path` are resolved against the process working directory. Grammar and additional input paths are repository-relative. The API launches JJTree in a separate JVM for `.jjt`, and requires a complete ordinary Java classpath; module-path-only launching is not supported. Do not run overlapping calls against the same report directory. Fact computation uses JavaCC's existing option machinery and is not advertised as thread-safe.

## Inputs and cache

Production Java/resources, Maven/Gradle build files, wrappers and configuration are watched by default. Add all other inputs affecting parser behavior or the claimed regression evidence, including custom source roots, policy files and tests. Unlisted inputs cannot invalidate evidence. Symlinked watched files/trees are rejected. Source locations, absolute build paths, SQL corpora and project-specific tests do not belong in this module.

Cache entries contain checksummed, validated data, never serialized executable Java objects. Keys bind complete grammar content, input kind/path and actual loaded analyzer/core/generator contents plus runtime identity. Renaming a JAR does not bypass identity checks. Separate JVM content hits skip JJTree, grammar parsing and fixed-point analysis; external inputs are rebound on every invocation. A changed grammar still undergoes complete JavaCC syntax and semantic validation before incremental FIRST/nullable, FOLLOW and decision reuse. This is not an incremental grammar parser. Invalid or incompatible entries are cache misses.

Review bindings change after migration because the analyzer/generator identity changes. Review the report and actual code before copying proposed fingerprints into evidence. Proposed bindings are candidates, not approvals.

## Evidence and limits

TSV columns are key, fingerprint, reason, regression reference, and optional scope. Four-column records retain `context` scope. An explicit fifth column `token-probe` certifies one complete, positive, unnested token restriction with no predicate or Java side effects. It does not certify ASTs, continuations, error behavior or whole-production cleanup. Unknown scopes and unsupported token certificates fail.

Full contexts bind caller reachability, competing alternatives, prefix probes, complete callee closures and continuations. Opaque Java and uncertain lexical information cause conservative invalidation; the analyzer cannot prove arbitrary Java code independent. Neither FIRST/FOLLOW1 facts nor a token certificate authorize deleting a lookahead. Keep state/dialect/interruption guards and verify complete consumption and parser behavior separately.

## Tests and provenance

The audit suite includes independent JVM cache tests, changed-versus-cold oracles and small generated command grammars exercising caller/probe reachability, hidden Java calls, inline token names and lexical transitions. It does not require a SQL grammar. Generator-backed tests use the test-scoped Java generator; no generator dependency is added to core at runtime.

The implementation is adapted from JSQLParser's lookahead auditing work. Original copyright notices are retained under the Apache 2.0 option; see `LICENSE-LOOKAHEAD` and `LICENSE-APACHEV2`. Other JavaCC files retain their existing license.
