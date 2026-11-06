# Release-candidate review

## Reproduction and usefulness

The README starts with the concrete output: ZIP inventory, input SHA-256, suspicious selected-text evidence, and explicit incomplete-inspection reasons. A developer can run the shipped samples with Python alone; installation, accounts, API keys, and archive extraction are unnecessary.

A fresh standard-library-only virtual environment passed all 11 test methods. The three bundled CLI cases returned the expected exit codes (0, 0, 2), and their complete stdout bytes matched the example reports. The instruction-like demo produced seven categories and ten findings with verified lines and matched text. Sample/report regeneration was identical on the verified environment. See `REPRODUCIBILITY.json`.

## Scope and disclosure

Source, documentation, generated JSON, and decompressed synthetic sample contents were reviewed for credentials, personal filesystem paths, nonpublic links, and operational records. The distribution contains only the standalone tool, tests, generator, synthetic samples, examples, and release documentation. Instruction-like strings are labelled as untrusted evidence.

The parser and bounds were retained. Two project-specific literal alternatives were removed for disclosure hygiene; the shipped demo uses the already-existing generic owner-approval and warning-suppression patterns. No detection category or pattern was added. This is a limited synthetic reproduction, not an accuracy evaluation.

The README distinguishes selected text from unscanned content, declared ZIP metadata from verified selected streams, COMPLETE from UNKNOWN, and report labels from execution permission. False positives, missed instructions, unsupported content, real-world archives, malware detection, model behavior, and OS isolation remain outside the demonstrated claims.

## Release decision

No unresolved functional or disclosure blocker was found in the reviewed candidate. Remaining **publication blockers** are rightsholder confirmation and license selection/application. `RELEASE_DECISION.md` compares MIT and Apache-2.0; neither has been granted. Public release remains pending a separate maintainer decision.

Additional detection rules, packaging, CI matrices, support for other platforms, and real-world accuracy benchmarks are follow-up work, not prerequisites for reproducing the bundled samples. They are not claimed as completed.
