# Hardening and resource bounds

Version 0.0.9 adds explicit preflight limits before the public scanner API reads repository workflows.

Current defaults:

- maximum discovered files: 100,000;
- maximum individual GitHub Actions workflow text size: 1 MiB;
- repository root symbolic links are rejected by the public API;
- directory/file symbolic links remain skipped by recursive discovery.

View limits:

```bash
dkwess-securerepo --show-limits
```

These bounds reduce accidental denial-of-service behavior from pathological repository trees or unexpectedly large workflow files. They are not a sandbox and do not make arbitrary repository content trustworthy.

CI validates the project on Linux, macOS and Windows without third-party checkout actions. The scanner still does not execute target repository code during ordinary audits.
