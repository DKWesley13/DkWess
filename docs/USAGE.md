# CLI usage

```text
dkwess-securerepo [PATH] [OPTIONS]
```

Examples:
```bash
dkwess-securerepo .
dkwess-securerepo ../my-project
dkwess-securerepo . --output build/security-audit
dkwess-securerepo . --fail-on MEDIUM
dkwess-securerepo . --require-full-coverage
dkwess-securerepo . --no-reports --json-stdout
dkwess-securerepo --list-checks
dkwess-securerepo --explain SR-GHA-008
dkwess-securerepo --version
```

Windows:
```powershell
dkwess-securerepo "C:\Projects\my-project"
```

## Severity thresholds
`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

A finding at or above `--fail-on` returns exit code 2.

## Strict coverage
`--require-full-coverage` returns exit code 3 if no finding threshold failed but any capability is `PARTIAL` or `UNKNOWN`.

A repository with no GitHub Actions workflows normally has GitHub Actions `NOT_ASSESSED / UNKNOWN`, so strict coverage should only be enabled when that policy is appropriate.

## Suggested local workflow
1. run default audit;
2. read `reports/audit.md`;
3. explain unfamiliar rules;
4. fix or document accepted risk;
5. rerun with a stricter threshold if appropriate.

## Exit codes
| Code | Meaning |
|---:|---|
| 0 | success under configured policy |
| 1 | runtime/configuration error |
| 2 | finding threshold reached |
| 3 | full coverage required but not achieved |
