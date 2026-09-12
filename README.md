# DkWess SecureRepo

DkWess SecureRepo is a small, dependency-light repository auditing toolkit for developers who want evidence about repository hygiene, GitHub Actions risks, governance files, dependency manifests, and potentially sensitive filenames.

> **Important:** a `PASS` result is not a security guarantee. SecureRepo is a focused static review tool, not a penetration test, vulnerability scanner, or certification.

## Why this project exists

Modern repositories accumulate CI workflows, dependency manifests, credentials-adjacent files, and governance requirements quickly. SecureRepo provides a transparent first-pass audit that is easy to run locally or in CI and produces machine-readable and human-readable evidence.

The project is implemented from scratch for public use. It does not contain private project code, customer data, credentials, or proprietary business logic.

## Current V1 checks

- repository documentation and governance files (`README`, `SECURITY`, `CONTRIBUTING`, license presence);
- `.gitignore` hygiene;
- potentially sensitive filenames and key/certificate extensions, without reading or printing secret contents;
- common dependency manifests across Python, Node.js, Go, Rust, Ruby, PHP, Java and Gradle projects;
- GitHub Actions heuristics for:
  - `pull_request_target`;
  - `permissions: write-all`;
  - `persist-credentials: true`;
  - remote actions that are not pinned to a full 40-character commit SHA;
- Markdown and JSON audit reports;
- CI-friendly exit codes with configurable severity threshold.

See [`docs/CHECKS.md`](docs/CHECKS.md) for exact behavior and limitations.

## Quick start

Requires Python 3.11+ and uses only the Python standard library at runtime.

```bash
python -m pip install -e .
dkwess-securerepo .
```

Or without installing:

```bash
PYTHONPATH=src python -m dkwess_securerepo .
```

On PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m dkwess_securerepo .
```

By default reports are written to:

```text
reports/audit.json
reports/audit.md
```

Example with a stricter CI threshold:

```bash
dkwess-securerepo . --fail-on MEDIUM
```

Exit code `0` means no finding met the selected failure threshold. Exit code `2` means at least one finding met or exceeded it. Tool/runtime errors use exit code `1`.

## Example output

```text
DkWess SecureRepo
Status: REVIEW_REQUIRED
Findings: 3
HIGH: 0 | MEDIUM: 2 | LOW: 1 | INFO: 0
Reports: reports/audit.json, reports/audit.md
```

## Design principles

1. **Evidence over claims.** Report what was checked and what was not.
2. **Fail honestly.** Unknown or risky conditions should not be silently converted into PASS.
3. **Minimal authority.** The scanner reads repository files and writes only its report directory.
4. **No secret echoing.** Sensitive-file checks are filename/path based; findings never print file contents.
5. **Portable by default.** Runtime functionality uses the Python standard library.
6. **`PASS != SECURITY GUARANTEE`.** A clean focused scan does not establish complete security.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m dkwess_securerepo . --output reports --fail-on HIGH
```

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md) first.

## Project status

**V1 / early public development.** The rules are intentionally conservative and limited. Future work may add SARIF output, configurable policies, SBOM integration, repository metadata checks, richer workflow parsing, and dependency lockfile analysis.

## License status

A software license has **not yet been selected** for this new repository. Public visibility does not by itself grant reuse rights. License selection is intentionally left as a maintainer decision before the first tagged release.
