# SecureRepo checks

This document describes the V1 checks implemented by DkWess SecureRepo. The scanner is intentionally narrow and evidence-oriented.

## Documentation and governance

| ID | Default severity | What it checks |
|---|---:|---|
| `SR-DOC-001` | MEDIUM | `README.md` exists |
| `SR-DOC-002` | LOW | `SECURITY.md` exists |
| `SR-DOC-003` | LOW | `CONTRIBUTING.md` exists |
| `SR-DOC-004` | MEDIUM | a common software license filename exists |

The tool checks presence only. It does not attempt to decide whether legal text is correct for your jurisdiction or project.

## Repository hygiene

| ID | Default severity | What it checks |
|---|---:|---|
| `SR-REP-001` | MEDIUM | `.gitignore` exists |
| `SR-REP-002` | LOW | `.gitignore` can be read |
| `SR-REP-003` | LOW | basic ignore coverage for environment files, Python cache, and report output |

`.gitignore` evaluation is deliberately heuristic. A repository can use valid alternative layouts that are not recognized by V1.

## Potentially sensitive filenames

`SR-SEC-001` is HIGH when the repository tree contains names/extensions commonly associated with secrets or private key material, including `.env`, `credentials.json`, `secrets.json`, `id_rsa`, `id_ed25519`, `.pem`, `.key`, `.p12`, `.pfx`, and `.kdbx`.

The check **does not read file contents**. `.env.example` and `.env.sample` are explicitly treated as examples.

A filename match is not proof that the file contains a real secret. It is a prompt for human review.

## Dependency manifests

`SR-SC-001` is INFO when no supported dependency manifest is found. V1 recognizes common Python, Node.js, Go, Rust, Ruby, PHP, Maven and Gradle manifest/lockfile names.

V1 inventories manifests only. It does not query vulnerability databases, install packages, resolve dependency graphs, or access the network.

## GitHub Actions

| ID | Default severity | What it checks |
|---|---:|---|
| `SR-GHA-000` | LOW | workflow file could not be read |
| `SR-GHA-001` | HIGH | `pull_request_target` trigger is present |
| `SR-GHA-002` | HIGH | `permissions: write-all` is present |
| `SR-GHA-003` | MEDIUM | `persist-credentials: true` is present |
| `SR-GHA-004` | HIGH | a remote `uses:` action has no `@ref` |
| `SR-GHA-005` | MEDIUM | a remote action is not pinned to a full 40-character commit SHA |

The V1 workflow parser is intentionally conservative and line-oriented; it is **not a general YAML parser**. It can miss equivalent YAML constructs or produce findings that require context. No GitHub token permissions are inferred beyond the exact implemented patterns.

## Result semantics

- `PASS`: no implemented check produced a finding.
- `REVIEW_REQUIRED`: one or more findings exist, but none are HIGH or CRITICAL.
- `FAIL`: at least one HIGH or CRITICAL finding exists.

The CLI failure threshold is separately configurable through `--fail-on`.

A status describes the scanner's implemented checks only:

**`PASS != SECURITY GUARANTEE`**

## Non-goals in V1

SecureRepo V1 does not perform penetration testing, exploit validation, malware detection, secret-content scanning, SAST, dependency vulnerability lookup, license legal analysis, branch-protection verification, GitHub organization policy review, or cloud configuration assessment.
