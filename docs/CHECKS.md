# SecureRepo checks

This document describes the V0.2 checks implemented by DkWess SecureRepo. The scanner is intentionally narrow and evidence-oriented.

Every finding now includes a **category** and **confidence**, and the report contains a separate capability matrix with **assessment** and **coverage** states.

## Documentation and governance

| ID | Severity | Category | What it checks |
|---|---:|---|---|
| `SR-DOC-001` | MEDIUM | governance | `README.md` exists |
| `SR-DOC-002` | LOW | governance | `SECURITY.md` exists |
| `SR-DOC-003` | LOW | governance | `CONTRIBUTING.md` exists |
| `SR-DOC-004` | MEDIUM | governance | a common software license filename exists |

The tool checks presence only. It does not decide whether legal text is correct for a jurisdiction or project.

## Repository hygiene

| ID | Severity | Category | What it checks |
|---|---:|---|---|
| `SR-REP-001` | MEDIUM | repository-hygiene | `.gitignore` exists |
| `SR-REP-002` | LOW | repository-hygiene | `.gitignore` can be read |
| `SR-REP-003` | LOW | repository-hygiene | basic ignore coverage for environment files, Python cache and report output |

`.gitignore` evaluation is heuristic. Valid alternative layouts may not be recognized by V0.2.

## Potentially sensitive filenames

`SR-SEC-001` is HIGH when the repository tree contains names/extensions commonly associated with secrets or private-key material, including `.env`, `credentials.json`, `secrets.json`, `id_rsa`, `id_ed25519`, `.pem`, `.key`, `.p12`, `.pfx`, and `.kdbx`.

The check **does not read file contents**. `.env.example` and `.env.sample` are explicitly treated as examples.

The recursive walker skips symbolic links.

A filename match is not proof that the file contains a real secret. Its confidence is intentionally `MEDIUM`.

## Dependency manifests

`SR-SC-001` is INFO when no supported dependency manifest is found. V0.2 recognizes common Python, Node.js, Go, Rust, Ruby, PHP, Maven and Gradle manifest/lockfile names.

When no recognized manifest exists, the **Dependency Inventory capability is `NOT_ASSESSED / UNKNOWN`** rather than claiming a dependency-security PASS.

V0.2 inventories manifests only. It does not query vulnerability databases, install packages, resolve dependency graphs, or access the network.

## GitHub Actions

| ID | Severity | Category | What it checks |
|---|---:|---|---|
| `SR-GHA-000` | LOW | github-actions | workflow file could not be read |
| `SR-GHA-001` | HIGH | github-actions | `pull_request_target` trigger is present |
| `SR-GHA-002` | HIGH | github-actions | `permissions: write-all` is present |
| `SR-GHA-003` | MEDIUM | github-actions | `persist-credentials: true` is present |
| `SR-GHA-004` | HIGH | github-actions | a remote `uses:` action has no `@ref` |
| `SR-GHA-005` | MEDIUM | github-actions | a remote action is not pinned to a full 40-character commit SHA |

The V0.2 workflow parser is conservative and line-oriented; it is **not a general YAML parser**. It can miss equivalent YAML constructs or produce findings that require context.

If workflow files exist but one cannot be read, capability coverage becomes `PARTIAL` and assessment becomes `BLOCKED`.

If no supported workflow files exist, the capability is `NOT_ASSESSED / UNKNOWN`.

## Result semantics

Top-level status remains intentionally simple:

- `PASS`: no implemented check produced a finding and no capability is blocked;
- `REVIEW_REQUIRED`: findings below HIGH exist and/or a capability is blocked;
- `FAIL`: at least one HIGH or CRITICAL finding exists.

Capability assessment is more precise:

- `PASS`;
- `FAIL`;
- `BLOCKED`;
- `NOT_ASSESSED`.

Coverage:

- `FULL`;
- `PARTIAL`;
- `UNKNOWN`.

The CLI failure threshold is separately configurable through `--fail-on`.

A status describes the scanner's implemented checks only:

**`PASS != SECURITY GUARANTEE`**

## Non-goals in V0.2

SecureRepo V0.2 does not perform penetration testing, exploit validation, malware detection, secret-content scanning, SAST, dependency vulnerability lookup, license legal analysis, branch-protection verification, GitHub organization policy review, cloud configuration assessment, or automatic remediation.
