# Built-in checks — v0.0.3

Live catalog:
```bash
dkwess-securerepo --list-checks
dkwess-securerepo --explain SR-GHA-010
```

## Governance
| Rule | Severity | Purpose |
|---|---|---|
| `SR-DOC-001` | MEDIUM | README presence |
| `SR-DOC-002` | LOW | SECURITY presence |
| `SR-DOC-003` | LOW | CONTRIBUTING presence |
| `SR-DOC-004` | MEDIUM | license file presence |

## Repository hygiene
| Rule | Severity | Purpose |
|---|---|---|
| `SR-REP-001` | MEDIUM | `.gitignore` missing |
| `SR-REP-002` | LOW | `.gitignore` unreadable |
| `SR-REP-003` | LOW | basic ignore coverage incomplete |
| `SR-REP-004` | LOW | recursive discovery incomplete |

## Sensitive files
| Rule | Severity | Purpose |
|---|---|---|
| `SR-SEC-001` | HIGH | secret/key-associated filename or extension |
| `SR-SEC-002` | MEDIUM | credential-adjacent configuration path |

These checks do not read or print matched file contents.

## Dependency inventory
| Rule | Severity | Purpose |
|---|---|---|
| `SR-SC-001` | INFO | no recognized manifest |
| `SR-SC-002` | LOW | package.json without recognized lockfile |
| `SR-SC-003` | LOW | go.mod without go.sum |

## GitHub Actions Analyzer V2
| Rule | Severity | Purpose |
|---|---|---|
| `SR-GHA-000` | LOW | workflow unreadable |
| `SR-GHA-001` | HIGH | `pull_request_target` review |
| `SR-GHA-002` | HIGH | `permissions: write-all` |
| `SR-GHA-003` | MEDIUM | `persist-credentials: true` |
| `SR-GHA-004` | HIGH | remote action missing `@ref` |
| `SR-GHA-005` | MEDIUM | action not pinned full SHA |
| `SR-GHA-006` | MEDIUM | self-hosted runner boundary |
| `SR-GHA-007` | HIGH | selected untrusted context in shell |
| `SR-GHA-008` | HIGH | selected pipe-to-shell pattern |
| `SR-GHA-009` | MEDIUM | Docker action not digest-pinned |
| `SR-GHA-010` | CRITICAL | `pull_request_target` + PR-head content |

The analyzer is not a full YAML semantic interpreter and can miss aliases, indirection, generated/reusable workflows, API context and complex shell semantics.
