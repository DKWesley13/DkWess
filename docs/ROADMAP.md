# SecureRepo roadmap

## Completed path to v1

| Version | Milestone | Status |
|---|---|---|
| 0.0.3 | public UX + GitHub Actions Analyzer V2 | ✅ |
| 0.0.4 | known-findings baseline + regression gate | ✅ |
| 0.0.5 | supply-chain inventory + local provenance | ✅ |
| 0.0.6 | SARIF 2.1.0 | ✅ |
| 0.0.7 | static CycloneDX SBOM inventory | ✅ |
| 0.0.8 | TOML/JSON policy engine | ✅ |
| 0.0.9 | resource hardening + cross-platform CI | ✅ |
| 1.0.0 | technically stable public-source API/CLI milestone | ✅ |

## Separate legal gate

A software license remains a maintainer decision. v1.0.0 technical stability does not by itself grant reuse rights. The project should not be described as fully open source until an explicit license is selected and added.

## Post-1.0 candidates

Future work can deepen structural GitHub Actions parsing, broaden manifest ecosystems, support authoritative build-generated SBOM/provenance ingestion, add richer policy schemas, improve performance for very large monorepos, publish signed release artifacts, and integrate more CI providers.

Every future feature should preserve `PASS != SECURITY GUARANTEE`, explicit coverage, secret-safe reporting and non-execution of target repository code during ordinary scans.
