# Report schema v3

SecureRepo v0.0.3 writes JSON schema version `3`.

Top-level fields include `schema_version`, `tool`, `tool_version`, `root`, `status`, `security_guarantee`, `statement`, severity counts, coverage counts, `coverage_percent`, scan `metrics`, `manifests`, `capabilities`, and `findings`.

A finding includes `check_id`, `severity`, `title`, `path`, `detail`, `remediation`, `category`, `confidence`, and a short stable `fingerprint`.

Example:
```json
{
  "check_id": "SR-GHA-007",
  "severity": "HIGH",
  "category": "github-actions",
  "confidence": "HIGH",
  "path": ".github/workflows/ci.yml:25",
  "fingerprint": "0123456789abcdefabcd"
}
```

The fingerprint is SHA-256-derived from rule ID, evidence path and title. It is intended for future baseline comparison, not repository attestation.

Capability objects contain `capability`, `assessment`, `coverage`, `finding_count`, and `notes`.

Metrics contain `files_discovered`, `symlinks_skipped`, `discovery_errors`, `workflows_discovered`, and `manifests_detected`.

Before 1.0, consumers should check `schema_version`; report evolution may occur between incubation releases.
