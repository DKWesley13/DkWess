# Report Schema

## Version

SecureRepo `0.2.0` emits JSON report schema version `2`.

Schema versioning is separate from package versioning. A breaking report-contract change requires a schema-version increment.

## Top-level document

```json
{
  "schema_version": 2,
  "tool": "DkWess SecureRepo",
  "root": "/path/to/repository",
  "status": "REVIEW_REQUIRED",
  "security_guarantee": false,
  "statement": "PASS != SECURITY GUARANTEE",
  "counts": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0
  },
  "coverage_counts": {
    "FULL": 4,
    "PARTIAL": 0,
    "UNKNOWN": 1
  },
  "manifests": ["pyproject.toml"],
  "capabilities": [],
  "findings": []
}
```

## Finding

```json
{
  "check_id": "SR-GHA-005",
  "severity": "MEDIUM",
  "title": "Remote action is not pinned to a full commit SHA",
  "path": ".github/workflows/ci.yml:12",
  "detail": "Action `owner/action` uses mutable or non-SHA reference `v1`.",
  "remediation": "Review the action source and pin it to an immutable 40-character commit SHA.",
  "category": "github-actions",
  "confidence": "HIGH"
}
```

### Severity

Allowed values:

`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### Confidence

Allowed values:

`LOW`, `MEDIUM`, `HIGH`.

Confidence describes confidence in the **rule match**, not certainty of exploitability or business impact.

## Capability assessment

```json
{
  "capability": "GitHub Actions",
  "assessment": "PASS",
  "coverage": "FULL",
  "finding_count": 0,
  "notes": "Workflow files were inspected with conservative line-oriented heuristics."
}
```

### Assessment

- `PASS`
- `FAIL`
- `BLOCKED`
- `NOT_ASSESSED`

### Coverage

- `FULL`
- `PARTIAL`
- `UNKNOWN`

Assessment and coverage are separate dimensions.

Examples:

```text
PASS / FULL
FAIL / FULL
BLOCKED / PARTIAL
NOT_ASSESSED / UNKNOWN
```

## Compatibility rule

Consumers should reject unsupported future schema versions rather than silently assuming backward compatibility.

## Security semantics

A report with `status: PASS` is not a security certification. It means the implemented checks did not produce findings for the assessed snapshot and capability coverage is reported separately.
