# Example audit interpretation

Imagine SecureRepo reports:

```text
Status: REVIEW_REQUIRED
HIGH: 0 | MEDIUM: 2 | LOW: 1 | INFO: 0
```

That means the implemented checks found items that deserve review, but none reached the default HIGH failure threshold.

A possible finding might be:

```text
SR-GHA-005 — Remote action is not pinned to a full commit SHA
Path: .github/workflows/ci.yml:12
Severity: MEDIUM
```

The recommended response is to review the action source and pin the action to a specific immutable commit SHA if that fits the project's update policy.

A `PASS` report should be interpreted narrowly: no implemented V1 check produced a finding for that snapshot. It is not evidence that the repository has no vulnerabilities.
