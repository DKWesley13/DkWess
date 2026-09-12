# Audit methodology

SecureRepo follows an evidence-first model.

For each capability it asks:
1. Did implemented checks run?
2. Did a check produce a finding?
3. Was implemented coverage FULL, PARTIAL, or UNKNOWN?
4. What evidence can be shown without exposing sensitive content?
5. What remediation can a maintainer review?

Assessment and coverage are independent: `PASS / FULL`, `FAIL / FULL`, `BLOCKED / PARTIAL`, `NOT_ASSESSED / UNKNOWN`.

Every finding contains a stable rule ID, severity, confidence, category, path/line evidence when available, explanation, remediation and a short stable fingerprint.

Repository discovery skips selected generated/vendor directories, does not follow symlinks, counts traversal errors, and does not hide incomplete traversal behind PASS.

Sensitive-file checks use filename/path heuristics and do not inspect or print matched file contents. False positives and false negatives remain possible.

The GitHub Actions analyzer is text-aware and conservative. It can identify selected trigger, permissions, credential-persistence, pinning, self-hosted-runner, shell-context, pipe-to-shell and privileged checkout patterns. It is not a complete YAML semantic engine.

Dependency analysis inventories recognized manifests and selected lockfile relationships. It does not resolve dependency graphs, query vulnerability databases, or install packages.

Severity is review priority under the built-in rule model, not a universal CVSS score. Confidence reflects how directly the implemented pattern supports the finding, not exploitation probability.

Non-goals in v0.0.3 include SAST, DAST, malware scanning, active exploit verification, secret-content scanning, vulnerability-database dependency resolution, cloud auditing, branch-protection API auditing, organization policy auditing, complete YAML semantics, and legal license analysis.
