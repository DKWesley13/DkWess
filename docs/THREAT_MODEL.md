# Threat model

Assets include repository-source confidentiality, secret values, evidence integrity, CI credentials/token scope, and user trust in assessment semantics.

Primary threats:
- secret disclosure through scanner output;
- symlink traversal outside the requested root;
- accidental target-code execution;
- false assurance from incomplete scans;
- CI privilege escalation patterns;
- supply-chain compromise of SecureRepo itself.

Mitigations in v0.0.3 include filename/path-only secret heuristics, no symlink following, no target dependency installation/execution, explicit coverage states, GitHub Actions risk checks, standard-library-only runtime, and CI that avoids third-party checkout actions.

Out of scope: active penetration testing, exploit development, malware analysis, full secret-content scanning, full YAML semantics, vulnerability databases, cloud/API assessment, org-wide GitHub administration audits and legal license analysis.

False positives/negatives remain possible. Use SecureRepo as one evidence source in a broader review process.
