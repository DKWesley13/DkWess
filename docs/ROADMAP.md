# Roadmap

SecureRepo uses staged releases so public maturity claims remain aligned with implemented evidence.

## Release train

### 0.2 — Evidence & Coverage Foundation

Status: **implemented**

- finding categories;
- confidence field;
- capability assessment states;
- coverage states;
- capability matrix in Markdown/JSON/console;
- symlink-safe recursive discovery;
- architecture, threat-model and report-schema documentation.

### 0.3 — GitHub Actions Analyzer V2

Planned:

- safer structural parsing strategy;
- job-level and workflow-level permissions;
- OIDC permission checks;
- untrusted checkout/dataflow heuristics;
- shell/script risk surfaces;
- reusable workflows;
- confidence calibration;
- fixture corpus for real-world workflow variants.

### 0.4 — Known Findings Baseline

Planned:

- stable finding fingerprints;
- `baseline create`;
- `baseline compare`;
- new/resolved/unchanged findings;
- regression exit mode;
- baseline schema versioning;
- explicit prevention of "accepted finding = PASS".

### 0.5 — Supply Chain & Provenance

Planned:

- lockfile coverage;
- install/build script inventory;
- dependency source/provenance evidence;
- upstream repository metadata;
- audited SHA records;
- upstream drift comparison.

### 0.6 — SARIF / GitHub Code Scanning

Planned:

- SARIF 2.1.0 output;
- rule catalogue metadata;
- GitHub Code Scanning upload example;
- location mapping;
- deterministic result fingerprints.

### 0.7 — SBOM

Planned:

- SBOM discovery;
- CycloneDX/SPDX strategy;
- generation or validation mode;
- package identity normalization;
- provenance linkage.

### 0.8 — Policy Engine

Planned:

- `.securerepo.yml`;
- project-specific severity thresholds;
- capability requirements;
- allowed exceptions with expiry/owner/reason;
- policy validation.

### 0.9 — Public-release hardening

Planned:

- packaging verification;
- fresh-install tests;
- Windows/Linux/macOS test matrix;
- adversarial test corpus;
- performance/resource limits;
- terminal sanitization;
- documentation UX;
- public examples.

### 1.0 — Audited public release

Target gate:

```text
Architecture Review             PASS
Core Tests                      PASS
Adversarial Tests               PASS
Windows                         PASS
Linux                           PASS
macOS                           PASS
Packaging                       PASS
Fresh Installation              PASS
GitHub Actions                  PASS
Self Audit                      PASS
Documentation                   PASS
Security Documentation          PASS
SARIF                           PASS
JSON Schema                     PASS
Baseline Engine                 PASS
No known HIGH regression        PASS
License                         SELECTED
```

A 1.0 release should not be created until the license is explicitly selected.
