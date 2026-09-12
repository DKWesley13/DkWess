# Changelog

All notable project changes are recorded here.

## 0.2.0 - Evidence & Coverage Foundation

### Added

- capability assessment model: `PASS`, `FAIL`, `BLOCKED`, `NOT_ASSESSED`;
- coverage model: `FULL`, `PARTIAL`, `UNKNOWN`;
- finding categories and confidence;
- capability matrix in console, Markdown and JSON reports;
- JSON report schema version 2;
- architecture documentation and Mermaid system diagrams;
- project mind map;
- threat model;
- staged roadmap to 1.0;
- report-schema documentation;
- explicit symlink skipping during recursive repository discovery;
- tests for capability semantics and symlink behavior.

### Changed

- dependency inventory no longer implies coverage when no recognized manifest exists;
- GitHub Actions capability reports `NOT_ASSESSED / UNKNOWN` when no supported workflow exists;
- unreadable workflows can reduce GitHub Actions coverage to `PARTIAL`;
- public project version advanced to `0.2.0`.

### Security

- maintained the no-secret-echo invariant for sensitive filename checks;
- documented repository input as untrusted data;
- documented parser and resource-limit gaps still requiring hardening.

## 0.1.0 - Initial public foundation

- repository governance scanner;
- GitHub Actions hygiene checks;
- sensitive filename checks;
- dependency manifest inventory;
- Markdown/JSON reports;
- unit tests;
- CI self-audit;
- SECURITY and CONTRIBUTING policies.
