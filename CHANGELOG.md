# Changelog

## [0.0.3] - 2026-09-12

### Public usability
- normalized the maintainer-requested public incubation version line to `0.0.3`;
- expanded README with installation, tutorials, command reference, architecture and project map;
- added Portuguese README, support, conduct and community templates;
- added a root composite `action.yml`.

### Scanner
- modularized models, rules, scanner and reporting while preserving `core.py` compatibility;
- added scan metrics and discovery-error evidence;
- added credential-adjacent path review;
- added Node.js and Go lockfile hygiene.

### GitHub Actions Analyzer V2
- self-hosted runner review;
- selected untrusted-event-context shell interpolation detection;
- selected curl/wget pipe-to-shell detection;
- Docker action digest-pinning review;
- CRITICAL review for `pull_request_target` combined with pull-request-head content references.

### Evidence and CLI
- report schema v3;
- stable finding fingerprints;
- `--list-checks`, `--explain`, `--json-stdout`, `--require-full-coverage`;
- version and scan metrics in reports/console.

### Testing
- expanded unit tests and CI smoke checks.

### Known limitation
- software license selection remains pending and is the legal/public-reuse blocker before calling the project fully open source.

## [development milestone 0.2.0] - 2026-09-12
- evidence and coverage states;
- finding confidence/categories;
- report schema v2;
- architecture, threat model and roadmap;
- README redesign.

## [initial foundation] - 2026-09-12
- first functional scanner, reports, tests and CI.
