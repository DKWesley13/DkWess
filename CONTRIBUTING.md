# Contributing to DkWess SecureRepo

Read `README.md`, `docs/ARCHITECTURE.md`, `docs/AUDIT_METHODOLOGY.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md` first.

## Development setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Quality gate
```bash
python -m compileall -q src
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m dkwess_securerepo --version
PYTHONPATH=src python -m dkwess_securerepo --list-checks
PYTHONPATH=src python -m dkwess_securerepo . --output reports --fail-on HIGH
```

## Pull requests
Explain the problem, behavior changed, test evidence, false-positive/false-negative considerations, security/compatibility impact, and whether filesystem/network/process/GitHub permissions expand.

## New rules
Add a stable ID in `rules.py`, category, severity, confidence, description, remediation, positive/negative tests, documentation, and explicit limitations.

Preserve: `PASS != SECURITY GUARANTEE`, unknown is not PASS, no target-code execution, no telemetry/network access without design review, no repository mutation during scans, no secret echoing, minimal runtime dependencies, deterministic/explainable evidence.
