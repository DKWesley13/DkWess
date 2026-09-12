# Contributing

Thanks for considering a contribution to DkWess SecureRepo.

## Principles

Changes should preserve these rules:

- do not claim complete security from a focused static scan;
- do not print or store secret contents in findings;
- prefer deterministic checks with clear evidence;
- keep runtime dependencies minimal;
- document false-positive and false-negative limitations;
- add or update tests for behavior changes;
- do not add telemetry, external network calls, or repository mutation without an explicit design review.

## Development setup

Python 3.11+ is required.

```bash
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
```

On PowerShell:

```powershell
python -m pip install -e .
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

## Pull requests

A good pull request should explain:

1. the problem being solved;
2. the exact checks or behavior changed;
3. test evidence;
4. known limitations or compatibility impact;
5. whether the change expands filesystem, network, process, or GitHub permissions.

Keep unrelated refactors out of security-rule changes whenever possible.

## New checks

Each new check should have a stable ID, severity, concise title, evidence path, explanation, remediation guidance, and tests for both positive and negative cases.
