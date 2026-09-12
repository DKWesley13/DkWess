# Getting started

SecureRepo is a local-first repository auditor. It reads a repository tree, evaluates governance, hygiene, dependency and GitHub Actions checks, then writes structured evidence. It does not exploit a target, execute arbitrary repository code, install target dependencies, or guarantee security.

## Requirements
- Python 3.11+
- Git recommended
- read access to the target repository
- write access only to the selected report directory

## Windows PowerShell
```powershell
git clone https://github.com/DKWesley13/DkWess.git
cd DkWess
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
dkwess-securerepo --version
```

If activation is blocked, run the venv Python directly:
```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m dkwess_securerepo --version
```

## Linux / macOS
```bash
git clone https://github.com/DKWesley13/DkWess.git
cd DkWess
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
dkwess-securerepo --version
```

## First audit
```bash
dkwess-securerepo .
dkwess-securerepo /path/to/project
```

Reports:
```text
reports/
├── audit.json
└── audit.md
```

`audit.md` is for humans; `audit.json` is for automation.

## Read capability states
Example:
```text
Governance: FAIL / FULL
GitHub Actions: PASS / FULL
Dependency Inventory: NOT_ASSESSED / UNKNOWN
```

`NOT_ASSESSED / UNKNOWN` is deliberately different from PASS.

## Understand rules
```bash
dkwess-securerepo --list-checks
dkwess-securerepo --explain SR-GHA-010
```

## CI thresholds
```bash
dkwess-securerepo . --fail-on HIGH
dkwess-securerepo . --fail-on MEDIUM
dkwess-securerepo . --fail-on HIGH --require-full-coverage
```

## JSON-only automation
```bash
dkwess-securerepo . --no-reports --json-stdout
```

## Safety model
SecureRepo does not follow symlinks during recursive discovery, does not print secret contents for filename-based sensitive-file checks, does not execute the target repository, does not install target dependencies, and writes only to the chosen output directory.

Next: [USAGE.md](USAGE.md), [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md), [CHECKS.md](CHECKS.md), [AUDIT_METHODOLOGY.md](AUDIT_METHODOLOGY.md), [FAQ.md](FAQ.md).
