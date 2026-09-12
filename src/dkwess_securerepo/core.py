from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import re
from typing import Iterable

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ASSESSMENT_STATES = {"PASS", "FAIL", "BLOCKED", "NOT_ASSESSED"}
COVERAGE_STATES = {"FULL", "PARTIAL", "UNKNOWN"}
CONFIDENCE_STATES = {"LOW", "MEDIUM", "HIGH"}


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    title: str
    path: str
    detail: str
    remediation: str
    category: str = "general"
    confidence: str = "HIGH"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported severity: {self.severity}")
        if self.confidence not in CONFIDENCE_STATES:
            raise ValueError(f"Unsupported confidence: {self.confidence}")
        if not self.category:
            raise ValueError("Finding category must not be empty")


@dataclass(frozen=True)
class CapabilityAssessment:
    capability: str
    assessment: str
    coverage: str
    finding_count: int
    notes: str

    def __post_init__(self) -> None:
        if self.assessment not in ASSESSMENT_STATES:
            raise ValueError(f"Unsupported assessment state: {self.assessment}")
        if self.coverage not in COVERAGE_STATES:
            raise ValueError(f"Unsupported coverage state: {self.coverage}")
        if self.finding_count < 0:
            raise ValueError("finding_count must be >= 0")


@dataclass
class AuditResult:
    root: str
    findings: list[Finding]
    manifests: list[str]
    capabilities: list[CapabilityAssessment]

    @property
    def counts(self) -> dict[str, int]:
        return {
            severity: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }

    @property
    def coverage_counts(self) -> dict[str, int]:
        return {
            state: sum(1 for capability in self.capabilities if capability.coverage == state)
            for state in ("FULL", "PARTIAL", "UNKNOWN")
        }

    @property
    def status(self) -> str:
        if any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["HIGH"] for f in self.findings):
            return "FAIL"
        if any(cap.assessment == "BLOCKED" for cap in self.capabilities):
            return "REVIEW_REQUIRED"
        if self.findings:
            return "REVIEW_REQUIRED"
        return "PASS"

    def exit_code(self, fail_on: str = "HIGH") -> int:
        if fail_on not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported fail-on severity: {fail_on}")
        threshold = SEVERITY_ORDER[fail_on]
        return 2 if any(SEVERITY_ORDER[f.severity] >= threshold for f in self.findings) else 0

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 2,
            "tool": "DkWess SecureRepo",
            "root": self.root,
            "status": self.status,
            "security_guarantee": False,
            "statement": "PASS != SECURITY GUARANTEE",
            "counts": self.counts,
            "coverage_counts": self.coverage_counts,
            "manifests": self.manifests,
            "capabilities": [asdict(capability) for capability in self.capabilities],
            "findings": [asdict(finding) for finding in self.findings],
        }


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "reports",
    "dist",
    "build",
}

SENSITIVE_EXACT = {
    ".env",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
}

SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}
SAFE_SENSITIVE_EXAMPLES = {".env.example", ".env.sample"}

MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
}


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _walk_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part in IGNORED_DIRS for part in relative_parts):
            continue
        if path.is_symlink():
            continue
        if path.is_file():
            yield path


def _check_governance(root: Path) -> list[Finding]:
    checks = (
        ("README.md", "SR-DOC-001", "MEDIUM", "README.md is missing", "Add a README describing purpose, setup, usage, and limitations."),
        ("SECURITY.md", "SR-DOC-002", "LOW", "SECURITY.md is missing", "Add a vulnerability reporting and support policy."),
        ("CONTRIBUTING.md", "SR-DOC-003", "LOW", "CONTRIBUTING.md is missing", "Document contribution and review expectations."),
    )
    findings: list[Finding] = []
    for filename, check_id, severity, title, remediation in checks:
        if not (root / filename).is_file():
            findings.append(
                Finding(
                    check_id,
                    severity,
                    title,
                    filename,
                    f"Expected governance file `{filename}` was not found.",
                    remediation,
                    category="governance",
                )
            )

    license_candidates = [
        root / "LICENSE",
        root / "LICENSE.md",
        root / "LICENSE.txt",
        root / "COPYING",
        root / "COPYING.md",
    ]
    if not any(path.is_file() for path in license_candidates):
        findings.append(
            Finding(
                "SR-DOC-004",
                "MEDIUM",
                "No software license detected",
                ".",
                "Public source without an explicit license can be ambiguous for users and contributors.",
                "Select an appropriate license and add the corresponding license file after maintainer/legal review.",
                category="governance",
            )
        )
    return findings


def _check_gitignore(root: Path) -> list[Finding]:
    path = root / ".gitignore"
    if not path.is_file():
        return [
            Finding(
                "SR-REP-001",
                "MEDIUM",
                ".gitignore is missing",
                ".gitignore",
                "Generated files and local secrets are easier to commit accidentally without ignore rules.",
                "Add a project-appropriate .gitignore and include local secret/config patterns.",
                category="repository-hygiene",
            )
        ]

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [
            Finding(
                "SR-REP-002",
                "LOW",
                "Unable to inspect .gitignore",
                ".gitignore",
                f"The file could not be read: {exc.__class__.__name__}.",
                "Ensure .gitignore is readable by the audit process.",
                category="repository-hygiene",
                confidence="MEDIUM",
            )
        ]

    normalized = {line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")}
    expected_groups = {
        "environment files": {".env", ".env.*", "*.env"},
        "Python cache": {"__pycache__/", "__pycache__", "*.pyc", "*.py[cod]"},
        "audit reports": {"reports/", "reports"},
    }
    missing = [label for label, alternatives in expected_groups.items() if not normalized.intersection(alternatives)]
    if not missing:
        return []
    return [
        Finding(
            "SR-REP-003",
            "LOW",
            ".gitignore may be incomplete",
            ".gitignore",
            "No matching ignore rule was detected for: " + ", ".join(missing) + ".",
            "Review .gitignore for local environment files, generated caches, and audit output.",
            category="repository-hygiene",
            confidence="MEDIUM",
        )
    ]


def _check_sensitive_filenames(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _walk_files(root):
        lowered = path.name.lower()
        if lowered in SAFE_SENSITIVE_EXAMPLES:
            continue
        exact_match = lowered in SENSITIVE_EXACT
        suffix_match = path.suffix.lower() in SENSITIVE_SUFFIXES
        if not (exact_match or suffix_match):
            continue
        findings.append(
            Finding(
                "SR-SEC-001",
                "HIGH",
                "Potentially sensitive file tracked in repository tree",
                _relative(path, root),
                "The filename or extension is commonly associated with credentials, private keys, or secret-bearing configuration. File contents were not read for this check.",
                "Verify whether the file is safe to publish. If it contains secrets, remove it from version control and rotate affected credentials.",
                category="sensitive-files",
                confidence="MEDIUM",
            )
        )
    return findings


def _detect_manifests(root: Path) -> tuple[list[str], list[Finding]]:
    manifests = sorted({_relative(path, root) for path in _walk_files(root) if path.name in MANIFEST_NAMES})
    if manifests:
        return manifests, []
    return [], [
        Finding(
            "SR-SC-001",
            "INFO",
            "No recognized dependency manifest detected",
            ".",
            "SecureRepo did not find a supported dependency manifest in the scanned tree.",
            "No action is required for repositories without dependencies; otherwise confirm the manifest format is supported.",
            category="dependency-inventory",
            confidence="MEDIUM",
        )
    ]


def _read_workflow(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _workflow_finding(
    check_id: str,
    severity: str,
    title: str,
    workflow: Path,
    root: Path,
    line_number: int,
    detail: str,
    remediation: str,
    confidence: str = "HIGH",
) -> Finding:
    return Finding(
        check_id,
        severity,
        title,
        f"{_relative(workflow, root)}:{line_number}",
        detail,
        remediation,
        category="github-actions",
        confidence=confidence,
    )


def _check_github_actions(root: Path) -> list[Finding]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return []

    findings: list[Finding] = []
    workflow_paths = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")))
    full_sha = re.compile(r"^[0-9a-fA-F]{40}$")
    uses_pattern = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^\s#'\"]+)")

    for workflow in workflow_paths:
        text = _read_workflow(workflow)
        if text is None:
            findings.append(
                Finding(
                    "SR-GHA-000",
                    "LOW",
                    "Unable to inspect workflow",
                    _relative(workflow, root),
                    "The workflow could not be read.",
                    "Ensure the workflow is readable by the audit process.",
                    category="github-actions",
                    confidence="HIGH",
                )
            )
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if re.match(r"^pull_request_target\s*:", stripped):
                findings.append(
                    _workflow_finding(
                        "SR-GHA-001",
                        "HIGH",
                        "pull_request_target requires elevated review",
                        workflow,
                        root,
                        line_number,
                        "This trigger executes in the context of the base repository and can expose privileged context if combined with untrusted pull-request content.",
                        "Prefer `pull_request` where possible. If `pull_request_target` is required, isolate untrusted code and review permissions and checkout behavior carefully.",
                    )
                )
            if re.match(r"^permissions\s*:\s*write-all\s*$", stripped, flags=re.IGNORECASE):
                findings.append(
                    _workflow_finding(
                        "SR-GHA-002",
                        "HIGH",
                        "Workflow grants write-all permissions",
                        workflow,
                        root,
                        line_number,
                        "Broad token write permissions increase the impact of workflow compromise.",
                        "Declare the minimum job or workflow permissions required.",
                    )
                )
            if re.search(r"persist-credentials\s*:\s*true", stripped, flags=re.IGNORECASE):
                findings.append(
                    _workflow_finding(
                        "SR-GHA-003",
                        "MEDIUM",
                        "Checkout credentials are persisted",
                        workflow,
                        root,
                        line_number,
                        "Persisted Git credentials can remain available to later workflow steps.",
                        "Set `persist-credentials: false` unless later authenticated Git operations are intentionally required.",
                    )
                )

            match = uses_pattern.match(line)
            if not match:
                continue
            reference = match.group(1)
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            if "@" not in reference:
                findings.append(
                    _workflow_finding(
                        "SR-GHA-004",
                        "HIGH",
                        "Remote action has no explicit reference",
                        workflow,
                        root,
                        line_number,
                        f"Remote action `{reference}` has no `@ref` component.",
                        "Pin the action to a reviewed immutable commit SHA.",
                    )
                )
                continue
            action, ref = reference.rsplit("@", 1)
            if not full_sha.fullmatch(ref):
                findings.append(
                    _workflow_finding(
                        "SR-GHA-005",
                        "MEDIUM",
                        "Remote action is not pinned to a full commit SHA",
                        workflow,
                        root,
                        line_number,
                        f"Action `{action}` uses mutable or non-SHA reference `{ref}`.",
                        "Review the action source and pin it to an immutable 40-character commit SHA; keep the human-readable version in a comment if useful.",
                    )
                )
    return findings


def _capability(
    name: str,
    category: str,
    findings: list[Finding],
    *,
    applicable: bool = True,
    blocked: bool = False,
    notes: str,
) -> CapabilityAssessment:
    category_findings = [finding for finding in findings if finding.category == category]
    if not applicable:
        return CapabilityAssessment(name, "NOT_ASSESSED", "UNKNOWN", len(category_findings), notes)
    if blocked:
        return CapabilityAssessment(name, "BLOCKED", "PARTIAL", len(category_findings), notes)
    assessment = "FAIL" if category_findings else "PASS"
    return CapabilityAssessment(name, assessment, "FULL", len(category_findings), notes)


def _build_capabilities(root: Path, findings: list[Finding], manifests: list[str]) -> list[CapabilityAssessment]:
    workflow_dir = root / ".github" / "workflows"
    workflow_paths = []
    if workflow_dir.is_dir():
        workflow_paths = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
    workflow_unreadable = any(finding.check_id == "SR-GHA-000" for finding in findings)

    return [
        _capability(
            "Governance",
            "governance",
            findings,
            notes="Checks project documentation and license-file presence.",
        ),
        _capability(
            "Repository Hygiene",
            "repository-hygiene",
            findings,
            notes="Checks .gitignore coverage and basic repository hygiene.",
        ),
        _capability(
            "Sensitive Filenames",
            "sensitive-files",
            findings,
            notes="Filename/path heuristics only; file contents are not inspected by this capability.",
        ),
        _capability(
            "Dependency Inventory",
            "dependency-inventory",
            findings,
            applicable=bool(manifests),
            notes=(
                "Recognized dependency manifests were inventoried."
                if manifests
                else "No recognized dependency manifest was found; dependency security was not assessed."
            ),
        ),
        _capability(
            "GitHub Actions",
            "github-actions",
            findings,
            applicable=bool(workflow_paths),
            blocked=workflow_unreadable,
            notes=(
                "Workflow files were inspected with conservative line-oriented heuristics."
                if workflow_paths
                else "No supported GitHub Actions workflow files were found."
            ),
        ),
    ]


def scan_repository(root: str | Path) -> AuditResult:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root_path}")

    findings: list[Finding] = []
    findings.extend(_check_governance(root_path))
    findings.extend(_check_gitignore(root_path))
    findings.extend(_check_sensitive_filenames(root_path))
    manifests, manifest_findings = _detect_manifests(root_path)
    findings.extend(manifest_findings)
    findings.extend(_check_github_actions(root_path))
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.check_id, item.path))
    capabilities = _build_capabilities(root_path, findings, manifests)
    return AuditResult(str(root_path), findings, manifests, capabilities)


def _markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: AuditResult) -> str:
    counts = result.counts
    coverage_counts = result.coverage_counts
    lines = [
        "# DkWess SecureRepo Audit",
        "",
        f"**Status:** `{result.status}`",
        "",
        "> PASS != SECURITY GUARANTEE. This report covers only the implemented checks for the scanned snapshot.",
        "",
        "## Summary",
        "",
        f"- Root: `{result.root}`",
        f"- Findings: {len(result.findings)}",
        f"- Critical: {counts['CRITICAL']}",
        f"- High: {counts['HIGH']}",
        f"- Medium: {counts['MEDIUM']}",
        f"- Low: {counts['LOW']}",
        f"- Info: {counts['INFO']}",
        f"- Coverage FULL/PARTIAL/UNKNOWN: {coverage_counts['FULL']}/{coverage_counts['PARTIAL']}/{coverage_counts['UNKNOWN']}",
        "",
        "## Capability matrix",
        "",
        "| Capability | Assessment | Coverage | Findings | Notes |",
        "|---|---|---|---:|---|",
    ]
    for capability in result.capabilities:
        lines.append(
            f"| {_markdown_escape(capability.capability)} | `{capability.assessment}` | "
            f"`{capability.coverage}` | {capability.finding_count} | {_markdown_escape(capability.notes)} |"
        )

    lines.extend(["", "## Dependency manifests", ""])
    if result.manifests:
        lines.extend(f"- `{manifest}`" for manifest in result.manifests)
    else:
        lines.append("- None recognized")

    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings were produced by the implemented checks.")
    else:
        lines.extend([
            "| Severity | Confidence | Category | Check | Path | Finding |",
            "|---|---|---|---|---|---|",
        ])
        for finding in result.findings:
            lines.append(
                f"| {finding.severity} | {finding.confidence} | `{_markdown_escape(finding.category)}` | "
                f"`{finding.check_id}` | `{_markdown_escape(finding.path)}` | {_markdown_escape(finding.title)} |"
            )
        lines.append("")
        for finding in result.findings:
            lines.extend(
                [
                    f"### {finding.check_id} — {finding.title}",
                    "",
                    f"- Severity: **{finding.severity}**",
                    f"- Confidence: **{finding.confidence}**",
                    f"- Category: `{finding.category}`",
                    f"- Path: `{finding.path}`",
                    f"- Evidence: {finding.detail}",
                    f"- Remediation: {finding.remediation}",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def write_reports(result: AuditResult, output: str | Path = "reports") -> tuple[Path, Path]:
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / "audit.json"
    markdown_path = output_path / "audit.md"
    json_path.write_text(json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    return json_path, markdown_path
