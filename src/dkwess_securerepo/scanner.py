from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable

from .models import AuditResult, CapabilityAssessment, Finding, ScanMetrics, SEVERITY_ORDER
from .rules import make_finding

TOOL_VERSION = "0.0.3"

IGNORED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", "reports", "dist", "build"}
SENSITIVE_EXACT = {".env", "credentials.json", "secrets.json", "id_rsa", "id_ed25519"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}
SAFE_SENSITIVE_EXAMPLES = {".env.example", ".env.sample"}
CREDENTIAL_ADJACENT_NAMES = {".npmrc", ".pypirc", ".netrc"}
CREDENTIAL_ADJACENT_PATH_SUFFIXES = {".aws/credentials", ".docker/config.json", ".kube/config"}
MANIFEST_NAMES = {"pyproject.toml", "requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}
UNTRUSTED_GITHUB_CONTEXTS = ("github.event.issue.title", "github.event.issue.body", "github.event.pull_request.title", "github.event.pull_request.body", "github.event.comment.body", "github.event.review.body", "github.event.review_comment.body", "github.event.head_commit.message")
REMOTE_SHELL_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", flags=re.IGNORECASE)
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^\s#'\"]+)")
RUN_RE = re.compile(r"^(?P<indent>\s*)-?\s*run\s*:\s*(?P<body>.*)$")


@dataclass(frozen=True)
class DiscoveryResult:
    files: tuple[Path, ...]
    symlinks_skipped: int
    errors: int


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _discover_files(root: Path) -> DiscoveryResult:
    files: list[Path] = []
    symlinks_skipped = 0
    errors = 0
    def onerror(_: OSError) -> None:
        nonlocal errors
        errors += 1
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        directory = Path(dirpath)
        kept_dirs: list[str] = []
        for dirname in dirnames:
            if dirname in IGNORED_DIRS:
                continue
            candidate = directory / dirname
            try:
                if candidate.is_symlink():
                    symlinks_skipped += 1
                    continue
            except OSError:
                errors += 1
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in filenames:
            candidate = directory / filename
            try:
                if candidate.is_symlink():
                    symlinks_skipped += 1
                    continue
                if candidate.is_file():
                    files.append(candidate)
            except OSError:
                errors += 1
    files.sort(key=lambda path: _relative(path, root))
    return DiscoveryResult(tuple(files), symlinks_skipped, errors)


def _check_governance(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for filename, rule_id in (("README.md", "SR-DOC-001"), ("SECURITY.md", "SR-DOC-002"), ("CONTRIBUTING.md", "SR-DOC-003")):
        if not (root / filename).is_file():
            findings.append(make_finding(rule_id, filename))
    license_candidates = (root / "LICENSE", root / "LICENSE.md", root / "LICENSE.txt", root / "COPYING", root / "COPYING.md")
    if not any(path.is_file() for path in license_candidates):
        findings.append(make_finding("SR-DOC-004", "."))
    return findings


def _check_gitignore(root: Path) -> list[Finding]:
    path = root / ".gitignore"
    if not path.is_file():
        return [make_finding("SR-REP-001", ".gitignore")]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [make_finding("SR-REP-002", ".gitignore")]
    normalized = {line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")}
    expected_groups = {"environment files": {".env", ".env.*", "*.env"}, "Python cache": {"__pycache__/", "__pycache__", "*.pyc", "*.py[cod]"}, "audit reports": {"reports/", "reports"}}
    missing = [label for label, alternatives in expected_groups.items() if not normalized.intersection(alternatives)]
    if not missing:
        return []
    return [make_finding("SR-REP-003", ".gitignore", detail="No matching ignore rule was detected for: " + ", ".join(missing) + ".")]


def _check_sensitive_filenames(root: Path, files: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        relative = _relative(path, root)
        lowered_name = path.name.lower()
        lowered_relative = relative.lower()
        if lowered_name in SAFE_SENSITIVE_EXAMPLES:
            continue
        if lowered_name in SENSITIVE_EXACT or path.suffix.lower() in SENSITIVE_SUFFIXES:
            findings.append(make_finding("SR-SEC-001", relative, detail="The filename or extension is commonly associated with credentials, private keys, or secret-bearing configuration. File contents were not read for this check."))
            continue
        if lowered_name in CREDENTIAL_ADJACENT_NAMES or any(lowered_relative.endswith(suffix) for suffix in CREDENTIAL_ADJACENT_PATH_SUFFIXES):
            findings.append(make_finding("SR-SEC-002", relative, detail="This path is commonly used for credential-adjacent configuration. SecureRepo did not inspect or print the file contents."))
    return findings


def _detect_manifests(root: Path, files: Iterable[Path]) -> tuple[list[str], list[Finding]]:
    file_list = list(files)
    manifests = sorted({_relative(path, root) for path in file_list if path.name in MANIFEST_NAMES})
    findings: list[Finding] = []
    if not manifests:
        findings.append(make_finding("SR-SC-001", "."))
        return [], findings
    file_set = {path.resolve() for path in file_list}
    for path in file_list:
        if path.name == "package.json":
            lockfiles = (path.parent / "package-lock.json", path.parent / "pnpm-lock.yaml", path.parent / "yarn.lock")
            if not any(lockfile.resolve() in file_set for lockfile in lockfiles):
                findings.append(make_finding("SR-SC-002", _relative(path, root)))
        elif path.name == "go.mod" and (path.parent / "go.sum").resolve() not in file_set:
            findings.append(make_finding("SR-SC-003", _relative(path, root)))
    return manifests, findings


def _workflow_paths(root: Path) -> list[Path]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return []
    return sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")), key=lambda path: path.name)


def _read_workflow(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _line_path(workflow: Path, root: Path, line_number: int) -> str:
    return f"{_relative(workflow, root)}:{line_number}"


def _has_untrusted_context(text: str) -> str | None:
    compact = text.replace(" ", "")
    for context in UNTRUSTED_GITHUB_CONTEXTS:
        if "${{" + context in compact:
            return context
    return None


def _inspect_shell_fragment(fragment: str, workflow: Path, root: Path, line_number: int, findings: list[Finding]) -> None:
    context = _has_untrusted_context(fragment)
    if context:
        findings.append(make_finding("SR-GHA-007", _line_path(workflow, root, line_number), detail=f"Potentially user-controlled context `{context}` appears directly in shell execution."))
    if REMOTE_SHELL_RE.search(fragment):
        findings.append(make_finding("SR-GHA-008", _line_path(workflow, root, line_number), detail="A curl/wget command appears to pipe remote content directly to a shell interpreter."))


def _check_github_actions(root: Path, workflows: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for workflow in workflows:
        text = _read_workflow(workflow)
        if text is None:
            findings.append(make_finding("SR-GHA-000", _relative(workflow, root)))
            continue
        lines = text.splitlines()
        meaningful = [line.split("#", 1)[0] for line in lines]
        has_pull_request_target = any("pull_request_target" in line for line in meaningful)
        head_ref_lines: list[int] = []
        for line_number, line in enumerate(meaningful, start=1):
            compact = line.replace(" ", "")
            if any(marker in compact for marker in ("github.event.pull_request.head.sha", "github.event.pull_request.head.ref", "github.event.pull_request.head.repo.full_name")):
                head_ref_lines.append(line_number)
        if has_pull_request_target and head_ref_lines:
            for line_number in head_ref_lines:
                findings.append(make_finding("SR-GHA-010", _line_path(workflow, root, line_number), detail="This workflow contains pull_request_target and references pull-request head content. That combination needs immediate privileged-context review."))
        run_block_indent: int | None = None
        for line_number, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            content = raw_line.split("#", 1)[0].rstrip()
            if not content.strip():
                continue
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            if run_block_indent is not None and indent <= run_block_indent:
                run_block_indent = None
            if "pull_request_target" in content and not content.lstrip().startswith("#"):
                findings.append(make_finding("SR-GHA-001", _line_path(workflow, root, line_number)))
            if re.match(r"^\s*permissions\s*:\s*write-all\s*$", content, flags=re.IGNORECASE):
                findings.append(make_finding("SR-GHA-002", _line_path(workflow, root, line_number)))
            if re.search(r"persist-credentials\s*:\s*true", content, flags=re.IGNORECASE):
                findings.append(make_finding("SR-GHA-003", _line_path(workflow, root, line_number)))
            if re.search(r"^\s*runs-on\s*:.*\bself-hosted\b", content, flags=re.IGNORECASE):
                findings.append(make_finding("SR-GHA-006", _line_path(workflow, root, line_number)))
            uses_match = USES_RE.match(content)
            if uses_match:
                reference = uses_match.group(1)
                if reference.startswith("./"):
                    pass
                elif reference.startswith("docker://"):
                    if "@sha256:" not in reference:
                        findings.append(make_finding("SR-GHA-009", _line_path(workflow, root, line_number), detail=f"Docker action `{reference}` is not pinned by sha256 digest."))
                elif "@" not in reference:
                    findings.append(make_finding("SR-GHA-004", _line_path(workflow, root, line_number), detail=f"Remote action `{reference}` has no @ref component."))
                else:
                    action, ref = reference.rsplit("@", 1)
                    if not FULL_SHA_RE.fullmatch(ref):
                        findings.append(make_finding("SR-GHA-005", _line_path(workflow, root, line_number), detail=f"Action `{action}` uses mutable or non-full-SHA reference `{ref}`."))
            run_match = RUN_RE.match(content)
            if run_match:
                body = run_match.group("body").strip()
                run_indent = len(run_match.group("indent"))
                if body in {"|", ">", "|-", ">-", "|+", ">+"}:
                    run_block_indent = run_indent
                elif body:
                    _inspect_shell_fragment(body, workflow, root, line_number, findings)
                continue
            if run_block_indent is not None and indent > run_block_indent:
                _inspect_shell_fragment(stripped, workflow, root, line_number, findings)
    deduped: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        deduped[(finding.check_id, finding.path, finding.detail)] = finding
    return list(deduped.values())


def _capability(name: str, category: str, findings: list[Finding], *, applicable: bool = True, blocked: bool = False, notes: str) -> CapabilityAssessment:
    category_findings = [finding for finding in findings if finding.category == category]
    if not applicable:
        return CapabilityAssessment(name, "NOT_ASSESSED", "UNKNOWN", len(category_findings), notes)
    if blocked:
        return CapabilityAssessment(name, "BLOCKED", "PARTIAL", len(category_findings), notes)
    return CapabilityAssessment(name, "FAIL" if category_findings else "PASS", "FULL", len(category_findings), notes)


def scan_repository(root: str | Path) -> AuditResult:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root_path}")
    discovery = _discover_files(root_path)
    files = list(discovery.files)
    findings: list[Finding] = []
    findings.extend(_check_governance(root_path))
    findings.extend(_check_gitignore(root_path))
    if discovery.errors:
        findings.append(make_finding("SR-REP-004", ".", detail=f"Repository discovery encountered {discovery.errors} filesystem error(s); paths are omitted from this finding."))
    findings.extend(_check_sensitive_filenames(root_path, files))
    manifests, dependency_findings = _detect_manifests(root_path, files)
    findings.extend(dependency_findings)
    workflows = _workflow_paths(root_path)
    workflow_findings = _check_github_actions(root_path, workflows)
    findings.extend(workflow_findings)
    findings.sort(key=lambda finding: (-SEVERITY_ORDER[finding.severity], finding.check_id, finding.path))
    workflow_blocked = any(finding.check_id == "SR-GHA-000" for finding in workflow_findings)
    discovery_blocked = discovery.errors > 0
    capabilities = [
        _capability("Governance", "governance", findings, notes="Top-level project documentation and license-presence checks."),
        _capability("Repository Hygiene", "repository-hygiene", findings, blocked=discovery_blocked, notes=".gitignore and filesystem discovery hygiene checks."),
        _capability("Sensitive Filenames", "sensitive-files", findings, blocked=discovery_blocked, notes="Filename/path heuristics only; secret contents are not read or printed."),
        _capability("Dependency Inventory", "dependency-inventory", findings, applicable=bool(manifests), blocked=discovery_blocked and bool(manifests), notes="Recognized dependency manifests and selected lockfile-hygiene checks." if manifests else "No recognized manifest was found; no dependency-security conclusion is made."),
        _capability("GitHub Actions", "github-actions", findings, applicable=bool(workflows), blocked=workflow_blocked, notes="Workflow risk-pattern analysis with conservative text-aware shell checks." if workflows else "No .github/workflows YAML files were present."),
    ]
    metrics = ScanMetrics(files_discovered=len(files), symlinks_skipped=discovery.symlinks_skipped, discovery_errors=discovery.errors, workflows_discovered=len(workflows), manifests_detected=len(manifests))
    return AuditResult(root=str(root_path), findings=findings, manifests=manifests, capabilities=capabilities, metrics=metrics, tool_version=TOOL_VERSION)
