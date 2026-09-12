from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    remediation: str
    confidence: str = "HIGH"


def _rule(rule_id: str, category: str, severity: str, title: str, description: str, remediation: str, confidence: str = "HIGH") -> RuleDefinition:
    return RuleDefinition(rule_id, category, severity, title, description, remediation, confidence)


RULES: dict[str, RuleDefinition] = {
    "SR-DOC-001": _rule("SR-DOC-001", "governance", "MEDIUM", "README.md is missing", "A public repository should explain its purpose, setup, usage, limitations, and support expectations.", "Add a README describing purpose, setup, usage, and limitations."),
    "SR-DOC-002": _rule("SR-DOC-002", "governance", "LOW", "SECURITY.md is missing", "Maintainers should provide a safe path for vulnerability reports.", "Add a SECURITY.md with vulnerability reporting and support guidance."),
    "SR-DOC-003": _rule("SR-DOC-003", "governance", "LOW", "CONTRIBUTING.md is missing", "Contribution expectations are not documented.", "Add contribution, testing, and review guidance."),
    "SR-DOC-004": _rule("SR-DOC-004", "governance", "MEDIUM", "No software license detected", "Public source without an explicit license can be ambiguous for users and contributors.", "Select an appropriate license and add the corresponding license file after maintainer/legal review."),
    "SR-REP-001": _rule("SR-REP-001", "repository-hygiene", "MEDIUM", ".gitignore is missing", "Generated files and local secrets are easier to commit accidentally without ignore rules.", "Add a project-appropriate .gitignore and include local secret/config patterns."),
    "SR-REP-002": _rule("SR-REP-002", "repository-hygiene", "LOW", "Unable to inspect .gitignore", "The scanner could not read .gitignore and cannot fully evaluate ignore hygiene.", "Ensure .gitignore is readable by the audit process.", "MEDIUM"),
    "SR-REP-003": _rule("SR-REP-003", "repository-hygiene", "LOW", ".gitignore may be incomplete", "Expected ignore coverage was not detected for one or more common local/generated file groups.", "Review .gitignore for local environment files, generated caches, and audit output.", "MEDIUM"),
    "SR-REP-004": _rule("SR-REP-004", "repository-hygiene", "LOW", "Repository discovery was incomplete", "One or more filesystem traversal errors prevented complete repository discovery.", "Review filesystem permissions and unreadable paths, then rerun the audit."),
    "SR-SEC-001": _rule("SR-SEC-001", "sensitive-files", "HIGH", "Potentially sensitive file tracked in repository tree", "The filename or extension is commonly associated with credentials, private keys, or secret-bearing configuration.", "Verify whether the file is safe to publish. If it contains secrets, remove it from version control and rotate affected credentials.", "MEDIUM"),
    "SR-SEC-002": _rule("SR-SEC-002", "sensitive-files", "MEDIUM", "Credential-adjacent configuration file requires review", "The filename or path is commonly used for package-manager, cloud, container, or user credentials, but may also contain harmless configuration.", "Review the file before publication. Remove embedded credentials and use documented secret-management mechanisms instead.", "MEDIUM"),
    "SR-SC-001": _rule("SR-SC-001", "dependency-inventory", "INFO", "No recognized dependency manifest detected", "SecureRepo did not find a supported dependency manifest in the scanned tree.", "No action is required for repositories without dependencies; otherwise confirm the manifest format is supported.", "MEDIUM"),
    "SR-SC-002": _rule("SR-SC-002", "dependency-inventory", "LOW", "Node.js manifest has no recognized lockfile", "A package.json was found without package-lock.json, pnpm-lock.yaml, or yarn.lock in the same directory.", "For applications and reproducible builds, commit the package-manager lockfile when appropriate for the project.", "MEDIUM"),
    "SR-SC-003": _rule("SR-SC-003", "dependency-inventory", "LOW", "Go module has no go.sum", "A go.mod was found without a sibling go.sum, reducing evidence about resolved module checksums.", "Run the normal Go module workflow and commit go.sum when the project requires external modules.", "MEDIUM"),
    "SR-GHA-000": _rule("SR-GHA-000", "github-actions", "LOW", "Unable to inspect workflow", "A GitHub Actions workflow could not be read, so coverage for that workflow is incomplete.", "Ensure the workflow is readable by the audit process."),
    "SR-GHA-001": _rule("SR-GHA-001", "github-actions", "HIGH", "pull_request_target requires elevated review", "This trigger executes in the base-repository context and can expose privileged context if combined with untrusted pull-request content.", "Prefer pull_request where possible. If pull_request_target is required, isolate untrusted code and review checkout behavior and permissions carefully."),
    "SR-GHA-002": _rule("SR-GHA-002", "github-actions", "HIGH", "Workflow grants write-all permissions", "Broad GitHub token write permissions increase the impact of workflow compromise.", "Declare only the minimum job or workflow permissions required."),
    "SR-GHA-003": _rule("SR-GHA-003", "github-actions", "MEDIUM", "Checkout credentials are persisted", "Persisted Git credentials can remain available to later workflow steps.", "Set persist-credentials: false unless later authenticated Git operations are intentionally required."),
    "SR-GHA-004": _rule("SR-GHA-004", "github-actions", "HIGH", "Remote action has no explicit reference", "A remote uses: entry has no @ref component.", "Pin the action to a reviewed immutable commit SHA."),
    "SR-GHA-005": _rule("SR-GHA-005", "github-actions", "MEDIUM", "Remote action is not pinned to a full commit SHA", "A remote action uses a mutable tag, branch, or shortened reference instead of an immutable full commit SHA.", "Review the action source and pin it to a full 40-character commit SHA. Keep the human-readable release version in a comment if useful."),
    "SR-GHA-006": _rule("SR-GHA-006", "github-actions", "MEDIUM", "Self-hosted runner requires trust-boundary review", "Self-hosted runners can retain state or expose internal resources if untrusted code reaches them.", "Use ephemeral or isolated runners where appropriate and prevent untrusted pull requests from reaching privileged self-hosted runners.", "MEDIUM"),
    "SR-GHA-007": _rule("SR-GHA-007", "github-actions", "HIGH", "Potentially untrusted GitHub context is interpolated into shell execution", "User-controlled event data can become shell input when interpolated directly inside run commands.", "Pass untrusted values through environment variables and treat them as data; quote them correctly and avoid dynamic shell construction."),
    "SR-GHA-008": _rule("SR-GHA-008", "github-actions", "HIGH", "Remote content is piped directly to a shell", "Piping curl or wget output directly into sh/bash executes remote content without an explicit review boundary.", "Download to a file, verify origin/integrity, inspect or pin the artifact, and only then execute it if required.", "MEDIUM"),
    "SR-GHA-009": _rule("SR-GHA-009", "github-actions", "MEDIUM", "Docker action is not pinned by image digest", "A docker:// action reference uses a tag or implicit latest reference rather than an immutable sha256 digest.", "Pin the container image by an immutable sha256 digest where practical.", "MEDIUM"),
    "SR-GHA-010": _rule("SR-GHA-010", "github-actions", "CRITICAL", "pull_request_target checks out pull-request head content", "Combining pull_request_target with pull-request head checkout can execute or expose untrusted fork content in a privileged base-repository context.", "Redesign the workflow so privileged pull_request_target jobs never execute untrusted pull-request code. Use separate unprivileged pull_request workflows for code execution."),
}


def get_rule(rule_id: str) -> RuleDefinition | None:
    return RULES.get(rule_id.upper())


def iter_rules() -> list[RuleDefinition]:
    return [RULES[key] for key in sorted(RULES)]


def make_finding(rule_id: str, path: str, *, detail: str | None = None, confidence: str | None = None) -> Finding:
    rule = get_rule(rule_id)
    if rule is None:
        raise KeyError(f"Unknown rule: {rule_id}")
    return Finding(check_id=rule.rule_id, severity=rule.severity, title=rule.title, path=path, detail=detail or rule.description, remediation=rule.remediation, category=rule.category, confidence=confidence or rule.confidence)
