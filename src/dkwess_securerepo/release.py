from __future__ import annotations

from pathlib import Path

from .models import AuditResult

REQUIRED_PUBLIC_FILES = (
    "README.md",
    "README.pt-BR.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "docs/GETTING_STARTED.md",
    "docs/USAGE.md",
    "docs/ARCHITECTURE.md",
    "docs/AUDIT_METHODOLOGY.md",
    "docs/THREAT_MODEL.md",
    "docs/ROADMAP.md",
    "docs/RELEASE_CHECKLIST.md",
)
LICENSE_CANDIDATES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md")


def release_readiness(root: str | Path, result: AuditResult) -> dict[str, object]:
    root_path = Path(root).expanduser().resolve()
    missing_docs = [name for name in REQUIRED_PUBLIC_FILES if not (root_path / name).is_file()]
    non_license_findings = [finding.as_dict() for finding in result.findings if finding.check_id != "SR-DOC-004"]
    incomplete_coverage = [
        {"capability": capability.capability, "coverage": capability.coverage}
        for capability in result.capabilities
        if capability.coverage != "FULL"
    ]
    license_file = next((name for name in LICENSE_CANDIDATES if (root_path / name).is_file()), None)
    stable_version = result.tool_version == "1.0.0"
    technical_ready = stable_version and not missing_docs and not non_license_findings and not incomplete_coverage
    return {
        "schema_version": 1,
        "tool_version": result.tool_version,
        "stable_version": stable_version,
        "technical_ready": technical_ready,
        "open_source_reuse_ready": bool(technical_ready and license_file),
        "license_file": license_file,
        "missing_public_docs": missing_docs,
        "non_license_findings": non_license_findings,
        "incomplete_coverage": incomplete_coverage,
        "statement": "Technical readiness and legal reuse permission are separate gates. PASS != SECURITY GUARANTEE.",
    }
