from __future__ import annotations

import json
from pathlib import Path

from .models import AuditResult


def _markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: AuditResult) -> str:
    counts = result.counts
    metrics = result.metrics
    lines = [
        "# DkWess SecureRepo Audit", "", f"**Tool version:** `{result.tool_version}`  ", f"**Status:** `{result.status}`  ", f"**Implemented capability coverage:** `{result.coverage_percent}%`", "", "> [!IMPORTANT]", "> `PASS != SECURITY GUARANTEE`. This report describes only the checks and coverage implemented by this SecureRepo version.", "", "## Executive summary", "", f"- Root: `{result.root}`", f"- Findings: **{len(result.findings)}**", f"- Critical: **{counts['CRITICAL']}**", f"- High: **{counts['HIGH']}**", f"- Medium: **{counts['MEDIUM']}**", f"- Low: **{counts['LOW']}**", f"- Info: **{counts['INFO']}**", "", "## Scan metrics", "", "| Metric | Value |", "|---|---:|", f"| Files discovered | {metrics.files_discovered} |", f"| Symlinks skipped | {metrics.symlinks_skipped} |", f"| Discovery errors | {metrics.discovery_errors} |", f"| Workflows discovered | {metrics.workflows_discovered} |", f"| Manifests detected | {metrics.manifests_detected} |", "", "## Capability matrix", "", "| Capability | Assessment | Coverage | Findings | Notes |", "|---|---|---|---:|---|",
    ]
    for capability in result.capabilities:
        lines.append("| " + " | ".join([_markdown_escape(capability.capability), f"`{capability.assessment}`", f"`{capability.coverage}`", str(capability.finding_count), _markdown_escape(capability.notes)]) + " |")
    lines.extend(["", "## Dependency manifests", ""])
    if result.manifests:
        lines.extend(f"- `{manifest}`" for manifest in result.manifests)
    else:
        lines.append("- None recognized")
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings were produced by the implemented checks.")
    else:
        lines.extend(["| Severity | Confidence | Rule | Category | Path | Finding |", "|---|---|---|---|---|---|"])
        for finding in result.findings:
            lines.append("| " + " | ".join([finding.severity, finding.confidence, f"`{finding.check_id}`", f"`{finding.category}`", f"`{_markdown_escape(finding.path)}`", _markdown_escape(finding.title)]) + " |")
        lines.append("")
        for finding in result.findings:
            lines.extend([f"### {finding.check_id} — {finding.title}", "", f"- Severity: **{finding.severity}**", f"- Confidence: **{finding.confidence}**", f"- Category: `{finding.category}`", f"- Path: `{finding.path}`", f"- Fingerprint: `{finding.fingerprint}`", f"- Evidence: {finding.detail}", f"- Remediation: {finding.remediation}", ""])
    lines.extend(["## Interpretation", "", "- `PASS` means the implemented checks for that capability completed without findings.", "- `FAIL` means at least one implemented check produced a finding.", "- `BLOCKED` means SecureRepo attempted the capability but could not complete it.", "- `NOT_ASSESSED` means no meaningful conclusion is made for that capability.", "- `FULL`, `PARTIAL`, and `UNKNOWN` describe implemented-check coverage, not overall security coverage.", "", "A clean report is evidence about this scanner's current rule set, not proof that the repository has no vulnerabilities."])
    return "\n".join(lines).rstrip() + "\n"


def write_reports(result: AuditResult, output: str | Path = "reports") -> tuple[Path, Path]:
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / "audit.json"
    markdown_path = output_path / "audit.md"
    json_path.write_text(json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    return json_path, markdown_path
