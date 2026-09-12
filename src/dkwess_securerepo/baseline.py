from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .models import AuditResult, Finding, SEVERITY_ORDER

BASELINE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class BaselineComparison:
    new_findings: tuple[Finding, ...]
    resolved_fingerprints: tuple[str, ...]
    unchanged_fingerprints: tuple[str, ...]
    baseline_tool_version: str

    @property
    def has_regressions(self) -> bool:
        return bool(self.new_findings)

    def has_new_at_or_above(self, severity: str) -> bool:
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported severity: {severity}")
        threshold = SEVERITY_ORDER[severity]
        return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in self.new_findings)

    def as_dict(self) -> dict[str, object]:
        return {
            "baseline_tool_version": self.baseline_tool_version,
            "new_count": len(self.new_findings),
            "resolved_count": len(self.resolved_fingerprints),
            "unchanged_count": len(self.unchanged_fingerprints),
            "new_findings": [finding.as_dict() for finding in self.new_findings],
            "resolved_fingerprints": list(self.resolved_fingerprints),
            "unchanged_fingerprints": list(self.unchanged_fingerprints),
        }


def baseline_payload(result: AuditResult) -> dict[str, object]:
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "tool": "DkWess SecureRepo",
        "tool_version": result.tool_version,
        "statement": "A baseline records known findings; it does not convert them into PASS.",
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "check_id": finding.check_id,
                "severity": finding.severity,
                "path": finding.path,
                "title": finding.title,
            }
            for finding in result.findings
        ],
    }


def write_baseline(result: AuditResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(baseline_payload(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def load_baseline(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Baseline must be a JSON object")
    if payload.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(f"Unsupported baseline schema: {payload.get('schema_version')!r}")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Baseline findings must be a list")
    for item in findings:
        if not isinstance(item, dict) or not isinstance(item.get("fingerprint"), str):
            raise ValueError("Each baseline finding must contain a string fingerprint")
    return payload


def compare_baseline(result: AuditResult, payload: dict[str, Any]) -> BaselineComparison:
    baseline_items = payload.get("findings", [])
    baseline_fingerprints = {str(item["fingerprint"]) for item in baseline_items}
    current = {finding.fingerprint: finding for finding in result.findings}
    current_fingerprints = set(current)
    new = tuple(
        sorted(
            (current[fingerprint] for fingerprint in current_fingerprints - baseline_fingerprints),
            key=lambda finding: (-SEVERITY_ORDER[finding.severity], finding.check_id, finding.path),
        )
    )
    return BaselineComparison(
        new_findings=new,
        resolved_fingerprints=tuple(sorted(baseline_fingerprints - current_fingerprints)),
        unchanged_fingerprints=tuple(sorted(baseline_fingerprints & current_fingerprints)),
        baseline_tool_version=str(payload.get("tool_version", "unknown")),
    )
