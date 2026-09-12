from __future__ import annotations

import json
from pathlib import Path
import re

from .models import AuditResult
from .rules import get_rule

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def _location(path: str) -> tuple[str, int | None]:
    match = re.match(r"^(.*):(\d+)$", path)
    if not match:
        return path, None
    return match.group(1), int(match.group(2))


def sarif_payload(result: AuditResult) -> dict[str, object]:
    used_ids = sorted({finding.check_id for finding in result.findings})
    rules: list[dict[str, object]] = []
    for rule_id in used_ids:
        rule = get_rule(rule_id)
        if rule is None:
            continue
        rules.append({
            "id": rule.rule_id,
            "name": rule.rule_id,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.remediation},
            "properties": {"category": rule.category, "severity": rule.severity, "confidence": rule.confidence},
        })
    results: list[dict[str, object]] = []
    for finding in result.findings:
        artifact, line = _location(finding.path)
        physical: dict[str, object] = {"artifactLocation": {"uri": artifact.replace("\\", "/")}}
        if line is not None:
            physical["region"] = {"startLine": line}
        results.append({
            "ruleId": finding.check_id,
            "level": _level(finding.severity),
            "message": {"text": f"{finding.title}. {finding.detail} Remediation: {finding.remediation}"},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"dkwessSecureRepoFingerprint/v1": finding.fingerprint},
            "properties": {"severity": finding.severity, "confidence": finding.confidence, "category": finding.category},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "DkWess SecureRepo", "version": result.tool_version, "informationUri": "https://github.com/DKWesley13/DkWess", "rules": rules}},
            "results": results,
            "properties": {"securityGuarantee": False, "statement": "PASS != SECURITY GUARANTEE"},
        }],
    }


def write_sarif(result: AuditResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sarif_payload(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
