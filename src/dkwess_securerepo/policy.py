from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path
import re
import tomllib
from typing import Any

from .models import AuditResult, CapabilityAssessment, Finding, SEVERITY_ORDER
from .rules import get_rule

CAPABILITY_CATEGORY = {
    "Governance": "governance",
    "Repository Hygiene": "repository-hygiene",
    "Sensitive Filenames": "sensitive-files",
    "Dependency Inventory": "dependency-inventory",
    "GitHub Actions": "github-actions",
}


@dataclass(frozen=True)
class PolicyConfig:
    fail_on: str | None = None
    require_full_coverage: bool = False
    disabled_rules: frozenset[str] = frozenset()
    exclude_paths: tuple[str, ...] = ()
    allow_critical_suppression: bool = False

    def __post_init__(self) -> None:
        if self.fail_on is not None and self.fail_on not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported policy fail_on: {self.fail_on}")
        for rule_id in self.disabled_rules:
            rule = get_rule(rule_id)
            if rule is None:
                raise ValueError(f"Unknown disabled rule: {rule_id}")
            if rule.severity == "CRITICAL" and not self.allow_critical_suppression:
                raise ValueError(f"Refusing to suppress CRITICAL rule {rule_id} without allow_critical_suppression=true")


@dataclass(frozen=True)
class PolicyApplication:
    suppressed_count: int
    suppressed_fingerprints: tuple[str, ...]
    policy_path: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "suppressed_count": self.suppressed_count,
            "suppressed_fingerprints": list(self.suppressed_fingerprints),
            "policy_path": self.policy_path,
        }


def _section(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("policy", payload)
    if not isinstance(value, dict):
        raise ValueError("Policy root must be a table/object")
    return value


def load_policy(path: str | Path) -> PolicyConfig:
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() == ".json":
        payload = json.loads(text)
    else:
        payload = tomllib.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("Policy must be an object/table")
    data = _section(payload)
    disabled = data.get("disabled_rules", [])
    excludes = data.get("exclude_paths", [])
    if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
        raise ValueError("disabled_rules must be a list of strings")
    if not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes):
        raise ValueError("exclude_paths must be a list of strings")
    fail_on = data.get("fail_on")
    if fail_on is not None and not isinstance(fail_on, str):
        raise ValueError("fail_on must be a severity string")
    require = data.get("require_full_coverage", False)
    critical = data.get("allow_critical_suppression", False)
    if not isinstance(require, bool) or not isinstance(critical, bool):
        raise ValueError("policy boolean fields must be true/false")
    return PolicyConfig(
        fail_on=fail_on.upper() if isinstance(fail_on, str) else None,
        require_full_coverage=require,
        disabled_rules=frozenset(item.upper() for item in disabled),
        exclude_paths=tuple(excludes),
        allow_critical_suppression=critical,
    )


def _path_without_line(path: str) -> str:
    match = re.match(r"^(.*):(\d+)$", path)
    return match.group(1) if match else path


def _suppressed(finding: Finding, policy: PolicyConfig) -> bool:
    if finding.check_id in policy.disabled_rules:
        return True
    path = _path_without_line(finding.path).replace("\\", "/")
    return any(fnmatch.fnmatch(path, pattern) for pattern in policy.exclude_paths)


def apply_policy(result: AuditResult, policy: PolicyConfig, *, policy_path: str | None = None) -> tuple[AuditResult, PolicyApplication]:
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in result.findings:
        (suppressed if _suppressed(finding, policy) else kept).append(finding)
    capabilities: list[CapabilityAssessment] = []
    for original in result.capabilities:
        category = CAPABILITY_CATEGORY.get(original.capability)
        count = sum(1 for finding in kept if category is not None and finding.category == category)
        if original.assessment == "NOT_ASSESSED":
            assessment = "NOT_ASSESSED"
        elif original.assessment == "BLOCKED":
            assessment = "BLOCKED"
        else:
            assessment = "FAIL" if count else "PASS"
        capabilities.append(CapabilityAssessment(original.capability, assessment, original.coverage, count, original.notes))
    filtered = AuditResult(
        root=result.root,
        findings=kept,
        manifests=list(result.manifests),
        capabilities=capabilities,
        metrics=result.metrics,
        tool_version=result.tool_version,
    )
    application = PolicyApplication(len(suppressed), tuple(sorted(finding.fingerprint for finding in suppressed)), policy_path)
    return filtered, application
