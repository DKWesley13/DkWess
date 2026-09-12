from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib

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

    @property
    def fingerprint(self) -> str:
        payload = f"{self.check_id}\0{self.path}\0{self.title}".encode("utf-8", errors="replace")
        return hashlib.sha256(payload).hexdigest()[:20]

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data


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


@dataclass(frozen=True)
class ScanMetrics:
    files_discovered: int
    symlinks_skipped: int
    discovery_errors: int
    workflows_discovered: int
    manifests_detected: int

    def __post_init__(self) -> None:
        for value in (
            self.files_discovered,
            self.symlinks_skipped,
            self.discovery_errors,
            self.workflows_discovered,
            self.manifests_detected,
        ):
            if value < 0:
                raise ValueError("scan metrics must be >= 0")


@dataclass
class AuditResult:
    root: str
    findings: list[Finding]
    manifests: list[str]
    capabilities: list[CapabilityAssessment]
    metrics: ScanMetrics
    tool_version: str

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
    def coverage_percent(self) -> int:
        if not self.capabilities:
            return 0
        full = sum(1 for capability in self.capabilities if capability.coverage == "FULL")
        return round((full / len(self.capabilities)) * 100)

    @property
    def status(self) -> str:
        if any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["HIGH"] for finding in self.findings):
            return "FAIL"
        if any(capability.assessment == "BLOCKED" for capability in self.capabilities):
            return "REVIEW_REQUIRED"
        if self.findings:
            return "REVIEW_REQUIRED"
        return "PASS"

    def exit_code(self, fail_on: str = "HIGH", require_full_coverage: bool = False) -> int:
        if fail_on not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported fail-on severity: {fail_on}")
        threshold = SEVERITY_ORDER[fail_on]
        if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in self.findings):
            return 2
        if require_full_coverage and any(capability.coverage != "FULL" for capability in self.capabilities):
            return 3
        return 0

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 3,
            "tool": "DkWess SecureRepo",
            "tool_version": self.tool_version,
            "root": self.root,
            "status": self.status,
            "security_guarantee": False,
            "statement": "PASS != SECURITY GUARANTEE",
            "counts": self.counts,
            "coverage_counts": self.coverage_counts,
            "coverage_percent": self.coverage_percent,
            "metrics": asdict(self.metrics),
            "manifests": self.manifests,
            "capabilities": [asdict(capability) for capability in self.capabilities],
            "findings": [finding.as_dict() for finding in self.findings],
        }
