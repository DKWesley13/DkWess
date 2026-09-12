"""DkWess SecureRepo public API."""

from .version import VERSION as __version__
from . import scanner as _scanner

# Keep the internal scanner's evidence version aligned with the public package version.
_scanner.TOOL_VERSION = __version__

from .baseline import BaselineComparison, compare_baseline, load_baseline, write_baseline
from .core import AuditResult, CapabilityAssessment, Finding, ScanMetrics, scan_repository, write_reports
from .hardening import describe_limits, preflight_repository
from .policy import PolicyApplication, PolicyConfig, apply_policy, load_policy
from .provenance import provenance_payload, write_provenance
from .release import release_readiness
from .sarif import sarif_payload, write_sarif
from .sbom import sbom_payload, write_sbom
from .supply_chain import supply_chain_payload, write_supply_chain

__all__ = [
    "AuditResult", "BaselineComparison", "CapabilityAssessment", "Finding", "PolicyApplication", "PolicyConfig", "ScanMetrics",
    "apply_policy", "compare_baseline", "describe_limits", "load_baseline", "load_policy", "preflight_repository", "provenance_payload",
    "release_readiness", "sarif_payload", "sbom_payload", "scan_repository", "supply_chain_payload", "write_baseline", "write_provenance",
    "write_reports", "write_sarif", "write_sbom", "write_supply_chain",
]
