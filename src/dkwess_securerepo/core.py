"""Compatibility facade for SecureRepo's public scanning/reporting API."""

from .hardening import preflight_repository
from .models import (
    ASSESSMENT_STATES,
    CONFIDENCE_STATES,
    COVERAGE_STATES,
    SEVERITY_ORDER,
    AuditResult,
    CapabilityAssessment,
    Finding,
    ScanMetrics,
)
from .reporting import render_markdown, write_reports
from .scanner import scan_repository as _scan_repository
from .version import VERSION as TOOL_VERSION


def scan_repository(root):
    preflight_repository(root)
    result = _scan_repository(root)
    result.tool_version = TOOL_VERSION
    return result


__all__ = [
    "ASSESSMENT_STATES", "CONFIDENCE_STATES", "COVERAGE_STATES", "SEVERITY_ORDER",
    "AuditResult", "CapabilityAssessment", "Finding", "ScanMetrics", "TOOL_VERSION",
    "render_markdown", "scan_repository", "write_reports",
]
