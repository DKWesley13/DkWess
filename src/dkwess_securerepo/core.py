"""Compatibility facade for SecureRepo's public scanning/reporting API."""

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
from .scanner import TOOL_VERSION, scan_repository

__all__ = [
    "ASSESSMENT_STATES",
    "CONFIDENCE_STATES",
    "COVERAGE_STATES",
    "SEVERITY_ORDER",
    "AuditResult",
    "CapabilityAssessment",
    "Finding",
    "ScanMetrics",
    "TOOL_VERSION",
    "render_markdown",
    "scan_repository",
    "write_reports",
]
