from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .baseline import compare_baseline, load_baseline, write_baseline
from .core import SEVERITY_ORDER, scan_repository, write_reports
from .rules import get_rule, iter_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dkwess-securerepo",
        description=(
            "Audit repository governance, sensitive filenames, dependency hygiene, and GitHub Actions risk patterns "
            "with explicit evidence and coverage states."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan (default: current directory).")
    parser.add_argument("--output", default="reports", help="Directory for audit.json and audit.md (default: reports).")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH", help="Return exit code 2 if this severity or higher is found (default: HIGH).")
    parser.add_argument("--require-full-coverage", action="store_true", help="Return exit code 3 when any capability coverage is PARTIAL or UNKNOWN and no finding threshold already failed.")
    parser.add_argument("--no-reports", action="store_true", help="Do not write audit.json/audit.md.")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON audit output to stdout.")
    parser.add_argument("--list-checks", action="store_true", help="List all built-in rule IDs and exit.")
    parser.add_argument("--explain", metavar="RULE_ID", help="Explain one built-in rule and exit.")
    parser.add_argument("--write-baseline", metavar="FILE", help="Write the current finding fingerprints as a baseline JSON file.")
    parser.add_argument("--compare-baseline", metavar="FILE", help="Compare current findings with a previously written baseline.")
    parser.add_argument("--fail-on-new", action="store_true", help="With --compare-baseline, gate only new findings at --fail-on severity; exit 4 on regression.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _print_rules() -> None:
    print("DkWess SecureRepo built-in checks")
    for rule in iter_rules():
        print(f"{rule.rule_id:<12} {rule.severity:<8} {rule.category:<22} {rule.title}")


def _explain_rule(rule_id: str) -> int:
    rule = get_rule(rule_id)
    if rule is None:
        print(f"Unknown SecureRepo rule: {rule_id}", file=sys.stderr)
        return 1
    print(f"Rule: {rule.rule_id}")
    print(f"Title: {rule.title}")
    print(f"Category: {rule.category}")
    print(f"Severity: {rule.severity}")
    print(f"Default confidence: {rule.confidence}")
    print(f"Description: {rule.description}")
    print(f"Remediation: {rule.remediation}")
    return 0


def _print_human_summary(result, report_paths: tuple[Path, Path] | None) -> None:
    counts = result.counts
    metrics = result.metrics
    print(f"DkWess SecureRepo v{result.tool_version}")
    print(f"Status: {result.status}")
    print(f"Findings: {len(result.findings)}")
    print(" | ".join([f"CRITICAL: {counts['CRITICAL']}", f"HIGH: {counts['HIGH']}", f"MEDIUM: {counts['MEDIUM']}", f"LOW: {counts['LOW']}", f"INFO: {counts['INFO']}"]))
    print("Discovery: " f"{metrics.files_discovered} files | {metrics.workflows_discovered} workflows | " f"{metrics.manifests_detected} manifests | {metrics.symlinks_skipped} symlinks skipped")
    print(f"Implemented capability coverage: {result.coverage_percent}%")
    print("Capabilities:")
    for capability in result.capabilities:
        print(f"  {capability.capability}: {capability.assessment} / {capability.coverage} ({capability.finding_count} findings)")
    if report_paths:
        print(f"Reports: {report_paths[0]}, {report_paths[1]}")
    print("PASS != SECURITY GUARANTEE")


def _print_baseline(comparison) -> None:
    print("Baseline regression comparison:")
    print(f"  New: {len(comparison.new_findings)}")
    print(f"  Resolved: {len(comparison.resolved_fingerprints)}")
    print(f"  Unchanged: {len(comparison.unchanged_fingerprints)}")
    for finding in comparison.new_findings:
        print(f"  NEW {finding.severity:<8} {finding.check_id} {finding.path} :: {finding.title}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        _print_rules()
        return 0
    if args.explain:
        return _explain_rule(args.explain)
    if args.fail_on_new and not args.compare_baseline:
        print("SecureRepo error: --fail-on-new requires --compare-baseline", file=sys.stderr)
        return 1
    try:
        result = scan_repository(args.path)
        report_paths: tuple[Path, Path] | None = None
        if not args.no_reports:
            report_paths = write_reports(result, args.output)
        if args.write_baseline:
            write_baseline(result, args.write_baseline)
        comparison = compare_baseline(result, load_baseline(args.compare_baseline)) if args.compare_baseline else None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SecureRepo error: {exc}", file=sys.stderr)
        return 1
    if args.json_stdout:
        payload: dict[str, object] = {"audit": result.as_dict()}
        if comparison is not None:
            payload["baseline_comparison"] = comparison.as_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human_summary(result, report_paths)
        if args.write_baseline:
            print(f"Baseline written: {args.write_baseline}")
        if comparison is not None:
            _print_baseline(comparison)
    if args.fail_on_new and comparison is not None:
        if comparison.has_new_at_or_above(args.fail_on):
            return 4
        if args.require_full_coverage and any(capability.coverage != "FULL" for capability in result.capabilities):
            return 3
        return 0
    return result.exit_code(args.fail_on, require_full_coverage=args.require_full_coverage)


if __name__ == "__main__":
    raise SystemExit(main())
