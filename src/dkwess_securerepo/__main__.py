from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .baseline import compare_baseline, load_baseline, write_baseline
from .core import SEVERITY_ORDER, scan_repository, write_reports
from .provenance import write_provenance
from .rules import get_rule, iter_rules
from .sarif import write_sarif
from .supply_chain import write_supply_chain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dkwess-securerepo", description="Evidence-oriented repository governance, supply-chain hygiene and GitHub Actions auditing.")
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan (default: current directory).")
    parser.add_argument("--output", default="reports", help="Directory for audit.json and audit.md (default: reports).")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH", help="Return exit code 2 if this severity or higher is found (default: HIGH).")
    parser.add_argument("--require-full-coverage", action="store_true", help="Return exit code 3 when any capability coverage is PARTIAL or UNKNOWN.")
    parser.add_argument("--no-reports", action="store_true", help="Do not write audit.json/audit.md.")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON audit output to stdout.")
    parser.add_argument("--list-checks", action="store_true", help="List all built-in rule IDs and exit.")
    parser.add_argument("--explain", metavar="RULE_ID", help="Explain one built-in rule and exit.")
    parser.add_argument("--write-baseline", metavar="FILE", help="Write current finding fingerprints as a baseline.")
    parser.add_argument("--compare-baseline", metavar="FILE", help="Compare current findings with a baseline.")
    parser.add_argument("--fail-on-new", action="store_true", help="With --compare-baseline, gate only new findings; exit 4 on regression.")
    parser.add_argument("--supply-chain", metavar="FILE", help="Write a local static supply-chain inventory JSON file.")
    parser.add_argument("--provenance", metavar="FILE", help="Write local Git/manifests provenance evidence JSON.")
    parser.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 results for code-scanning compatible consumers.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _print_rules() -> None:
    print("DkWess SecureRepo built-in checks")
    for rule in iter_rules():
        print(f"{rule.rule_id:<12} {rule.severity:<8} {rule.category:<22} {rule.title}")


def _explain_rule(rule_id: str) -> int:
    rule = get_rule(rule_id)
    if rule is None:
        print(f"Unknown SecureRepo rule: {rule_id}", file=sys.stderr); return 1
    print(f"Rule: {rule.rule_id}\nTitle: {rule.title}\nCategory: {rule.category}\nSeverity: {rule.severity}\nDefault confidence: {rule.confidence}\nDescription: {rule.description}\nRemediation: {rule.remediation}")
    return 0


def _print_human_summary(result, report_paths: tuple[Path, Path] | None) -> None:
    counts = result.counts; metrics = result.metrics
    print(f"DkWess SecureRepo v{result.tool_version}\nStatus: {result.status}\nFindings: {len(result.findings)}")
    print(" | ".join([f"CRITICAL: {counts['CRITICAL']}", f"HIGH: {counts['HIGH']}", f"MEDIUM: {counts['MEDIUM']}", f"LOW: {counts['LOW']}", f"INFO: {counts['INFO']}"]))
    print(f"Discovery: {metrics.files_discovered} files | {metrics.workflows_discovered} workflows | {metrics.manifests_detected} manifests | {metrics.symlinks_skipped} symlinks skipped")
    print(f"Implemented capability coverage: {result.coverage_percent}%")
    for capability in result.capabilities:
        print(f"  {capability.capability}: {capability.assessment} / {capability.coverage} ({capability.finding_count} findings)")
    if report_paths: print(f"Reports: {report_paths[0]}, {report_paths[1]}")
    print("PASS != SECURITY GUARANTEE")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks: _print_rules(); return 0
    if args.explain: return _explain_rule(args.explain)
    if args.fail_on_new and not args.compare_baseline:
        print("SecureRepo error: --fail-on-new requires --compare-baseline", file=sys.stderr); return 1
    try:
        result = scan_repository(args.path)
        report_paths = None if args.no_reports else write_reports(result, args.output)
        if args.write_baseline: write_baseline(result, args.write_baseline)
        comparison = compare_baseline(result, load_baseline(args.compare_baseline)) if args.compare_baseline else None
        if args.supply_chain: write_supply_chain(args.path, result, args.supply_chain)
        if args.provenance: write_provenance(args.path, result, args.provenance)
        if args.sarif: write_sarif(result, args.sarif)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SecureRepo error: {exc}", file=sys.stderr); return 1
    if args.json_stdout:
        payload: dict[str, object] = {"audit": result.as_dict()}
        if comparison is not None: payload["baseline_comparison"] = comparison.as_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human_summary(result, report_paths)
        if comparison is not None: print(f"Baseline: {len(comparison.new_findings)} new | {len(comparison.resolved_fingerprints)} resolved | {len(comparison.unchanged_fingerprints)} unchanged")
        if args.supply_chain: print(f"Supply-chain inventory: {args.supply_chain}")
        if args.provenance: print(f"Provenance evidence: {args.provenance}")
        if args.sarif: print(f"SARIF: {args.sarif}")
    if args.fail_on_new and comparison is not None:
        if comparison.has_new_at_or_above(args.fail_on): return 4
        if args.require_full_coverage and any(capability.coverage != "FULL" for capability in result.capabilities): return 3
        return 0
    return result.exit_code(args.fail_on, require_full_coverage=args.require_full_coverage)


if __name__ == "__main__":
    raise SystemExit(main())
