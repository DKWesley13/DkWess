from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .baseline import compare_baseline, load_baseline, write_baseline
from .core import SEVERITY_ORDER, scan_repository, write_reports
from .hardening import describe_limits
from .policy import PolicyConfig, apply_policy, load_policy
from .provenance import write_provenance
from .release import release_readiness
from .rules import get_rule, iter_rules
from .sarif import write_sarif
from .sbom import write_sbom
from .supply_chain import write_supply_chain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dkwess-securerepo",
        description="Audit repository governance, CI workflows and supply-chain evidence without executing target project code.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to audit (default: current directory).")
    parser.add_argument("--output", default="reports", help="Directory for audit.json/audit.md (default: reports).")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None, help="Failure severity; overrides policy (default: HIGH).")
    parser.add_argument("--require-full-coverage", action="store_true", help="Exit 3 when implemented capability coverage is not FULL.")
    parser.add_argument("--policy", metavar="FILE", help="Load TOML/JSON SecureRepo policy.")
    parser.add_argument("--no-reports", action="store_true", help="Do not write default audit.json/audit.md.")
    parser.add_argument("--json-stdout", action="store_true", help="Emit machine-readable audit/policy/baseline JSON to stdout.")
    parser.add_argument("--list-checks", action="store_true", help="List built-in checks and exit.")
    parser.add_argument("--explain", metavar="RULE_ID", help="Explain one rule and its remediation.")
    parser.add_argument("--show-limits", action="store_true", help="Show built-in resource bounds and exit.")
    parser.add_argument("--write-baseline", metavar="FILE", help="Write current finding fingerprints as a known-findings baseline.")
    parser.add_argument("--compare-baseline", metavar="FILE", help="Compare current findings to a baseline.")
    parser.add_argument("--fail-on-new", action="store_true", help="With --compare-baseline, fail only on new findings at threshold; exit 4.")
    parser.add_argument("--supply-chain", metavar="FILE", help="Write static local supply-chain inventory JSON.")
    parser.add_argument("--provenance", metavar="FILE", help="Write credential-redacted local Git/manifests provenance JSON.")
    parser.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 findings.")
    parser.add_argument("--sbom", metavar="FILE", help="Write best-effort CycloneDX 1.5 static dependency inventory.")
    parser.add_argument("--release-check", action="store_true", help="Evaluate v1 technical-release gates; exit 5 on technical blocker. License is reported separately.")
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
    print(f"Rule: {rule.rule_id}\nTitle: {rule.title}\nCategory: {rule.category}\nSeverity: {rule.severity}\nDefault confidence: {rule.confidence}\nDescription: {rule.description}\nRemediation: {rule.remediation}")
    return 0


def _print_human_summary(result, report_paths: tuple[Path, Path] | None, policy_application=None) -> None:
    counts = result.counts; metrics = result.metrics
    print(f"DkWess SecureRepo v{result.tool_version}")
    print(f"Status: {result.status}")
    print(f"Findings: {len(result.findings)}")
    print(" | ".join([f"CRITICAL: {counts['CRITICAL']}", f"HIGH: {counts['HIGH']}", f"MEDIUM: {counts['MEDIUM']}", f"LOW: {counts['LOW']}", f"INFO: {counts['INFO']}"]))
    print(f"Discovery: {metrics.files_discovered} files | {metrics.workflows_discovered} workflows | {metrics.manifests_detected} manifests | {metrics.symlinks_skipped} symlinks skipped")
    print(f"Implemented capability coverage: {result.coverage_percent}%")
    for capability in result.capabilities:
        print(f"  {capability.capability}: {capability.assessment} / {capability.coverage} ({capability.finding_count} findings)")
    if policy_application is not None:
        print(f"Policy suppressions: {policy_application.suppressed_count}")
    if report_paths:
        print(f"Reports: {report_paths[0]}, {report_paths[1]}")
    print("PASS != SECURITY GUARANTEE")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        _print_rules(); return 0
    if args.explain:
        return _explain_rule(args.explain)
    if args.show_limits:
        print(json.dumps(describe_limits(), indent=2, sort_keys=True)); return 0
    if args.fail_on_new and not args.compare_baseline:
        print("SecureRepo error: --fail-on-new requires --compare-baseline", file=sys.stderr); return 1
    try:
        policy = load_policy(args.policy) if args.policy else PolicyConfig()
        fail_on = args.fail_on or policy.fail_on or "HIGH"
        require_full_coverage = args.require_full_coverage or policy.require_full_coverage
        raw_result = scan_repository(args.path)
        result, policy_application = apply_policy(raw_result, policy, policy_path=args.policy)
        readiness = release_readiness(args.path, raw_result) if args.release_check else None
        report_paths = None if args.no_reports else write_reports(result, args.output)
        if args.write_baseline: write_baseline(result, args.write_baseline)
        comparison = compare_baseline(result, load_baseline(args.compare_baseline)) if args.compare_baseline else None
        if args.supply_chain: write_supply_chain(args.path, result, args.supply_chain)
        if args.provenance: write_provenance(args.path, result, args.provenance)
        if args.sarif: write_sarif(result, args.sarif)
        if args.sbom: write_sbom(args.path, result, args.sbom)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SecureRepo error: {exc}", file=sys.stderr); return 1
    if args.json_stdout:
        payload: dict[str, object] = {"audit": result.as_dict(), "policy_application": policy_application.as_dict()}
        if comparison is not None: payload["baseline_comparison"] = comparison.as_dict()
        if readiness is not None: payload["release_readiness"] = readiness
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human_summary(result, report_paths, policy_application)
        if comparison is not None: print(f"Baseline: {len(comparison.new_findings)} new | {len(comparison.resolved_fingerprints)} resolved | {len(comparison.unchanged_fingerprints)} unchanged")
        for label, value in (("Supply-chain inventory", args.supply_chain), ("Provenance evidence", args.provenance), ("SARIF", args.sarif), ("SBOM", args.sbom)):
            if value: print(f"{label}: {value}")
        if readiness is not None:
            print("Release readiness:")
            print(f"  Technical ready: {readiness['technical_ready']}")
            print(f"  Open-source reuse ready: {readiness['open_source_reuse_ready']}")
            print(f"  License file: {readiness['license_file'] or 'MISSING'}")
    if args.release_check and readiness is not None and not readiness["technical_ready"]:
        return 5
    if args.fail_on_new and comparison is not None:
        if comparison.has_new_at_or_above(fail_on): return 4
        if require_full_coverage and any(capability.coverage != "FULL" for capability in result.capabilities): return 3
        return 0
    return result.exit_code(fail_on, require_full_coverage=require_full_coverage)


if __name__ == "__main__":
    raise SystemExit(main())
