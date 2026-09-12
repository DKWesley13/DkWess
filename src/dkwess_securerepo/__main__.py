from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .core import SEVERITY_ORDER, scan_repository, write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dkwess-securerepo",
        description="Audit repository governance, sensitive filenames, dependency manifests, and GitHub Actions hygiene.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan (default: current directory).")
    parser.add_argument("--output", default="reports", help="Directory for audit.json and audit.md (default: reports).")
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        default="HIGH",
        help="Return exit code 2 if this severity or higher is found (default: HIGH).",
    )
    parser.add_argument("--no-reports", action="store_true", help="Print the summary but do not write report files.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan_repository(args.path)
        report_paths: tuple[Path, Path] | None = None
        if not args.no_reports:
            report_paths = write_reports(result, args.output)
    except (OSError, ValueError) as exc:
        print(f"SecureRepo error: {exc}", file=sys.stderr)
        return 1

    counts = result.counts
    print("DkWess SecureRepo")
    print(f"Status: {result.status}")
    print(f"Findings: {len(result.findings)}")
    print(
        " | ".join(
            [
                f"CRITICAL: {counts['CRITICAL']}",
                f"HIGH: {counts['HIGH']}",
                f"MEDIUM: {counts['MEDIUM']}",
                f"LOW: {counts['LOW']}",
                f"INFO: {counts['INFO']}",
            ]
        )
    )
    print("Capabilities:")
    for capability in result.capabilities:
        print(
            f"  {capability.capability}: {capability.assessment} / "
            f"{capability.coverage} ({capability.finding_count} findings)"
        )
    if report_paths:
        print(f"Reports: {report_paths[0]}, {report_paths[1]}")
    print("PASS != SECURITY GUARANTEE")
    return result.exit_code(args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
