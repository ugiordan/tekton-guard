"""CLI entry point for Tekton scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tekton_guard.checks import run_checks, SEVERITY_ORDER
from tekton_guard.config import load_config
from tekton_guard.formatter import format_json, format_sarif, format_text
from tekton_guard.parser import parse_directory, parse_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tekton-guard",
        description="Security scanner for Tekton pipeline definitions",
    )
    parser.add_argument(
        "target",
        help="Path to a repo directory (scans .tekton/) or a single YAML file",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "text"],
        default="json",
        dest="output_format",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Config file with trust lists and check settings",
    )
    parser.add_argument(
        "--min-severity",
        default=None,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to report (overrides config)",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Exit 1 only if findings at or above this severity (default: any finding)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help="Always exit 0 regardless of findings (for informational runs)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Apply safe fixes (SHA pinning, readOnly). Requires GITHUB_TOKEN for git ref resolution.",
    )
    parser.add_argument(
        "--fix-dry-run",
        action="store_true",
        default=False,
        help="Preview fixes without applying them.",
    )
    parser.add_argument(
        "--resolve",
        action="store_true",
        default=False,
        help="Follow git resolver URLs to fetch and scan remote Pipeline/Task definitions",
    )
    parser.add_argument(
        "--resolve-method",
        choices=["api", "clone"],
        default="api",
        help="How to fetch remote resources: api (HTTP, fast) or clone (git, works with tokens)",
    )

    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.min_severity:
        config.min_severity = args.min_severity

    target = Path(args.target)
    if target.is_file():
        resources = parse_file(target)
    elif target.is_dir():
        resources = parse_directory(target)
    else:
        print(f"Error: '{args.target}' is not a valid file or directory", file=sys.stderr)
        return 2

    if args.resolve:
        from tekton_guard.resolver import resolve_remote_refs
        remote = resolve_remote_refs(resources, use_network=True, method=args.resolve_method)
        if remote:
            print(f"Resolved {len(remote)} remote resource(s)", file=sys.stderr)
        resources.extend(remote)

    findings = run_checks(resources, config)

    if args.fix or args.fix_dry_run:
        from tekton_guard.fixer import FixEngine
        engine = FixEngine(dry_run=args.fix_dry_run)
        # Group findings by file
        by_file: dict[str, list[dict]] = {}
        for f in findings:
            by_file.setdefault(f["file"], []).append(f)
        all_results = []
        for file_path, file_findings in by_file.items():
            result = engine.fix_findings(file_findings, file_path)
            all_results.append(result)
        total_fixed = sum(r.total_fixed for r in all_results)
        total_skipped = sum(len(r.skipped) for r in all_results)
        total_failed = sum(len(r.failed) for r in all_results)
        mode = "dry-run" if args.fix_dry_run else "applied"
        print(f"Fix {mode}: {total_fixed} fixed, {total_skipped} skipped, {total_failed} failed", file=sys.stderr)

    if args.output_format == "json":
        output = format_json(findings, str(target))
    elif args.output_format == "sarif":
        output = format_sarif(findings, str(target))
    else:
        output = format_text(findings, str(target))

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)

    if args.exit_zero:
        return 0

    if not findings:
        return 0

    if args.fail_on:
        threshold = SEVERITY_ORDER.get(args.fail_on, 0)
        if any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold for f in findings):
            return 1
        return 0

    return 1
