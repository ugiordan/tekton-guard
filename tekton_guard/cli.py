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
