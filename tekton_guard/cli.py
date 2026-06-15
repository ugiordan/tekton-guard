"""CLI entry point for Tekton scanner."""

from __future__ import annotations

import argparse
import json
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
    parser.add_argument(
        "--diff-base",
        default=None,
        help="Only report findings in files changed since this git ref (e.g., main). Requires git.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline file to suppress known findings (.tekton-guard-baseline.json)",
    )
    parser.add_argument(
        "--update-baseline",
        default=None,
        help="Write current findings as a new baseline file",
    )
    parser.add_argument(
        "--graph",
        default=None,
        help="Generate dependency graph JSON to this file path",
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

    if args.diff_base:
        import subprocess
        try:
            diff_output = subprocess.run(
                ["git", "-C", str(target), "diff", "--name-only", "--diff-filter=ACMR",
                 f"{args.diff_base}...HEAD"],
                capture_output=True, text=True, timeout=30,
            )
            changed_files = set(diff_output.stdout.strip().split("\n")) if diff_output.stdout.strip() else set()
            changed_tekton = {f for f in changed_files if ".tekton/" in f or ".tekton\\" in f}
            if changed_tekton:
                resources = [r for r in resources if any(
                    r.file_path.endswith(f) or f in r.file_path for f in changed_tekton
                )]
                print(f"Diff mode: scanning {len(changed_tekton)} changed .tekton/ file(s)", file=sys.stderr)
            else:
                resources = []
                print("Diff mode: no .tekton/ files changed", file=sys.stderr)
        except Exception as e:
            print(f"Warning: diff-base failed ({e}), scanning all files", file=sys.stderr)

    if args.resolve:
        from tekton_guard.resolver import resolve_remote_refs
        remote = resolve_remote_refs(resources, use_network=True, method=args.resolve_method)
        if remote:
            print(f"Resolved {len(remote)} remote resource(s)", file=sys.stderr)
        resources.extend(remote)

    if args.graph:
        from tekton_guard.graph import build_dependency_graph, calculate_blast_radius, detect_cycles
        graph = build_dependency_graph(resources)
        blast = calculate_blast_radius(graph)
        cycles = detect_cycles(graph)
        graph["blast_radius"] = blast
        graph["cycles"] = cycles
        Path(args.graph).write_text(json.dumps(graph, indent=2))
        print(f"Graph written: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges", file=sys.stderr)
        if cycles:
            print(f"WARNING: {len(cycles)} cycle(s) detected!", file=sys.stderr)

    findings = run_checks(resources, config)

    if args.baseline:
        baseline_path = Path(args.baseline)
        if baseline_path.exists():
            import hashlib
            baseline_data = json.loads(baseline_path.read_text())
            baseline_keys = set()
            for entry in baseline_data.get("findings", []):
                key = (entry["rule_id"], entry["file"], entry.get("content_hash", ""))
                baseline_keys.add(key)
            original_count = len(findings)
            findings = [f for f in findings if (
                f["rule_id"], f["file"],
                hashlib.sha256(f.get("current_value", f.get("message", "")).encode()).hexdigest()[:16]
            ) not in baseline_keys]
            suppressed = original_count - len(findings)
            if suppressed:
                print(f"Baseline: suppressed {suppressed} known finding(s)", file=sys.stderr)

    if args.update_baseline:
        import hashlib
        from datetime import datetime, timezone
        baseline = {
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "findings": []
        }
        for f in findings:
            content_hash = hashlib.sha256(
                f.get("current_value", f.get("message", "")).encode()
            ).hexdigest()[:16]
            baseline["findings"].append({
                "rule_id": f["rule_id"],
                "file": f["file"],
                "content_hash": content_hash,
                "line_hint": f.get("line_start", 0),
                "reason": "",
            })
        Path(args.update_baseline).write_text(json.dumps(baseline, indent=2))
        print(f"Baseline written: {len(baseline['findings'])} finding(s) to {args.update_baseline}", file=sys.stderr)

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

        # Re-scan to get post-fix findings for exit code
        if not args.fix_dry_run:
            target2 = Path(args.target)
            if target2.is_file():
                resources = parse_file(target2)
            elif target2.is_dir():
                resources = parse_directory(target2)
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
