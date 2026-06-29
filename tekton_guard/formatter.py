"""Output formatting for Tekton scanner findings."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any


def _category_from_rule(rule_id: str) -> str:
    prefix = rule_id.split("-")[1] if "-" in rule_id else ""
    return {
        "PIN": "pinning",
        "TRUST": "trust",
        "SA": "service_account",
        "WS": "workspace",
        "RES": "result_injection",
        "CHAIN": "chains_readiness",
        "SEC": "security_context",
        "VOL": "volume_mount",
        "TRIG": "trigger_security",
        "LIMIT": "resource_limits",
        "EXFIL": "exfiltration",
        "LOGIC": "pipeline_logic",
    }.get(prefix, "unknown")


def format_json(findings: list[dict[str, Any]], target: str) -> str:
    by_severity: dict[str, int] = Counter()
    by_category: dict[str, int] = Counter()

    for f in findings:
        by_severity[f["severity"]] += 1
        by_category[_category_from_rule(f["rule_id"])] += 1

    report = {
        "version": "1.0.0",
        "scanner": "tekton-guard",
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
        },
    }
    return json.dumps(report, indent=2)


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def format_sarif(findings: list[dict[str, Any]], target: str) -> str:
    rules_seen: dict[str, dict] = {}
    results = []

    for f in findings:
        rule_id = f["rule_id"]
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f["title"]},
                "helpUri": "",
                "properties": {"category": _category_from_rule(rule_id)},
            }
            if f.get("cwe"):
                rules_seen[rule_id]["properties"]["cwe"] = f["cwe"]

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {
                        "startLine": f.get("line_start", 1),
                        "endLine": f.get("line_end", f.get("line_start", 1)),
                    },
                },
            }],
        }
        if f.get("remediation"):
            result["fixes"] = [{"description": {"text": f["remediation"]}}]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "tekton-guard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/opendatahub-io/tekton-guard",
                    "rules": list(rules_seen.values()),
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def format_text(findings: list[dict[str, Any]], target: str) -> str:
    if not findings:
        return f"No findings in {target}\n"

    lines = [f"Tekton Security Scan: {target}", f"Found {len(findings)} issue(s)", ""]
    for f in findings:
        lines.append(f"[{f['severity']}] {f['rule_id']}: {f['title']}")
        lines.append(f"  File: {f['file']}:{f.get('line_start', '?')}")
        lines.append(f"  {f['message']}")
        if f.get("remediation"):
            lines.append(f"  Fix: {f['remediation']}")
        lines.append("")
    return "\n".join(lines)
