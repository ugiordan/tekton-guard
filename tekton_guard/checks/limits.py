"""Resource limit checks (TKN-LIMIT-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, collect_all_containers, register_check


@register_check
def check_limit_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-LIMIT-001: Missing resource requests/limits."""
    findings = []
    for ci in collect_all_containers(resource):
        res = ci.container.resources
        has_requests = bool(res.get("requests"))
        has_limits = bool(res.get("limits"))
        if has_requests or has_limits:
            continue
        if not ci.container.image:
            continue
        findings.append(_finding(
            "TKN-LIMIT-001", "LOW", "Missing resource requests/limits",
            resource, ci.container.image_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} "
            f"has no resource requests or limits. Unbounded resource consumption "
            f"can cause DoS or noisy-neighbor issues in shared build clusters.",
            cwe="CWE-400",
            remediation="Add resources.requests and resources.limits to the step spec.",
            extra={"step_name": ci.container.name, "container_type": ci.container_type},
        ))
    return findings


@register_check
def check_limit_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-LIMIT-002: Excessive timeout."""
    if resource.kind != "PipelineRun":
        return []
    findings = []
    raw_spec = resource.raw.get("spec", {})
    timeouts = raw_spec.get("timeouts", {})
    if not timeouts:
        return []

    pipeline_timeout = timeouts.get("pipeline", "")
    tasks_timeout = timeouts.get("tasks", "")

    def _parse_duration_hours(val: str) -> float:
        if not val:
            return 0
        val = str(val).strip()
        hours = 0.0
        try:
            if "h" in val:
                parts = val.split("h")
                hours += float(parts[0])
                val = parts[1] if len(parts) > 1 else ""
            if "m" in val:
                parts = val.split("m")
                hours += float(parts[0]) / 60
                val = parts[1] if len(parts) > 1 else ""
            if "s" in val:
                parts = val.split("s")
                hours += float(parts[0]) / 3600
        except (ValueError, IndexError):
            return 0
        return hours

    if pipeline_timeout:
        hours = _parse_duration_hours(str(pipeline_timeout))
        if hours > 4:
            findings.append(_finding(
                "TKN-LIMIT-002", "LOW", "Excessive pipeline timeout",
                resource, resource.line_offset,
                f"PipelineRun '{resource.name}' has a pipeline timeout of '{pipeline_timeout}' "
                f"(>{4}h). Long-running pipelines increase the attack window.",
                cwe="CWE-400",
                remediation="Reduce pipeline timeout to 4 hours or less.",
                extra={"timeout_type": "pipeline", "timeout_value": str(pipeline_timeout), "timeout_hours": hours},
            ))

    if tasks_timeout:
        hours = _parse_duration_hours(str(tasks_timeout))
        if hours > 3:
            findings.append(_finding(
                "TKN-LIMIT-002", "LOW", "Excessive task timeout",
                resource, resource.line_offset,
                f"PipelineRun '{resource.name}' has a tasks timeout of '{tasks_timeout}' "
                f"(>{3}h). Long task timeouts increase the attack window.",
                cwe="CWE-400",
                remediation="Reduce task timeout to 3 hours or less.",
                extra={"timeout_type": "tasks", "timeout_value": str(tasks_timeout), "timeout_hours": hours},
            ))
    return findings
