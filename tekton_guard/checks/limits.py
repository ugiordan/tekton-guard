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
        # Resources are not currently parsed into StepDef, check raw
        # This is a basic check: steps without any resource constraints
        # For now, we skip this since resources aren't in StepDef yet
        pass
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
        if "h" in val:
            parts = val.split("h")
            hours += float(parts[0])
            val = parts[1] if len(parts) > 1 else ""
        if "m" in val:
            parts = val.split("m")
            hours += float(parts[0]) / 60
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
                extra={"timeout_value": str(pipeline_timeout), "timeout_hours": hours},
            ))

    if tasks_timeout:
        hours = _parse_duration_hours(str(tasks_timeout))
        if hours > 2:
            findings.append(_finding(
                "TKN-LIMIT-002", "LOW", "Excessive task timeout",
                resource, resource.line_offset,
                f"PipelineRun '{resource.name}' has a tasks timeout of '{tasks_timeout}' "
                f"(>{2}h). Long task timeouts increase the attack window.",
                cwe="CWE-400",
                remediation="Reduce task timeout to 2 hours or less.",
                extra={"timeout_value": str(tasks_timeout), "timeout_hours": hours},
            ))
    return findings
