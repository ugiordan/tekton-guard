"""Result injection checks (TKN-RES-001..004)."""

from __future__ import annotations

import re

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import (
    PARAM_INTERP_RE, _finding, collect_all_containers, register_check,
)

_TASK_RESULT_REF_RE = re.compile(r"\$\(tasks\.([^.]+)\.results\.([^)]+)\)")

_PAC_TAINT_SOURCES = [
    "source_url", "repo_url", "revision", "source_branch",
    "target_branch", "sender", "pull_request_number", "body",
]
_PAC_TAINT_RE = re.compile(r"\{\{\s*(" + "|".join(_PAC_TAINT_SOURCES) + r")\s*\}\}")


@register_check
def check_res_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-RES-001: Task result interpolated in script block."""
    findings = []
    for ci in collect_all_containers(resource):
        if not ci.container.script:
            continue
        matches = PARAM_INTERP_RE.findall(ci.container.script)
        if not matches:
            continue
        findings.append(_finding(
            "TKN-RES-001", "MEDIUM",
            "Parameter/result interpolation in script block",
            resource, ci.container.script_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} interpolates {len(matches)} variable(s) directly "
            f"in a script block: {', '.join(matches[:5])}. "
            f"If any interpolated value comes from untrusted input, this enables "
            f"arbitrary code injection (the Tekton equivalent of GitHub Actions "
            f"${{{{ }}}} injection).",
            cwe="CWE-94",
            remediation="Pass values as environment variables instead of interpolating them in scripts. Use 'env' with 'value: $(params.name)' and reference $ENV_VAR in the script.",
            extra={"step_name": ci.container.name, "interpolations": matches[:10]},
        ))
    return findings


@register_check
def check_res_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-RES-002: Parameter interpolation in command args."""
    findings = []
    for ci in collect_all_containers(resource):
        all_args = ci.container.args + ci.container.command
        interps = []
        for arg in all_args:
            interps.extend(PARAM_INTERP_RE.findall(str(arg)))
        if not interps:
            continue
        findings.append(_finding(
            "TKN-RES-002", "LOW",
            "Parameter interpolation in command args",
            resource, ci.container.args_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} interpolates variables in command/args: "
            f"{', '.join(interps[:5])}. While safer than script injection, "
            f"this can still enable command injection if values are untrusted.",
            cwe="CWE-78",
            remediation="Validate parameter values before use, or pass them as environment variables.",
            extra={"step_name": ci.container.name, "interpolations": interps[:10]},
        ))
    return findings


@register_check
def check_res_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-RES-003: PaC-sourced parameter taint."""
    if resource.kind != "PipelineRun":
        return []
    findings = []
    # Resolve line numbers from raw spec params for dedup
    resource.raw.get("spec", {}).get("params", [])
    for idx, param in enumerate(resource.params):
        if not isinstance(param, dict):
            continue
        value = str(param.get("value", ""))
        matches = _PAC_TAINT_RE.findall(value)
        if not matches:
            continue
        param_name = param.get("name", "unknown")
        if param_name in config.known_safe_pac_params:
            continue
        param_line = resource.line_offset + idx + 1
        findings.append(_finding(
            "TKN-RES-003", "MEDIUM",
            "PaC-sourced parameter taint",
            resource, param_line,
            f"PipelineRun '{resource.name}' passes PaC template variable(s) "
            f"({', '.join(matches)}) via param '{param_name}'. These values come from "
            f"webhook data and may reach script interpolation points in referenced tasks.",
            cwe="CWE-94",
            remediation="Validate PaC-sourced parameter values before using them in scripts. Pass through environment variables instead of direct interpolation.",
            extra={"param_name": param_name, "taint_sources": matches},
        ))
    return findings


# Result names consumed by Tekton Chains (covered by CHAIN-004, skip here to avoid duplication)
_CHAINS_CONSUMED_RESULTS = {"IMAGE_URL", "IMAGE_DIGEST", "CHAINS-GIT_URL", "CHAINS-GIT_COMMIT"}


@register_check
def check_res_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-RES-004: Untrusted task result consumed without validation."""
    if resource.kind != "Pipeline":
        return []

    # Build map: task_name -> is_untrusted
    untrusted_tasks: set[str] = set()
    all_tasks = resource.pipeline_tasks + resource.finally_tasks
    for pt in all_tasks:
        if not pt.task_ref or not pt.task_ref.resolver:
            continue
        ref = pt.task_ref.resolver
        if ref.resolver_type == "hub":
            untrusted_tasks.add(pt.name)
        elif ref.resolver_type == "git" and not config.is_trusted_git_source(ref.url):
            untrusted_tasks.add(pt.name)

    if not untrusted_tasks:
        return []

    findings: list[dict] = []
    raw_tasks = resource.raw.get("spec", {}).get("tasks", [])
    raw_finally = resource.raw.get("spec", {}).get("finally", [])

    for task_data in (raw_tasks or []) + (raw_finally or []):
        consumer_name = str(task_data.get("name", ""))
        # FP guard: skip if the consuming task is also untrusted (both sides untrusted, nothing new)
        if consumer_name in untrusted_tasks:
            continue

        # Check params for task result references
        params = task_data.get("params", [])
        for param in params or []:
            if not isinstance(param, dict):
                continue
            value = str(param.get("value", ""))
            for match in _TASK_RESULT_REF_RE.finditer(value):
                producer_name = match.group(1)
                result_name = match.group(2)
                if producer_name not in untrusted_tasks:
                    continue
                # FP guard: skip Chains-consumed results (covered by CHAIN-004)
                if result_name in _CHAINS_CONSUMED_RESULTS:
                    continue
                findings.append(_finding(
                    "TKN-RES-004", "MEDIUM",
                    "Untrusted task result consumed without validation",
                    resource, resource.line_offset,
                    f"Pipeline task '{consumer_name}' consumes result '{result_name}' "
                    f"from untrusted task '{producer_name}' via param. An untrusted task "
                    f"can inject arbitrary values into downstream trusted task params.",
                    cwe="CWE-94",
                    remediation="Validate untrusted task results before consuming them, or use trusted sources for the producing task.",
                    extra={"consumer_task": consumer_name, "producer_task": producer_name,
                           "result_name": result_name},
                ))
    return findings
