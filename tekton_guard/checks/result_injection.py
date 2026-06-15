"""Result injection checks (TKN-RES-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import (
    PARAM_INTERP_RE, _finding, collect_all_containers, register_check,
)


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
