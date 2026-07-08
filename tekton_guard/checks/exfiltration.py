"""Exfiltration checks (TKN-EXFIL-001..002)."""

from __future__ import annotations

import re

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, collect_all_containers, register_check

_NETWORK_TOOLS_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|telnet|openssl\s+s_client|dig|nslookup)\b"
)
_DEV_TCP_RE = re.compile(r"/dev/tcp/")


@register_check
def check_exfil_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-EXFIL-001: Task with secret access and network-capable scripts."""
    if resource.kind not in ("Task", "StepAction", "PipelineRun", "TaskRun", "Pipeline"):
        return []

    has_secret = False
    # Check workspace-level secrets
    for ws in resource.workspaces:
        if ws.secret_name:
            has_secret = True
            break
    # Check env-level secretKeyRef across ALL containers (steps, sidecars, embedded)
    if not has_secret:
        for ci in collect_all_containers(resource):
            for env_entry in ci.container.env:
                if isinstance(env_entry, dict):
                    value_from = env_entry.get("valueFrom", {})
                    if isinstance(value_from, dict) and "secretKeyRef" in value_from:
                        has_secret = True
                        break
            if has_secret:
                break
    # Check volume-mounted secrets in raw spec
    if not has_secret:
        raw_spec = resource.raw.get("spec", {})
        for vol in raw_spec.get("volumes", []):
            if isinstance(vol, dict) and isinstance(vol.get("secret"), dict):
                if vol["secret"].get("secretName"):
                    has_secret = True
                    break

    # Check inline taskSpec volumes for Pipeline/PipelineRun
    if not has_secret:
        if resource.kind in ("Pipeline", "PipelineRun"):
            # For PipelineRun, tasks may be under spec.pipelineSpec.tasks
            spec = resource.raw.get("spec", {})
            pipeline_spec = spec.get("pipelineSpec", spec)
            for task_list_key in ("tasks", "finally"):
                for task_data in pipeline_spec.get(task_list_key, []) or []:
                    for vol in task_data.get("taskSpec", {}).get("volumes", []) or []:
                        if isinstance(vol, dict) and vol.get("secret"):
                            has_secret = True
                            break
                    if has_secret:
                        break
                if has_secret:
                    break

    if not has_secret:
        return []

    findings = []
    for ci in collect_all_containers(resource):
        if not ci.container.script:
            continue
        net_matches = _NETWORK_TOOLS_RE.findall(ci.container.script)
        tcp_matches = _DEV_TCP_RE.findall(ci.container.script)
        all_matches = net_matches + tcp_matches
        if not all_matches:
            continue
        findings.append(_finding(
            "TKN-EXFIL-001", "MEDIUM",
            "Task with secret access and network-capable scripts",
            resource, ci.container.script_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} has access to secrets "
            f"and uses network tools: {', '.join(list(set(all_matches))[:5])}. "
            f"A compromised or malicious task could exfiltrate secrets to external endpoints.",
            cwe="CWE-200",
            remediation="Minimize secret exposure. Use dedicated tasks for secret access with no network tools. Apply NetworkPolicy to restrict egress.",
            extra={"step_name": ci.container.name, "network_tools": list(set(all_matches))},
        ))
    return findings


@register_check
def check_exfil_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-EXFIL-002: Network tool in script."""
    findings = []
    for ci in collect_all_containers(resource):
        if not ci.container.script:
            continue
        net_matches = _NETWORK_TOOLS_RE.findall(ci.container.script)
        tcp_matches = _DEV_TCP_RE.findall(ci.container.script)
        all_matches = net_matches + tcp_matches
        if not all_matches:
            continue
        findings.append(_finding(
            "TKN-EXFIL-002", "LOW",
            "Network tool in script",
            resource, ci.container.script_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} "
            f"uses network tools: {', '.join(list(set(all_matches))[:5])}. "
            f"These tools could be used for data exfiltration.",
            cwe="CWE-200",
            remediation="Review whether network access is necessary. Consider using NetworkPolicy to restrict egress.",
            extra={"step_name": ci.container.name, "network_tools": list(set(all_matches))},
        ))
    return findings
