"""Security context checks (TKN-SEC-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, collect_all_containers, register_check


@register_check
def check_sec_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SEC-001: Privileged step container."""
    findings = []
    for ci in collect_all_containers(resource):
        sc = ci.container.security_context
        if not sc.get("privileged"):
            continue
        findings.append(_finding(
            "TKN-SEC-001", "HIGH", "Privileged container",
            resource, ci.container.image_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} "
            f"runs with privileged: true. A compromised container with privileged "
            f"access can escape the sandbox and access the host node.",
            cwe="CWE-250",
            remediation="Remove 'privileged: true' from securityContext. If elevated access is needed, use specific capabilities instead.",
            extra={"step_name": ci.container.name, "container_type": ci.container_type},
        ))
    return findings


@register_check
def check_sec_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SEC-002: Root user step."""
    findings = []
    for ci in collect_all_containers(resource):
        sc = ci.container.security_context
        is_root = sc.get("runAsUser") == 0
        allows_escalation = sc.get("allowPrivilegeEscalation") is True
        if not is_root and not allows_escalation:
            continue
        issue = "runAsUser: 0" if is_root else "allowPrivilegeEscalation: true"
        findings.append(_finding(
            "TKN-SEC-002", "MEDIUM", "Root user or privilege escalation",
            resource, ci.container.image_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} "
            f"has {issue}. Running as root increases the blast radius of container escapes.",
            cwe="CWE-250",
            remediation="Set runAsNonRoot: true and allowPrivilegeEscalation: false in securityContext.",
            extra={"step_name": ci.container.name, "container_type": ci.container_type, "issue": issue},
        ))
    return findings
