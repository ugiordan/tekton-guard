"""Volume mount checks (TKN-VOL-001..002)."""

from __future__ import annotations

import re

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, register_check

_RUNTIME_SOCKET_PATHS = {
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/docker.sock",
}

_SENSITIVE_HOST_PATHS = {
    "/etc/shadow",
    "/etc/passwd",
    "/var/run/secrets",
    "/root",
    "/etc/kubernetes",
}


@register_check
def check_vol_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-VOL-001: Host path volume mount."""
    if resource.kind not in ("Task", "StepAction"):
        return []
    findings = []
    for vol in resource.volumes:
        host_path = vol.get("hostPath", {})
        if not host_path:
            continue
        path = host_path.get("path", "")
        if not path:
            continue
        if path in _RUNTIME_SOCKET_PATHS:
            continue  # handled by VOL-002
        findings.append(_finding(
            "TKN-VOL-001", "HIGH", "Host path volume mount",
            resource, resource.line_offset,
            f"Task '{resource.name}' mounts host path '{path}'. "
            f"Host path volumes give direct access to the node filesystem, "
            f"enabling container escape and data exfiltration.",
            cwe="CWE-284",
            remediation="Remove the hostPath volume. Use emptyDir or PVC-backed volumes instead.",
            extra={"volume_name": vol.get("name", ""), "host_path": path},
        ))
    return findings


@register_check
def check_vol_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-VOL-002: Container runtime socket mount."""
    if resource.kind not in ("Task", "StepAction"):
        return []
    findings = []
    for vol in resource.volumes:
        host_path = vol.get("hostPath", {})
        if not host_path:
            continue
        path = host_path.get("path", "")
        if path not in _RUNTIME_SOCKET_PATHS:
            continue
        findings.append(_finding(
            "TKN-VOL-002", "CRITICAL", "Container runtime socket mount",
            resource, resource.line_offset,
            f"Task '{resource.name}' mounts container runtime socket '{path}'. "
            f"This grants full control over the container runtime, enabling "
            f"arbitrary container creation, image manipulation, and node compromise.",
            cwe="CWE-284",
            remediation="Remove the runtime socket mount. Use rootless build tools (buildah, kaniko) that don't require Docker socket access.",
            extra={"volume_name": vol.get("name", ""), "host_path": path},
        ))
    return findings
