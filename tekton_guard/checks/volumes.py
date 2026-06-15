"""Volume mount checks (TKN-VOL-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource, _to_plain
from tekton_guard.checks._common import _finding, register_check

_RUNTIME_SOCKET_PATHS = {
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/docker.sock",
}


def _collect_volumes(resource: TektonResource) -> list[tuple[str, list[dict]]]:
    """Return (context_name, volumes) pairs from resource and inline taskSpecs."""
    pairs: list[tuple[str, list[dict]]] = []
    if resource.kind in ("Task", "StepAction"):
        pairs.append((f"Task '{resource.name}'", resource.volumes))
    if resource.kind == "Pipeline":
        raw_tasks = resource.raw.get("spec", {}).get("tasks", [])
        raw_finally = resource.raw.get("spec", {}).get("finally", [])
        for task_data in (raw_tasks or []) + (raw_finally or []):
            task_name = str(task_data.get("name", ""))
            task_spec = task_data.get("taskSpec", {})
            if task_spec:
                vols = task_spec.get("volumes", [])
                if vols:
                    pairs.append((f"pipeline task '{task_name}'", _to_plain(vols)))
    return pairs


@register_check
def check_vol_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-VOL-001: Host path volume mount."""
    findings = []
    for context_name, volumes in _collect_volumes(resource):
        for vol in volumes:
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
                f"{context_name} mounts host path '{path}'. "
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
    findings = []
    for context_name, volumes in _collect_volumes(resource):
        for vol in volumes:
            host_path = vol.get("hostPath", {})
            if not host_path:
                continue
            path = host_path.get("path", "")
            if path not in _RUNTIME_SOCKET_PATHS:
                continue
            findings.append(_finding(
                "TKN-VOL-002", "CRITICAL", "Container runtime socket mount",
                resource, resource.line_offset,
                f"{context_name} mounts container runtime socket '{path}'. "
                f"This grants full control over the container runtime, enabling "
                f"arbitrary container creation, image manipulation, and node compromise.",
                cwe="CWE-284",
                remediation="Remove the runtime socket mount. Use rootless build tools (buildah, kaniko) that don't require Docker socket access.",
                extra={"volume_name": vol.get("name", ""), "host_path": path},
            ))
    return findings
