"""ServiceAccount checks (TKN-SA-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, register_check


@register_check
def check_sa_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SA-001: Default ServiceAccount."""
    if resource.kind not in ("PipelineRun", "TaskRun"):
        return []
    if resource.service_account != "default":
        return []
    return [_finding(
        "TKN-SA-001", "HIGH", "Default ServiceAccount",
        resource, resource.service_account_line,
        f"{resource.kind} '{resource.name}' uses the 'default' ServiceAccount. "
        f"The default SA may have broad permissions that violate least-privilege. "
        f"Build workloads should use a dedicated SA with minimal RBAC.",
        cwe="CWE-269",
        remediation="Create and use a dedicated ServiceAccount with only the permissions required for this pipeline.",
    )]


@register_check
def check_sa_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SA-002: Missing ServiceAccount."""
    if resource.kind not in ("PipelineRun", "TaskRun"):
        return []
    if resource.service_account:
        return []
    return [_finding(
        "TKN-SA-002", "MEDIUM", "Missing ServiceAccount",
        resource, resource.line_offset,
        f"{resource.kind} '{resource.name}' does not specify a serviceAccountName. "
        f"It will inherit the namespace default ServiceAccount, which may have "
        f"unintended permissions.",
        cwe="CWE-269",
        remediation="Explicitly set serviceAccountName in taskRunTemplate (PipelineRun) or spec (TaskRun).",
    )]
