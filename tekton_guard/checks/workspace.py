"""Workspace checks (TKN-WS-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import PipelineTaskDef, TektonResource
from tekton_guard.checks._common import _finding, register_check


@register_check
def check_ws_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-WS-001: Secret workspace without readOnly."""
    if resource.kind not in ("PipelineRun", "TaskRun"):
        return []
    findings = []
    for ws in resource.workspaces:
        if not ws.secret_name:
            continue
        if ws.is_read_only is True:
            continue
        if ws.name in config.known_safe_secret_workspaces:
            continue
        findings.append(_finding(
            "TKN-WS-001", "LOW", "Secret workspace without readOnly",
            resource, ws.line,
            f"Workspace '{ws.name}' is backed by secret '{ws.secret_name}' "
            f"but is not mounted as readOnly. Tasks could potentially modify "
            f"the secret content.",
            cwe="CWE-732",
            remediation="Add 'readOnly: true' to the workspace binding for secret-backed workspaces.",
            extra={"workspace_name": ws.name, "secret_name": ws.secret_name},
        ))
    return findings


@register_check
def check_ws_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-WS-002: Shared workspace between untrusted tasks."""
    if resource.kind != "Pipeline":
        return []
    workspace_users: dict[str, list[PipelineTaskDef]] = {}
    for pt in resource.pipeline_tasks + resource.finally_tasks:
        for ws in pt.workspaces:
            ws_name = ws.workspace or ws.name
            workspace_users.setdefault(ws_name, []).append(pt)

    findings = []
    for ws_name, tasks in workspace_users.items():
        if len(tasks) < 2:
            continue
        untrusted = []
        for t in tasks:
            if t.task_ref and t.task_ref.resolver:
                ref = t.task_ref.resolver
                if ref.resolver_type == "git" and not config.is_trusted_git_source(ref.url):
                    untrusted.append(t.name)
                elif ref.resolver_type == "hub":
                    untrusted.append(t.name)
        if not untrusted:
            continue
        findings.append(_finding(
            "TKN-WS-002", "MEDIUM", "Shared workspace with untrusted tasks",
            resource, resource.line_offset,
            f"Workspace '{ws_name}' is shared between {len(tasks)} tasks, "
            f"including untrusted tasks: {', '.join(untrusted)}. "
            f"Untrusted tasks could read secrets or tamper with data from other tasks.",
            cwe="CWE-732",
            remediation="Isolate untrusted tasks with separate workspaces, or use Tekton Trusted Artifacts for verified data passing.",
            extra={"workspace_name": ws_name, "untrusted_tasks": untrusted, "total_tasks": len(tasks)},
        ))
    return findings
