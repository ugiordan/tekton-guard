"""Workspace checks (TKN-WS-001..003)."""

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


@register_check
def check_ws_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-WS-003: Large workspace fan-out."""
    if resource.kind != "Pipeline":
        return []

    workspace_users: dict[str, list[str]] = {}
    for pt in resource.pipeline_tasks + resource.finally_tasks:
        for ws in pt.workspaces:
            ws_name = ws.workspace or ws.name
            workspace_users.setdefault(ws_name, []).append(pt.name)

    findings: list[dict] = []
    for ws_name, task_names in workspace_users.items():
        # FP guard: threshold of 4 to avoid noisy findings on normal pipelines
        if len(task_names) < 4:
            continue
        findings.append(_finding(
            "TKN-WS-003", "LOW",
            "Large workspace fan-out",
            resource, resource.line_offset,
            f"Workspace '{ws_name}' is referenced by {len(task_names)} tasks: "
            f"{', '.join(task_names[:6])}{'...' if len(task_names) > 6 else ''}. "
            f"Wide workspace sharing increases the blast radius of a compromised task "
            f"and creates implicit data dependencies.",
            cwe="CWE-732",
            remediation="Reduce workspace sharing by splitting into task-specific workspaces or using Tekton Trusted Artifacts for verified data passing.",
            extra={"workspace_name": ws_name, "task_count": len(task_names),
                   "tasks": task_names},
        ))
    return findings
