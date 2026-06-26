"""Pipeline logic checks (TKN-LOGIC-001..004)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, register_check


@register_check
def check_logic_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-LOGIC-001: Security task not in finally block."""
    if resource.kind != "Pipeline":
        return []
    findings = []
    patterns = config.security_task_patterns

    for pt in resource.pipeline_tasks:
        name_lower = pt.name.lower()
        is_security = any(pat in name_lower for pat in patterns)
        if not is_security and pt.task_ref and pt.task_ref.name:
            is_security = any(pat in pt.task_ref.name.lower() for pat in patterns)
        if is_security:
            findings.append(_finding(
                "TKN-LOGIC-001", "MEDIUM",
                "Security task not in finally block",
                resource, pt.line,
                f"Pipeline task '{pt.name}' appears to be a security task but is in "
                f"spec.tasks instead of spec.finally. If any preceding task fails, "
                f"this security task will be skipped.",
                cwe="CWE-693",
                remediation="Move security tasks (scan, sign, verify, attest) to the finally block.",
                extra={"task_name": pt.name},
            ))
    return findings


@register_check
def check_logic_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-LOGIC-002: Overridable security-relevant param default."""
    if resource.kind not in ("Task", "StepAction"):
        return []
    findings = []
    security_keywords = ["privileged", "tls-verify", "skip", "insecure", "allow-all",
                         "no-verify", "disable-auth", "unsafe"]

    for param in resource.raw.get("spec", {}).get("params", []):
        if not isinstance(param, dict):
            continue
        default = str(param.get("default", ""))
        name = str(param.get("name", ""))
        if not default:
            continue
        combined = f"{name} {default}".lower()
        if any(kw in combined for kw in security_keywords):
            findings.append(_finding(
                "TKN-LOGIC-002", "LOW",
                "Overridable security-relevant param default",
                resource, resource.line_offset,
                f"Task param '{name}' has default '{default}' containing security-relevant "
                f"keywords. A PipelineRun caller can override this to a less secure value.",
                cwe="CWE-1188",
                remediation="Use hardcoded values instead of params for security-critical flags.",
                extra={"param_name": name, "default_value": default},
            ))
    return findings


@register_check
def check_logic_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-LOGIC-003: TOCTOU via parallel workspace access."""
    if resource.kind != "Pipeline":
        return []
    findings = []

    # Build workspace -> tasks mapping
    workspace_users: dict[str, list[str]] = {}
    task_run_after: dict[str, set[str]] = {}

    for pt in resource.pipeline_tasks:
        task_run_after[pt.name] = set(pt.run_after)
        for ws in pt.workspaces:
            ws_name = ws.workspace
            if not ws_name:
                continue  # task-local workspace binding without pipeline workspace ref
            workspace_users.setdefault(ws_name, []).append(pt.name)

    # Build transitive dependency closure
    def _transitive_deps(task_name: str, visited: set | None = None) -> set:
        if visited is None:
            visited = set()
        if task_name in visited:
            return visited
        visited.add(task_name)
        for dep in task_run_after.get(task_name, set()):
            _transitive_deps(dep, visited)
        return visited

    # For each shared workspace, check if any untrusted task can run in parallel
    for ws_name, task_names in workspace_users.items():
        if len(task_names) < 2:
            continue

        for i, t1 in enumerate(task_names):
            for t2 in task_names[i+1:]:
                # Check if t1 and t2 can run in parallel (neither depends on the other transitively)
                t1_all_deps = _transitive_deps(t1)
                t2_all_deps = _transitive_deps(t2)
                if t2 in t1_all_deps or t1 in t2_all_deps:
                    continue  # transitively ordered

                # Check if either is untrusted
                t1_pt = next((pt for pt in resource.pipeline_tasks if pt.name == t1), None)
                t2_pt = next((pt for pt in resource.pipeline_tasks if pt.name == t2), None)

                untrusted_name = None
                for pt in [t1_pt, t2_pt]:
                    if pt and pt.task_ref and pt.task_ref.resolver:
                        ref = pt.task_ref.resolver
                        if ref.resolver_type == "git" and not config.is_trusted_git_source(ref.url):
                            untrusted_name = pt.name
                            break
                        if ref.resolver_type == "hub":
                            untrusted_name = pt.name
                            break

                if untrusted_name:
                    findings.append(_finding(
                        "TKN-LOGIC-003", "MEDIUM",
                        "TOCTOU via parallel workspace access",
                        resource, resource.line_offset,
                        f"Tasks '{t1}' and '{t2}' share workspace '{ws_name}' and can "
                        f"run in parallel (no runAfter dependency). Untrusted task "
                        f"'{untrusted_name}' could modify data while the other reads it.",
                        cwe="CWE-367",
                        remediation="Add runAfter dependency or use separate workspaces.",
                        extra={"workspace": ws_name, "task1": t1, "task2": t2,
                               "untrusted": untrusted_name},
                    ))
    return findings


@register_check
def check_logic_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-LOGIC-004: Pipeline without finally block."""
    if resource.kind != "Pipeline":
        return []
    if resource.finally_tasks:
        return []
    if not resource.pipeline_tasks:
        return []  # empty pipeline, don't flag
    return [_finding(
        "TKN-LOGIC-004", "LOW", "Pipeline without finally block",
        resource, resource.line_offset,
        f"Pipeline '{resource.name}' has no finally block. There is no cleanup, "
        f"reporting, or error handling on pipeline failure.",
        cwe="CWE-390",
        remediation="Add a finally block with at minimum a status-reporting task.",
    )]
