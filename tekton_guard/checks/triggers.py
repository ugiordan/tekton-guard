"""Trigger security checks (TKN-TRIG-001..007)."""

from __future__ import annotations

import re

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, register_check

_USER_CONTROLLED_BODY_FIELDS = [
    "body.pull_request.title",
    "body.pull_request.body",
    "body.pull_request.head.ref",
    "body.head_commit.message",
    "body.commits",
    "body.comment.body",
    "body.sender",
]

_USER_CONTROLLED_RE = re.compile(
    r"body\.(?:pull_request\.(?:title|body|head\.ref)|head_commit\.message|commits|comment\.body|sender)"
)


@register_check
def check_trig_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-001: CEL expression with user-controlled body field references."""
    if resource.kind != "PipelineRun":
        return []
    cel_expr = resource.annotations.get("pipelinesascode.tekton.dev/on-cel-expression", "")
    if not cel_expr:
        return []
    matches = _USER_CONTROLLED_RE.findall(cel_expr)
    if not matches:
        return []
    return [_finding(
        "TKN-TRIG-001", "CRITICAL",
        "CEL expression references user-controlled webhook fields",
        resource, resource.line_offset,
        f"PipelineRun '{resource.name}' has a CEL expression referencing user-controlled "
        f"webhook body fields: {', '.join(matches[:5])}. An attacker can craft a PR "
        f"title, branch name, or commit message to inject code. This is the Tekton "
        f"equivalent of GitHub Actions pull_request_target injection.",
        cwe="CWE-94",
        remediation="Avoid referencing user-controlled body fields in CEL expressions. Use event type and target branch filtering only.",
        extra={"user_controlled_fields": matches},
    )]


@register_check
def check_trig_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-002: Overly permissive trigger."""
    if resource.kind != "PipelineRun":
        return []
    findings = []
    cel_expr = resource.annotations.get("pipelinesascode.tekton.dev/on-cel-expression", "")
    on_comment = resource.annotations.get("pipelinesascode.tekton.dev/on-comment", "")

    if cel_expr:
        is_push = 'event == "push"' in cel_expr or "event == 'push'" in cel_expr
        has_branch_filter = "target_branch" in cel_expr
        if is_push and not has_branch_filter:
            findings.append(_finding(
                "TKN-TRIG-002", "MEDIUM", "Overly permissive push trigger",
                resource, resource.line_offset,
                f"PipelineRun '{resource.name}' triggers on all push events without "
                f"branch restriction. Any push to any branch will trigger this pipeline.",
                cwe="CWE-284",
                remediation="Add target_branch filter to CEL expression: event == \"push\" && target_branch == \"main\"",
            ))

    if on_comment:
        on_target = resource.annotations.get("pipelinesascode.tekton.dev/on-target-branch", "")
        if not on_target:
            findings.append(_finding(
                "TKN-TRIG-002", "LOW", "Comment trigger without branch restriction",
                resource, resource.line_offset,
                f"PipelineRun '{resource.name}' has a comment trigger (on-comment: '{on_comment}') "
                f"without on-target-branch restriction.",
                cwe="CWE-284",
                remediation="Add pipelinesascode.tekton.dev/on-target-branch annotation to restrict which branches accept comment triggers.",
            ))
    return findings


@register_check
def check_trig_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-003: Conditional skip of security tasks."""
    if resource.kind != "Pipeline":
        return []
    security_patterns = ["scan", "sign", "verify", "attest", "cosign",
                         "enterprise-contract", "sast", "clair", "clamav"]
    findings = []
    raw_tasks = resource.raw.get("spec", {}).get("tasks", [])
    raw_finally = resource.raw.get("spec", {}).get("finally", [])
    for task_data in (raw_tasks or []) + (raw_finally or []):
        task_name = str(task_data.get("name", ""))
        when_list = task_data.get("when", [])
        if not when_list:
            continue
        is_security_task = any(pat in task_name.lower() for pat in security_patterns)
        if not is_security_task:
            task_ref = task_data.get("taskRef", {})
            ref_name = str(task_ref.get("name", ""))
            is_security_task = any(pat in ref_name.lower() for pat in security_patterns)
        if not is_security_task:
            continue
        for when in when_list:
            input_val = str(when.get("input", ""))
            if "$(params." in input_val or "$(tasks." in input_val:
                findings.append(_finding(
                    "TKN-TRIG-003", "MEDIUM",
                    "Conditional skip of security task",
                    resource, resource.line_offset,
                    f"Security task '{task_name}' has a 'when' expression that references "
                    f"'{input_val}'. If this parameter is user-controlled, an attacker "
                    f"could craft input to skip security checks.",
                    cwe="CWE-693",
                    remediation="Remove conditional when expressions from security-critical tasks, or validate that the when input is not user-controlled.",
                    extra={"task_name": task_name, "when_input": input_val},
                ))
    return findings


def _find_interpolations(data, pattern):
    """Recursively search dict/list/str for regex pattern matches."""
    matches = []
    if isinstance(data, str):
        matches.extend(pattern.findall(data))
    elif isinstance(data, dict):
        for v in data.values():
            matches.extend(_find_interpolations(v, pattern))
    elif isinstance(data, list):
        for item in data:
            matches.extend(_find_interpolations(item, pattern))
    return matches


@register_check
def check_trig_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-004: TriggerTemplate param injection."""
    if resource.kind != "TriggerTemplate":
        return []
    findings = []
    tt_param_re = re.compile(r"\$\(tt\.params\.[^)]+\)")
    templates = resource.raw.get("spec", {}).get("resourcetemplates", [])
    for tmpl in templates or []:
        if not isinstance(tmpl, dict):
            continue
        matches = _find_interpolations(tmpl, tt_param_re)
        if matches:
            findings.append(_finding(
                "TKN-TRIG-004", "HIGH", "TriggerTemplate param injection",
                resource, resource.line_offset,
                f"TriggerTemplate '{resource.name}' interpolates {len(matches)} "
                f"trigger param(s) in resourcetemplates: {', '.join(matches[:5])}. "
                f"These values flow from webhook body via TriggerBindings and may "
                f"reach task script blocks, enabling code injection.",
                cwe="CWE-94",
                remediation="Validate trigger params before passing to PipelineRun. Avoid interpolating webhook body fields directly.",
                extra={"interpolations": matches[:10]},
            ))
    return findings


@register_check
def check_trig_005(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-005: EventListener without interceptor."""
    if resource.kind != "EventListener":
        return []
    findings = []
    triggers = resource.raw.get("spec", {}).get("triggers", [])
    for i, trigger in enumerate(triggers or []):
        if not isinstance(trigger, dict):
            continue
        interceptors = trigger.get("interceptors", [])
        if not interceptors:
            trigger_name = trigger.get("name", f"trigger-{i}")
            findings.append(_finding(
                "TKN-TRIG-005", "MEDIUM", "EventListener without interceptor",
                resource, resource.line_offset,
                f"EventListener '{resource.name}' trigger '{trigger_name}' has no "
                f"interceptors configured. Raw webhook payloads reach TriggerBindings "
                f"without signature verification or filtering.",
                cwe="CWE-284",
                remediation="Add a webhook interceptor (GitHub, GitLab, CEL, or Bitbucket) to validate payload authenticity.",
                extra={"trigger_name": trigger_name},
            ))
    return findings


@register_check
def check_trig_006(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-006: PaC Repository allows all branches."""
    if resource.kind != "Repository":
        return []
    spec = resource.raw.get("spec", {})
    # PaC Repository can restrict via incoming webhook settings
    incoming = spec.get("incoming", [])

    # If no incoming rules defined, any webhook triggers the pipeline
    if not incoming:
        return [_finding(
            "TKN-TRIG-006", "MEDIUM", "PaC Repository allows all branches",
            resource, resource.line_offset,
            f"PaC Repository '{resource.name}' has no incoming webhook restrictions. "
            f"Any branch push or PR can trigger pipeline execution. "
            f"Note: PipelineRun-level on-cel-expression filters may provide "
            f"additional branch restrictions not visible at the Repository CR level.",
            cwe="CWE-284",
            remediation="Add incoming rules to restrict which branches and events trigger pipelines.",
        )]
    return []


@register_check
def check_trig_007(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRIG-007: EventListener with default/missing SA."""
    if resource.kind != "EventListener":
        return []
    sa = resource.raw.get("spec", {}).get("serviceAccountName", "")
    if sa and sa != "default":
        return []
    issue = "default" if sa == "default" else "missing (inherits namespace default)"
    return [_finding(
        "TKN-TRIG-007", "MEDIUM", "EventListener with default/missing SA",
        resource, resource.line_offset,
        f"EventListener '{resource.name}' has {issue} ServiceAccount. "
        f"The EventListener SA can create PipelineRuns and should use "
        f"a dedicated SA with minimal permissions.",
        cwe="CWE-269",
        remediation="Set serviceAccountName to a dedicated SA with only PipelineRun create permission.",
    )]
