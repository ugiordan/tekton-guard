"""Security checks for Tekton pipeline definitions."""

from __future__ import annotations

import re
from typing import Any

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import (
    DIGEST_RE,
    SHA_RE,
    PipelineTaskDef,
    TektonResource,
)

PARAM_INTERP_RE = re.compile(r"\$\((?:params|tasks)\.[^)]+\)")
PAC_TEMPLATE_RE = re.compile(r"^\{\{.*\}\}$")


def _is_pac_template(value: str) -> bool:
    """Check if a value is a PipelinesAsCode template variable like {{revision}}."""
    stripped = value.strip().strip("'\"")
    return bool(PAC_TEMPLATE_RE.match(stripped))


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    resource: TektonResource,
    line: int,
    message: str,
    *,
    cwe: str = "",
    remediation: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file": resource.file_path,
        "line_start": line,
        "line_end": line,
        "message": message,
        "resource_kind": resource.kind,
        "resource_name": resource.name,
        "cwe": cwe,
        "remediation": remediation,
    }
    if extra:
        result.update(extra)
    return result


# ---------------------------------------------------------------------------
# Category 1: Pinning (TKN-PIN)
# ---------------------------------------------------------------------------


def check_pin_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-001: Mutable pipeline revision."""
    if resource.kind not in ("PipelineRun",):
        return []
    ref = resource.pipeline_ref
    if not ref or ref.resolver_type != "git":
        return []
    rev = ref.revision
    if not rev or SHA_RE.match(rev):
        return []
    if _is_pac_template(rev):
        return []
    return [_finding(
        "TKN-PIN-001", "HIGH", "Mutable pipeline revision", resource, ref.line,
        f"PipelineRun '{resource.name}' references pipeline via git resolver with "
        f"mutable revision '{rev}' instead of a pinned commit SHA. A push to "
        f"'{rev}' in the referenced repo can alter the build pipeline without "
        f"any commit to this repository, breaking SLSA Build L3.",
        cwe="CWE-829",
        remediation="Pin revision to a 40-character commit SHA. Use Renovate or Mintmaker to keep SHA-pinned refs up to date.",
        extra={"resolver_type": "git", "resolver_url": ref.url, "current_value": rev},
    )]


def check_pin_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-002: Mutable task reference (git resolver)."""
    findings = []
    tasks = resource.pipeline_tasks + resource.finally_tasks
    for pt in tasks:
        if not pt.task_ref or not pt.task_ref.resolver:
            continue
        ref = pt.task_ref.resolver
        if ref.resolver_type != "git":
            continue
        rev = ref.revision
        if not rev or SHA_RE.match(rev):
            continue
        findings.append(_finding(
            "TKN-PIN-002", "HIGH", "Mutable task reference (git resolver)",
            resource, ref.line,
            f"Pipeline task '{pt.name}' references task via git resolver with "
            f"mutable revision '{rev}'. An attacker with push access to the "
            f"source repo can inject malicious task code.",
            cwe="CWE-829",
            remediation="Pin the task's git revision to a 40-character commit SHA.",
            extra={"resolver_type": "git", "resolver_url": ref.url, "current_value": rev, "task_name": pt.name},
        ))
    return findings


def check_pin_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-003: Unpinned task bundle."""
    findings = []
    tasks = resource.pipeline_tasks + resource.finally_tasks
    for pt in tasks:
        if not pt.task_ref or not pt.task_ref.resolver:
            continue
        ref = pt.task_ref.resolver
        if ref.resolver_type != "bundles":
            continue
        bundle = ref.bundle
        if not bundle or DIGEST_RE.search(bundle):
            continue
        findings.append(_finding(
            "TKN-PIN-003", "HIGH", "Unpinned task bundle",
            resource, ref.line,
            f"Pipeline task '{pt.name}' references a bundle without a digest pin: "
            f"'{bundle}'. Bundle tags are mutable and can be overwritten with "
            f"malicious content.",
            cwe="CWE-829",
            remediation="Pin the bundle reference to include @sha256:<digest>.",
            extra={"resolver_type": "bundles", "current_value": bundle, "task_name": pt.name},
        ))
    return findings


def check_pin_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-004: Mutable step image."""
    findings = []

    def _check_image(step, context: str) -> None:
        img = step.image
        if not img or DIGEST_RE.search(img):
            return
        if "{{" in img or "$(" in img:
            return
        findings.append(_finding(
            "TKN-PIN-004", "MEDIUM", "Mutable step image",
            resource, step.image_line,
            f"Step '{step.name}' in {context} uses image '{img}' without a digest pin. "
            f"Image tags are mutable and can be overwritten to inject malicious code into the build.",
            cwe="CWE-829",
            remediation="Pin the image to a digest: image: <registry>/<image>@sha256:<digest>",
            extra={"current_value": img, "step_name": step.name},
        ))

    if resource.kind in ("Task", "StepAction"):
        for step in resource.steps:
            _check_image(step, f"Task '{resource.name}'")

    if resource.kind == "Pipeline":
        for ctx, step in _collect_inline_steps(resource):
            _check_image(step, ctx)

    return findings


def check_pin_005(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-005: Mutable StepAction reference."""
    findings = []

    def _check_steps(steps: list, context_name: str) -> None:
        for step in steps:
            if not step.ref or step.ref.resolver_type != "git":
                continue
            rev = step.ref.revision
            if not rev or SHA_RE.match(rev):
                continue
            findings.append(_finding(
                "TKN-PIN-005", "HIGH", "Mutable StepAction reference",
                resource, step.ref.line,
                f"Step '{step.name}' in {context_name} references a StepAction via "
                f"git resolver with mutable revision '{rev}'. "
                f"The StepAction code can be changed without any commit to this repository.",
                cwe="CWE-829",
                remediation="Pin the StepAction's git revision to a 40-character commit SHA.",
                extra={"resolver_type": "git", "resolver_url": step.ref.url,
                       "current_value": rev, "step_name": step.name},
            ))

    # Steps in Task/StepAction definitions
    if resource.kind in ("Task", "StepAction"):
        _check_steps(resource.steps, f"Task '{resource.name}'")

    # Inline taskSpec steps in Pipeline tasks
    if resource.kind == "Pipeline":
        for pt in resource.pipeline_tasks + resource.finally_tasks:
            _check_steps(pt.steps, f"pipeline task '{pt.name}'")

    return findings


def _collect_inline_steps(resource: TektonResource) -> list[tuple[str, "StepDef"]]:
    """Collect steps from inline taskSpec blocks in a Pipeline, with context name."""
    pairs = []
    if resource.kind == "Pipeline":
        for pt in resource.pipeline_tasks + resource.finally_tasks:
            for step in pt.steps:
                pairs.append((f"pipeline task '{pt.name}'", step))
    return pairs


# ---------------------------------------------------------------------------
# Category 2: Trust (TKN-TRUST)
# ---------------------------------------------------------------------------


def check_trust_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-001: Pipeline from untrusted source."""
    if resource.kind not in ("PipelineRun",):
        return []
    ref = resource.pipeline_ref
    if not ref or ref.resolver_type != "git":
        return []
    url = ref.url
    if not url or config.is_trusted_git_source(url):
        return []
    if _is_pac_template(url):
        return []
    return [_finding(
        "TKN-TRUST-001", "HIGH", "Pipeline from untrusted source",
        resource, ref.line,
        f"PipelineRun '{resource.name}' references a pipeline from '{url}', "
        f"which is not in the trusted sources list. Untrusted pipeline sources "
        f"can execute arbitrary code in the build environment.",
        cwe="CWE-829",
        remediation="Use a pipeline from a trusted source or add this source to the trusted_git_sources configuration.",
        extra={"resolver_type": "git", "resolver_url": url},
    )]


def check_trust_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-002: Task from untrusted source."""
    findings = []
    tasks = resource.pipeline_tasks + resource.finally_tasks
    for pt in tasks:
        if not pt.task_ref or not pt.task_ref.resolver:
            continue
        ref = pt.task_ref.resolver
        if ref.resolver_type not in ("git", "hub"):
            continue
        url = ref.url
        if ref.resolver_type == "git" and (not url or config.is_trusted_git_source(url)):
            continue
        if ref.resolver_type == "hub":
            url = ref.params.get("catalog", "tekton") or "tekton"
        findings.append(_finding(
            "TKN-TRUST-002", "HIGH", "Task from untrusted source",
            resource, ref.line,
            f"Pipeline task '{pt.name}' references a task from untrusted source "
            f"(resolver: {ref.resolver_type}, source: '{url}'). "
            f"Untrusted tasks can exfiltrate secrets or inject malicious code.",
            cwe="CWE-829",
            remediation="Use tasks from trusted sources or add this source to the trusted_git_sources configuration.",
            extra={"resolver_type": ref.resolver_type, "resolver_url": url, "task_name": pt.name},
        ))
    return findings


def check_trust_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-003: Unverified cluster task reference."""
    if resource.kind != "Pipeline":
        return []
    findings = []
    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if not pt.task_ref:
            continue
        if pt.task_ref.resolver is not None:
            continue
        if not pt.task_ref.name:
            continue
        findings.append(_finding(
            "TKN-TRUST-003", "MEDIUM", "Unverified cluster task reference",
            resource, pt.task_ref.line,
            f"Pipeline task '{pt.name}' references cluster task '{pt.task_ref.name}' "
            f"by name without a resolver. Cluster tasks are mutable: anyone with "
            f"write access to the namespace can replace them.",
            cwe="CWE-829",
            remediation="Use a bundle or git resolver with a pinned reference instead of cluster-local task names.",
            extra={"task_name": pt.name, "cluster_task": pt.task_ref.name},
        ))
    return findings


# ---------------------------------------------------------------------------
# Category 3: ServiceAccount (TKN-SA)
# ---------------------------------------------------------------------------


def check_sa_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SA-001: Default ServiceAccount."""
    if resource.kind not in ("PipelineRun", "TaskRun"):
        return []
    sa = resource.service_account
    if sa != "default":
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


# ---------------------------------------------------------------------------
# Category 4: Workspace (TKN-WS)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Category 5: Result Injection (TKN-RES)
# ---------------------------------------------------------------------------


def check_res_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-RES-001: Task result interpolated in script block."""
    findings = []

    def _check_script(step, context: str) -> None:
        if not step.script:
            return
        matches = PARAM_INTERP_RE.findall(step.script)
        if not matches:
            return
        findings.append(_finding(
            "TKN-RES-001", "MEDIUM",
            "Parameter/result interpolation in script block",
            resource, step.script_line,
            f"Step '{step.name}' in {context} interpolates {len(matches)} variable(s) directly "
            f"in a script block: {', '.join(matches[:5])}. "
            f"If any interpolated value comes from untrusted input, this enables "
            f"arbitrary code injection (the Tekton equivalent of GitHub Actions "
            f"${{{{ }}}} injection).",
            cwe="CWE-94",
            remediation="Pass values as environment variables instead of interpolating them in scripts. Use 'env' with 'value: $(params.name)' and reference $ENV_VAR in the script.",
            extra={"step_name": step.name, "interpolations": matches[:10]},
        ))

    if resource.kind in ("Task", "StepAction"):
        for step in resource.steps:
            _check_script(step, f"Task '{resource.name}'")

    if resource.kind == "Pipeline":
        for ctx, step in _collect_inline_steps(resource):
            _check_script(step, ctx)

    return findings


def check_res_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-RES-002: Parameter interpolation in command args."""
    findings = []

    def _check_args(step, context: str) -> None:
        all_args = step.args + step.command
        interps = []
        for arg in all_args:
            interps.extend(PARAM_INTERP_RE.findall(str(arg)))
        if not interps:
            return
        findings.append(_finding(
            "TKN-RES-002", "LOW",
            "Parameter interpolation in command args",
            resource, step.args_line,
            f"Step '{step.name}' in {context} interpolates variables in command/args: "
            f"{', '.join(interps[:5])}. While safer than script injection, "
            f"this can still enable command injection if values are untrusted.",
            cwe="CWE-78",
            remediation="Validate parameter values before use, or pass them as environment variables.",
            extra={"step_name": step.name, "interpolations": interps[:10]},
        ))

    if resource.kind in ("Task", "StepAction"):
        for step in resource.steps:
            _check_args(step, f"Task '{resource.name}'")

    if resource.kind == "Pipeline":
        for ctx, step in _collect_inline_steps(resource):
            _check_args(step, ctx)

    return findings


# ---------------------------------------------------------------------------
# Category 6: Chains Readiness (TKN-CHAIN)
# ---------------------------------------------------------------------------


def check_chain_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CHAIN-001: Build pipeline missing Chains type hints."""
    if resource.kind != "PipelineRun":
        return []
    pipeline_type = resource.labels.get("pipelines.appstudio.openshift.io/type", "")
    if pipeline_type != "build":
        return []
    # Konflux/AppStudio configures Chains at the cluster level. PipelineRuns
    # with appstudio.openshift.io/application label are Konflux-managed.
    is_konflux = (
        "appstudio.openshift.io/application" in resource.labels
        or "appstudio.openshift.io/component" in resource.labels
    )
    if is_konflux:
        return []
    has_results_annotation = any(
        "chains.tekton.dev" in k for k in resource.annotations
    )
    if has_results_annotation:
        return []
    return [_finding(
        "TKN-CHAIN-001", "LOW", "Build pipeline without Chains annotations",
        resource, resource.line_offset,
        f"PipelineRun '{resource.name}' is labeled as a build pipeline but has "
        f"no chains.tekton.dev or appstudio.openshift.io annotations. Tekton Chains "
        f"may not generate provenance attestations for this build.",
        cwe="CWE-345",
        remediation="Ensure the referenced pipeline produces IMAGE_URL and IMAGE_DIGEST results for Tekton Chains to sign.",
    )]


def check_chain_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CHAIN-002: Missing provenance annotations."""
    if resource.kind != "PipelineRun":
        return []
    pipeline_type = resource.labels.get("pipelines.appstudio.openshift.io/type", "")
    if pipeline_type != "build":
        return []
    if "build.appstudio.redhat.com/commit_sha" in resource.annotations:
        return []
    return [_finding(
        "TKN-CHAIN-002", "INFO", "Missing provenance annotations",
        resource, resource.line_offset,
        f"PipelineRun '{resource.name}' is a build pipeline but lacks "
        f"'build.appstudio.redhat.com/commit_sha' annotation. This annotation "
        f"helps Tekton Chains correlate builds to source commits for SLSA provenance.",
        cwe="CWE-345",
        remediation="Add build.appstudio.redhat.com/commit_sha annotation with the source commit SHA.",
    )]


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_pin_001,
    check_pin_002,
    check_pin_003,
    check_pin_004,
    check_pin_005,
    check_trust_001,
    check_trust_002,
    check_trust_003,
    check_sa_001,
    check_sa_002,
    check_ws_001,
    check_ws_002,
    check_res_001,
    check_res_002,
    check_chain_001,
    check_chain_002,
]

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def run_checks(
    resources: list[TektonResource],
    config: ScannerConfig,
) -> list[dict[str, Any]]:
    """Run all enabled checks against all resources."""
    min_sev = SEVERITY_ORDER.get(config.min_severity.upper(), 0)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    for resource in resources:
        for check_fn in ALL_CHECKS:
            check_id = check_fn.__doc__.split(":")[0].strip() if check_fn.__doc__ else ""
            if check_id and not config.should_run_check(check_id):
                continue
            for f in check_fn(resource, config):
                if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                    continue
                dedup_key = (f["rule_id"], f["file"], f.get("line_start", 0))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(f)

    return findings
