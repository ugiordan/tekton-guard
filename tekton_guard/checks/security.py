"""Security context checks (TKN-SEC-001..006)."""

from __future__ import annotations

import re
import urllib.parse

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
        run_as_user = sc.get("runAsUser")
        is_root = run_as_user == 0 or str(run_as_user) == "0"
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


# Regex: match `..` that appears as an actual path component, not embedded in a filename.
# Matches /../ or /.. at end or ../ at start or bare .. (the whole string).
_PATH_TRAVERSAL_COMPONENT_RE = re.compile(r"(?:^|/)\.\.(?:/|$)")


@register_check
def check_sec_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SEC-003: Git resolver pathInRepo traversal (CVE-2026-33211)."""
    findings: list[dict] = []

    def _check_resolver_ref(ref, context: str) -> None:
        if not ref or ref.resolver_type != "git":
            return
        path_in_repo = ref.params.get("pathInRepo", "")
        if not path_in_repo:
            return
        # URL decode to catch %2e%2e obfuscation
        decoded = urllib.parse.unquote(str(path_in_repo))
        # FP guard: only flag if .. appears as a standalone path component
        if _PATH_TRAVERSAL_COMPONENT_RE.search(decoded):
            findings.append(_finding(
                "TKN-SEC-003", "CRITICAL",
                "Git resolver pathInRepo traversal (CVE-2026-33211)",
                resource, ref.line,
                f"{context} uses pathInRepo '{path_in_repo}' containing path traversal. "
                f"An attacker can escape the repository root and read arbitrary files "
                f"from the git resolver's filesystem.",
                cwe="CWE-22",
                remediation="Remove '..' path components from pathInRepo. Use an absolute path within the repository.",
                extra={"pathInRepo": path_in_repo, "decoded": decoded},
            ))

    # Check pipeline-level ref
    if resource.pipeline_ref:
        _check_resolver_ref(resource.pipeline_ref, f"PipelineRun '{resource.name}' pipelineRef")

    # Check all task refs in pipeline tasks
    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if pt.task_ref and pt.task_ref.resolver:
            _check_resolver_ref(pt.task_ref.resolver, f"Pipeline task '{pt.name}'")

    return findings


# Tekton internal paths that are dangerous when mounted by steps/sidecars.
# /tekton/home is legitimate (git credentials), so we skip it.
_DANGEROUS_TEKTON_PATHS = ("/tekton/run/", "/tekton/results/", "/tekton/creds/", "/tekton/steps/")


@register_check
def check_sec_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SEC-004: VolumeMount targeting /tekton/ paths (CVE-2026-40923)."""
    findings: list[dict] = []
    for ci in collect_all_containers(resource):
        for vm in ci.container.volume_mounts:
            mount_path = str(vm.get("mountPath", ""))
            if not mount_path.startswith("/tekton/"):
                continue
            # FP guard: /tekton/home is legitimate for git credential helpers
            if mount_path.rstrip("/") == "/tekton/home" or mount_path.startswith("/tekton/home/"):
                continue
            # Only flag known-dangerous paths to avoid FPs on future Tekton additions
            if any(mount_path.startswith(p) or mount_path.rstrip("/") == p.rstrip("/") for p in _DANGEROUS_TEKTON_PATHS):
                findings.append(_finding(
                    "TKN-SEC-004", "HIGH",
                    "VolumeMount targeting /tekton/ paths (CVE-2026-40923)",
                    resource, ci.container.image_line,
                    f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} "
                    f"mounts '{mount_path}' which is a Tekton-internal path. "
                    f"Mounting these paths allows tampering with pipeline execution, "
                    f"result injection, or credential theft.",
                    cwe="CWE-284",
                    remediation="Remove the volumeMount targeting Tekton-internal paths. Use Tekton's built-in mechanisms for inter-step communication.",
                    extra={"step_name": ci.container.name, "mount_path": mount_path,
                           "container_type": ci.container_type},
                ))
    return findings


@register_check
def check_sec_005(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SEC-005: Resolver name exceeds 30 characters (CVE-2026-33022)."""
    findings: list[dict] = []

    def _check_resolver_name(ref, context: str) -> None:
        if not ref or not ref.resolver_type:
            return
        # FP guard: only check the resolver type string itself, not the full config
        if len(ref.resolver_type) >= 31:
            findings.append(_finding(
                "TKN-SEC-005", "MEDIUM",
                "Resolver name exceeds 30 characters (CVE-2026-33022)",
                resource, ref.line,
                f"{context} uses resolver type '{ref.resolver_type}' which exceeds "
                f"30 characters ({len(ref.resolver_type)} chars). Excessively long "
                f"resolver names can cause denial-of-service via resource exhaustion "
                f"in the Tekton controller.",
                cwe="CWE-400",
                remediation="Use a resolver type name with 30 or fewer characters.",
                extra={"resolver_type": ref.resolver_type,
                       "resolver_length": len(ref.resolver_type)},
            ))

    if resource.pipeline_ref:
        _check_resolver_name(resource.pipeline_ref, f"PipelineRun '{resource.name}' pipelineRef")

    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if pt.task_ref and pt.task_ref.resolver:
            _check_resolver_name(pt.task_ref.resolver, f"Pipeline task '{pt.name}'")

    return findings


@register_check
def check_sec_006(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-SEC-006: Step without runAsNonRoot."""
    # Only check Task and StepAction kinds where steps are defined
    if resource.kind not in ("Task", "StepAction", "Pipeline", "PipelineRun", "TaskRun"):
        return []

    # Check pod-level securityContext that applies to all containers
    # For Task: spec.stepTemplate.securityContext
    # For PipelineRun: spec.taskRunTemplate.podTemplate.securityContext
    raw_spec = resource.raw.get("spec", {})

    pod_level_non_root = False
    # Task-level stepTemplate
    step_template_sc = raw_spec.get("stepTemplate", {})
    if isinstance(step_template_sc, dict):
        step_template_sc = step_template_sc.get("securityContext", {})
        if isinstance(step_template_sc, dict) and step_template_sc.get("runAsNonRoot") is True:
            pod_level_non_root = True

    # PipelineRun-level podTemplate
    if not pod_level_non_root:
        trt = raw_spec.get("taskRunTemplate", {})
        if isinstance(trt, dict):
            pod_template = trt.get("podTemplate", {})
            if isinstance(pod_template, dict):
                pod_sc = pod_template.get("securityContext", {})
                if isinstance(pod_sc, dict) and pod_sc.get("runAsNonRoot") is True:
                    pod_level_non_root = True

    if pod_level_non_root:
        return []  # Pod-level covers all containers

    findings: list[dict] = []
    for ci in collect_all_containers(resource):
        sc = ci.container.security_context
        # FP guard: skip if container already has runAsNonRoot: true
        if sc.get("runAsNonRoot") is True:
            continue
        # FP guard: skip if runAsUser is set to a non-zero value
        run_as_user = sc.get("runAsUser")
        if run_as_user is not None and str(run_as_user) != "0":
            try:
                if int(run_as_user) != 0:
                    continue
            except (ValueError, TypeError):
                pass

        # Also check pipeline-level inline taskSpec stepTemplate for Pipeline kind
        if resource.kind in ("Pipeline", "PipelineRun"):
            # Each pipeline task might have its own stepTemplate in taskSpec
            # We can't easily correlate ci back to the raw task, so just check container-level
            pass

        findings.append(_finding(
            "TKN-SEC-006", "MEDIUM",
            "Step without runAsNonRoot",
            resource, ci.container.image_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} "
            f"does not set runAsNonRoot: true. Without this constraint, the container "
            f"may run as root, increasing the blast radius of a compromise.",
            cwe="CWE-250",
            remediation="Add 'runAsNonRoot: true' to the step's securityContext, or set it at the pod level via stepTemplate.securityContext.",
            extra={"step_name": ci.container.name, "container_type": ci.container_type},
        ))
    return findings
