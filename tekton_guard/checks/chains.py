"""Chains readiness checks (TKN-CHAIN-001..002)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, register_check


@register_check
def check_chain_001(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CHAIN-001: Build pipeline missing Chains type hints."""
    if resource.kind != "PipelineRun":
        return []
    pipeline_type = resource.labels.get("pipelines.appstudio.openshift.io/type", "")
    if pipeline_type != "build":
        return []
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


@register_check
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


@register_check
def check_chain_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CHAIN-003: VerificationPolicy with unanchored regex."""
    if resource.kind != "VerificationPolicy":
        return []
    findings = []
    resources_list = resource.raw.get("spec", {}).get("resources", [])
    for res in resources_list or []:
        pattern = res.get("resourcePattern", "")
        if not pattern:
            continue
        if not pattern.startswith("^") or not pattern.endswith("$"):
            anchored = pattern
            if not anchored.startswith("^"):
                anchored = "^" + anchored
            if not anchored.endswith("$"):
                anchored = anchored + "$"
            findings.append(_finding(
                "TKN-CHAIN-003", "HIGH", f"VerificationPolicy with unanchored regex: {pattern}",
                resource, resource.line_offset,
                f"VerificationPolicy '{resource.name}' has resource pattern '{pattern}' "
                f"without ^ and $ anchors. Unanchored patterns can match unintended "
                f"resources (CVE-2026-25542).",
                cwe="CWE-185",
                remediation=f"Anchor the pattern: {anchored}",
                extra={"pattern": pattern},
            ))
    return findings


@register_check
def check_chain_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CHAIN-004: Chains-consumed result from untrusted task.

    Note: this check may fire alongside TKN-TRUST-002 on the same task.
    This is expected (different risk dimensions: TRUST-002 flags the untrusted
    source, CHAIN-004 flags the supply chain attestation poisoning risk).
    """
    if resource.kind != "Pipeline":
        return []
    findings = []
    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if not pt.task_ref or not pt.task_ref.resolver:
            continue
        ref = pt.task_ref.resolver
        is_untrusted = False
        if ref.resolver_type == "git" and not config.is_trusted_git_source(ref.url):
            is_untrusted = True
        elif ref.resolver_type == "hub":
            is_untrusted = True
        if not is_untrusted:
            continue
        # Check if task name suggests it produces Chains-consumed results
        name_lower = pt.name.lower()
        if any(kw in name_lower for kw in ("build", "push", "image", "container")):
            url_info = ref.url if ref.resolver_type == "git" else ref.params.get("name", ref.params.get("catalog", "hub"))
            findings.append(_finding(
                "TKN-CHAIN-004", "HIGH",
                "Chains-consumed result from untrusted task",
                resource, ref.line,
                f"Pipeline task '{pt.name}' appears to produce build/image results "
                f"but is from an untrusted source ({ref.resolver_type}: {url_info}). "
                f"A compromised task can poison Chains attestation.",
                cwe="CWE-345",
                remediation="Use trusted, pinned sources for all tasks that produce IMAGE_URL/IMAGE_DIGEST results.",
                extra={"task_name": pt.name, "resolver_type": ref.resolver_type},
            ))
    return findings


@register_check
def check_chain_005(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CHAIN-005: Build pipeline without SBOM task."""
    if resource.kind != "Pipeline":
        return []
    pipeline_type = resource.labels.get("pipelines.appstudio.openshift.io/type", "")
    if pipeline_type != "build":
        return []
    sbom_patterns = [p for p in config.security_task_patterns if p in ("sbom", "syft", "cyclonedx", "spdx")]
    if not sbom_patterns:
        sbom_patterns = ["sbom", "syft", "cyclonedx", "spdx"]
    all_tasks = resource.pipeline_tasks + resource.finally_tasks
    for pt in all_tasks:
        name_lower = pt.name.lower()
        if any(pat in name_lower for pat in sbom_patterns):
            return []
        if pt.task_ref and pt.task_ref.name:
            ref_lower = pt.task_ref.name.lower()
            if any(pat in ref_lower for pat in sbom_patterns):
                return []
    return [_finding(
        "TKN-CHAIN-005", "LOW", "Build pipeline without SBOM task",
        resource, resource.line_offset,
        f"Pipeline '{resource.name}' is labeled as a build pipeline but has no "
        f"SBOM generation task (syft, cyclonedx, spdx). Missing software bill "
        f"of materials reduces supply chain transparency.",
        cwe="CWE-1059",
        remediation="Add an SBOM generation task to the build pipeline.",
    )]
