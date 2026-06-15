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
