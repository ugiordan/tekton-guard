"""Trust checks (TKN-TRUST-001..006)."""

from __future__ import annotations

import re as _re

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import (
    _finding,
    _is_pac_template,
    register_check,
    register_correlation_check,
)


@register_check
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


@register_check
def check_trust_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-002: Task from untrusted source."""
    findings = []
    for pt in resource.pipeline_tasks + resource.finally_tasks:
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


@register_check
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


@register_check
def check_trust_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-004: HTTP resolver without digest."""
    findings = []
    all_refs = []

    if resource.pipeline_ref and resource.pipeline_ref.resolver_type == "http":
        all_refs.append(("pipelineRef", resource.pipeline_ref, resource.name))

    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if pt.task_ref and pt.task_ref.resolver and pt.task_ref.resolver.resolver_type == "http":
            all_refs.append((f"task '{pt.name}'", pt.task_ref.resolver, pt.name))

    for context, ref, name in all_refs:
        digest = ref.params.get("digest", "")
        if not digest:
            findings.append(_finding(
                "TKN-TRUST-004", "HIGH", "HTTP resolver without digest",
                resource, ref.line,
                f"{context} in '{resource.name}' uses HTTP resolver without a digest param. "
                f"Without integrity verification, a MITM or compromised server can inject "
                f"malicious task/pipeline definitions.",
                cwe="CWE-829",
                remediation="Add a digest param: digest: sha256:<hash>",
                extra={"resolver_type": "http", "resolver_url": ref.params.get("url", "")},
            ))
    return findings


@register_check
def check_trust_005(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-005: Cluster resolver in shared namespace."""
    findings = []
    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if not pt.task_ref or not pt.task_ref.resolver:
            continue
        ref = pt.task_ref.resolver
        if ref.resolver_type != "cluster":
            continue
        ns = ref.params.get("namespace", "")
        if ns and ns in config.shared_namespaces:
            findings.append(_finding(
                "TKN-TRUST-005", "MEDIUM",
                "Cluster resolver in shared namespace",
                resource, ref.line,
                f"Pipeline task '{pt.name}' references a task via cluster resolver in "
                f"shared namespace '{ns}'. Any user with Task create permission in that "
                f"namespace can replace the referenced task.",
                cwe="CWE-829",
                remediation="Use a dedicated namespace for cluster-resolver tasks, or switch to bundle/git resolver with pinning.",
                extra={"task_name": pt.name, "namespace": ns, "resolver_type": "cluster"},
            ))
    return findings


@register_correlation_check
def check_trust_006(resources: list, config: ScannerConfig) -> list[dict]:
    """TKN-TRUST-006: Bundle without VerificationPolicy coverage."""
    # Collect all VerificationPolicy patterns
    vp_patterns = []
    for r in resources:
        if r.kind != "VerificationPolicy":
            continue
        for res_entry in r.raw.get("spec", {}).get("resources", []):
            pattern = res_entry.get("resourcePattern", "")
            if pattern:
                vp_patterns.append(pattern)

    if not vp_patterns:
        return []  # No policies found, skip silently (avoids 100% FP)

    findings = []
    for r in resources:
        for pt in r.pipeline_tasks + r.finally_tasks:
            if not pt.task_ref or not pt.task_ref.resolver:
                continue
            ref = pt.task_ref.resolver
            if ref.resolver_type != "bundles":
                continue
            bundle = ref.bundle
            if not bundle:
                continue
            # Check if any VP pattern covers this bundle
            covered = False
            for pattern in vp_patterns:
                try:
                    if _re.search(pattern, bundle):
                        covered = True
                        break
                except _re.error:
                    pass
            if not covered:
                findings.append(_finding(
                    "TKN-TRUST-006", "MEDIUM",
                    "Bundle without VerificationPolicy coverage",
                    r, ref.line,
                    f"Pipeline task '{pt.name}' uses bundle '{bundle}' "
                    f"which is not covered by any VerificationPolicy pattern. "
                    f"Bundle content is not signature-verified before execution.",
                    cwe="CWE-345",
                    remediation="Create a VerificationPolicy with a resourcePattern covering this bundle's registry.",
                    extra={"task_name": pt.name, "bundle": bundle},
                ))
    return findings
