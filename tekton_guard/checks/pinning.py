"""Pinning checks (TKN-PIN-001..005)."""

from __future__ import annotations

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import DIGEST_RE, SHA_RE, TektonResource
from tekton_guard.checks._common import (
    _finding, _is_pac_template, collect_all_containers, register_check,
)


@register_check
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


@register_check
def check_pin_002(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-002: Mutable task reference (git resolver)."""
    findings = []
    for pt in resource.pipeline_tasks + resource.finally_tasks:
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


@register_check
def check_pin_003(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-003: Unpinned task bundle."""
    findings = []
    for pt in resource.pipeline_tasks + resource.finally_tasks:
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


@register_check
def check_pin_004(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-004: Mutable step image."""
    findings = []
    for ci in collect_all_containers(resource):
        img = ci.container.image
        if not img or DIGEST_RE.search(img):
            continue
        if "{{" in img or "$(" in img:
            continue
        findings.append(_finding(
            "TKN-PIN-004", "MEDIUM", "Mutable step image",
            resource, ci.container.image_line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} uses image '{img}' without a digest pin. "
            f"Image tags are mutable and can be overwritten to inject malicious code into the build.",
            cwe="CWE-829",
            remediation="Pin the image to a digest: image: <registry>/<image>@sha256:<digest>",
            extra={"current_value": img, "step_name": ci.container.name},
        ))
    return findings


@register_check
def check_pin_005(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-PIN-005: Mutable StepAction reference."""
    findings = []
    for ci in collect_all_containers(resource):
        if not ci.container.ref or ci.container.ref.resolver_type != "git":
            continue
        rev = ci.container.ref.revision
        if not rev or SHA_RE.match(rev):
            continue
        findings.append(_finding(
            "TKN-PIN-005", "HIGH", "Mutable StepAction reference",
            resource, ci.container.ref.line,
            f"{ci.container_type.capitalize()} '{ci.container.name}' in {ci.context} references a StepAction via "
            f"git resolver with mutable revision '{rev}'. "
            f"The StepAction code can be changed without any commit to this repository.",
            cwe="CWE-829",
            remediation="Pin the StepAction's git revision to a 40-character commit SHA.",
            extra={"resolver_type": "git", "resolver_url": ci.container.ref.url,
                   "current_value": rev, "step_name": ci.container.name},
        ))
    return findings
