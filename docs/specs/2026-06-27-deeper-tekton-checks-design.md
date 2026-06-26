# Deeper Tekton Checks: 28 to 42

**Date**: 2026-06-27
**Status**: Revised (post-adversarial review)
**Author**: Ugo Giordano

## Problem

tekton-guard has 28 checks but only covers 5 Tekton CRD kinds (PipelineRun, Pipeline, Task, TaskRun, StepAction). The full Tekton CRD surface includes TriggerTemplate, TriggerBinding, EventListener, Repository (PaC), and VerificationPolicy. Several of these represent attack surfaces that no existing tool scans (TriggerTemplate injection, PaC Repository scope, VerificationPolicy regex auditing).

Additionally, existing checks focus on individual resource properties but not on pipeline execution flow (can a security task be skipped? can results be poisoned?).

## Solution

Add 14 new checks across 4 categories, taking tekton-guard from 28 to 42 checks. Extend the parser to handle 5 new CRD kinds and add `runAfter` field to PipelineTaskDef.

## Architecture Changes

### Cross-resource correlation

Three new checks (CHAIN-006, LOGIC-003, TRUST-006) need to see multiple resources simultaneously. The current `check_fn(resource, config)` signature processes one resource at a time.

Solution: add a second check type `CorrelationCheckFn(resources: list[TektonResource], config) -> list[dict]` and a separate registration decorator `@register_correlation_check`. The `run_checks` function runs per-resource checks first, then correlation checks over the full resource list. This is additive: no changes to existing checks.

```python
CorrelationCheckFn = Callable[[list[TektonResource], ScannerConfig], list[dict]]
_CORRELATION_REGISTRY: list[CorrelationCheckFn] = []

def register_correlation_check(func: CorrelationCheckFn) -> CorrelationCheckFn:
    _CORRELATION_REGISTRY.append(func)
    return func
```

### Parser extensions

Add to `TEKTON_KINDS`:
```python
TEKTON_KINDS = {
    "PipelineRun", "Pipeline", "Task", "TaskRun", "StepAction",
    "TriggerTemplate", "TriggerBinding", "EventListener",
    "Repository", "VerificationPolicy",
}
```

Add `run_after: list[str]` field to `PipelineTaskDef` (extracted from `runAfter` key in Pipeline task definitions). Required by LOGIC-003.

For trigger/EventListener/Repository/VerificationPolicy CRDs: use `resource.raw` for field access rather than adding many new dataclass fields. These CRDs have diverse structures and raw dict access is simpler and more maintainable than trying to model them all.

Add `--policy-dir` CLI flag for specifying a directory containing VerificationPolicy YAML files (since they're namespace-scoped cluster resources that usually aren't in the scanned repo).

## New Checks (14 total)

### Trigger Deep (TKN-TRIG-004..007)

**TKN-TRIG-004: TriggerTemplate param injection**
- Severity: HIGH
- CWE: CWE-94
- Detect: TriggerTemplate `resourcetemplates` containing PipelineRun params that reference `$(tt.params.*)`. These params originate from TriggerBinding webhook body fields, enabling code injection via crafted webhook payloads.
- Uniqueness: no existing tool scans TriggerTemplate resource templates for injection
- Implementation: per-resource check on TriggerTemplate kind, scan `raw["spec"]["resourcetemplates"]` for `$(tt.params.*)` patterns

**TKN-TRIG-005: EventListener without interceptor**
- Severity: MEDIUM
- CWE: CWE-284
- Detect: EventListener with triggers that have no `interceptors` configured. Raw webhook payload reaches TriggerBinding without signature verification.
- Note: Kyverno/OPA can enforce this via admission policies, but tekton-guard catches it pre-deploy via static analysis
- Implementation: per-resource check on EventListener kind

**TKN-TRIG-006: PaC Repository allows all branches**
- Severity: MEDIUM (revised from HIGH: branch filtering often happens at PipelineRun annotation level)
- CWE: CWE-284
- Detect: PaC Repository CRD with no branch restrictions or pattern set to `*`
- Implementation: per-resource check on Repository kind

**TKN-TRIG-007: EventListener with default/missing SA**
- Severity: MEDIUM
- CWE: CWE-269
- Detect: EventListener with `serviceAccountName: default` or missing (inherits namespace default)
- Implementation: per-resource check, same pattern as existing TKN-SA-001/002

### Supply Chain Deep (TKN-CHAIN-003..006)

TKN-CHAIN-003 (results type hint) removed: `type: string` is the default in Tekton v1. Omitting it has no effect on Chains signing behavior. The check would produce false positives on valid Tasks.

**TKN-CHAIN-003: VerificationPolicy with unanchored regex** (renumbered from CHAIN-005)
- Severity: HIGH
- CWE: CWE-185
- Detect: VerificationPolicy `resourcePattern` regex without `^` and `$` anchors. Defense-in-depth: even though CVE-2026-25542 was patched, users may run older versions or port YAML between clusters.
- Implementation: per-resource check on VerificationPolicy kind, regex analysis on `raw["spec"]["resources"][].resourcePattern`

**TKN-CHAIN-004: Chains-consumed result from untrusted task** (renumbered from CHAIN-006)
- Severity: HIGH
- CWE: CWE-345
- Detect: Pipeline task producing IMAGE_URL/IMAGE_DIGEST results is from an untrusted source. Poisoned attestation.
- Implementation: **correlation check** (needs all resources). For each Pipeline, find tasks with IMAGE_URL/IMAGE_DIGEST in results, check trust status of their taskRef.
- Note: only feasible when the Task definition is available (inline taskSpec or via --resolve). When the Task is remote and not resolved, the check is skipped with an INFO note.

**TKN-CHAIN-005: Build pipeline without SBOM task** (renumbered from CHAIN-007)
- Severity: LOW
- CWE: CWE-1059
- Detect: Build-type Pipeline with no task matching SBOM patterns (syft, cyclonedx, spdx, sbom)
- Note: Enterprise Contract also checks for SBOM presence in attestations. This check catches it earlier (pre-build).
- Implementation: per-resource check on Pipeline kind, name pattern matching using centralized `security_task_patterns` config

### Pipeline Logic (TKN-LOGIC-001..004)

**TKN-LOGIC-001: Security task not in finally block**
- Severity: MEDIUM
- CWE: CWE-693
- Detect: Pipeline has a security-relevant task in `spec.tasks` instead of `spec.finally`. If preceding tasks fail, security tasks are skipped.
- Subsumes the originally proposed CHAIN-004 (finally signing block). Uses centralized `security_task_patterns` config.
- Implementation: per-resource check on Pipeline kind

**TKN-LOGIC-002: Overridable security-relevant param default**
- Severity: LOW (disabled by default, opt-in via config)
- CWE: CWE-1188
- Detect: Task param with default containing security keywords (privileged, tls-verify, skip, insecure) that can be overridden
- High FP potential. Heuristic-based.
- Implementation: per-resource check on Task kind

**TKN-LOGIC-003: TOCTOU via parallel workspace access**
- Severity: MEDIUM (revised from HIGH: Tekton AffinityAssistant serializes PVC access by default, requires RWX + disabled AffinityAssistant to exploit)
- CWE: CWE-367
- Detect: Pipeline tasks sharing a workspace that can run in parallel (no `runAfter` between them) where at least one is untrusted
- Requires: `run_after` field on PipelineTaskDef
- Implementation: per-resource check on Pipeline kind (has all task data within one resource)

**TKN-LOGIC-004: Pipeline without finally block**
- Severity: LOW
- CWE: CWE-390
- Detect: Pipeline with no `finally` block
- Implementation: per-resource check on Pipeline kind

### Resolver Deep (TKN-TRUST-004..006)

**TKN-TRUST-004: HTTP resolver without digest**
- Severity: HIGH
- CWE: CWE-829
- Detect: `resolver: http` without `digest` param. MITM can inject malicious definitions.
- Uniqueness: only tekton-guard checks resolver-specific params
- Implementation: per-resource check, extends existing resolver iteration in pinning/trust checks

**TKN-TRUST-005: Cluster resolver in shared namespace**
- Severity: MEDIUM
- CWE: CWE-829
- Detect: `resolver: cluster` with `namespace` param in configurable shared namespace list
- Implementation: per-resource check, new config field `shared_namespaces`

**TKN-TRUST-006: Bundle without VerificationPolicy coverage**
- Severity: MEDIUM
- CWE: CWE-345
- Detect: Bundle resolver reference not covered by any VerificationPolicy in the scanned files or `--policy-dir`
- Implementation: **correlation check** (needs VerificationPolicy resources). Skipped silently if no VerificationPolicy files found (avoids 100% FP rate).

## Config additions

```yaml
shared_namespaces:
  - "tekton-pipelines"
  - "openshift-pipelines"

security_task_patterns:
  - "scan"
  - "sign"
  - "verify"
  - "attest"
  - "cosign"
  - "enterprise-contract"
  - "sast"
  - "clair"
  - "clamav"
  - "sbom"
  - "syft"
  - "cyclonedx"
```

Centralized list used by: TKN-TRIG-003, TKN-LOGIC-001, TKN-CHAIN-005.

## Expected check count

- Existing: 28 checks (27 registered + 1 disabled TKN-LIMIT-001)
- New: 14 checks (12 per-resource + 2 correlation)
- Total: 42 checks (39 registered, 3 disabled by default: LIMIT-001, LOGIC-002, and correlation checks without policy data)

## Phased Implementation (reordered per review feedback)

**Phase B**: Supply Chain Deep (CHAIN-003..005) + VerificationPolicy in TEKTON_KINDS + correlation check infrastructure
**Phase D**: Resolver Deep (TRUST-004..006) + `--policy-dir` flag
**Phase A**: Trigger Deep (TRIG-004..007) + parser extensions for TriggerTemplate/EventListener/Repository
**Phase C**: Pipeline Logic (LOGIC-001..004) + `runAfter` field on PipelineTaskDef

Rationale: Phase B builds on existing CHAIN checks with familiar data model. Phase D extends existing TRUST checks. Phase A requires new CRD parsing (highest effort). Phase C needs `runAfter` parsing.

## Appendix: Adversarial Review Resolution

| Finding | Resolution |
|---------|------------|
| Cross-resource correlation architecture gap (R1, R2, R3) | Added `CorrelationCheckFn` type with separate registry and `register_correlation_check` decorator |
| VerificationPolicy not in TEKTON_KINDS (R1, R3) | Added to TEKTON_KINDS + `--policy-dir` flag |
| TKN-CHAIN-003 based on wrong Chains behavior (R1, R2) | Removed. type: string is default, omitting has no effect |
| 5 checks have competition (R3) | Acknowledged in spec. Kept because static pre-deploy catches issues earlier than runtime tools |
| Parser missing runAfter (R1) | Added `run_after: list[str]` to PipelineTaskDef |
| LOGIC-003 severity too high (R2) | Lowered to MEDIUM (AffinityAssistant serializes by default) |
| Phase order should be B->D->A->C (R3) | Reordered |
| LOGIC-002 contradicts itself (R2) | Fixed to LOW, disabled by default |
| CHAIN-004 overlaps LOGIC-001 (R3) | Merged CHAIN-004 into LOGIC-001. CHAIN renumbered: 003=regex, 004=result poisoning, 005=SBOM |
| Security task patterns inconsistent (R3) | Centralized in config, shared by TRIG-003, LOGIC-001, CHAIN-005 |
| TRIG-006 severity too high (R2) | Lowered to MEDIUM |
| TRUST-006 100% FP without policies (R2) | Skipped silently when no VerificationPolicy files found |
| Use raw dict for new CRDs (R1) | Specified raw dict access instead of new dataclass fields |
