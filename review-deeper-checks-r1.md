# Review: Deeper Tekton Checks Design Spec (2026-06-27)

**Reviewer**: Adversarial Code Review
**Date**: 2026-06-27
**Scope**: Design spec for 16 new checks (28->44), parser extensions, cross-check feasibility
**Source**: `docs/specs/2026-06-27-deeper-tekton-checks-design.md` vs. current parser/checks codebase

---

## Finding 1: God Object Problem -- TektonResource absorbs 6 new fields for trigger CRDs it has no business modeling

**Severity**: HIGH
**Category**: Architecture
**Location**: Design spec "Parser Extensions" section, current `parser.py:93-119`

**Description**:

`TektonResource` is already a 20-field dataclass that models Pipeline, PipelineRun, Task, TaskRun, and StepAction. The spec proposes adding 6 new fields (`trigger_template_params`, `trigger_resource_templates`, `trigger_bindings`, `event_listener_triggers`, `event_listener_interceptors`, `repository_spec`) to accommodate 4 completely different CRD kinds.

The problem is not just the field count. It is that these fields are semantically disjoint. A `TektonResource` of kind `Pipeline` will never use `trigger_template_params` or `event_listener_interceptors`. A `TektonResource` of kind `EventListener` will never use `pipeline_tasks` or `steps`. The dataclass becomes a union type that carries dead weight for every kind. This makes the type signature of every check function misleading (every check receives a `TektonResource` that might or might not have the fields it needs populated).

The red-team review (round 5) already flagged this direction. Adding 4 more CRD kinds without decomposition will make it worse.

**Fix**:

Option A (recommended): Use `resource.raw` for the new CRD kinds. The spec already acknowledges this for CHAIN-005 and TRUST-006. Extend this approach to all trigger/EventListener/Repository checks. The raw dict is already populated by the parser for every resource. This avoids any new fields on `TektonResource` and keeps the dataclass stable.

Option B: Introduce a subclass hierarchy (`TriggerTemplateResource`, `EventListenerResource`, etc.) or use composition (a `trigger_data: TriggerData | None` field that bundles all trigger-specific fields into a separate dataclass). This is more work but gives type safety.

Option C (worst): Add all 6 fields. This works but is a conscious decision to grow the God Object.

The spec should explicitly decide which option and document why, rather than defaulting to "add more fields to TektonResource."

---

## Finding 2: PipelineTaskDef does not parse `runAfter` -- LOGIC-003 and LOGIC-001 are infeasible without parser changes

**Severity**: HIGH
**Category**: Feasibility blocker
**Location**: `parser.py:82-89` (`PipelineTaskDef` dataclass), `parser.py:270-293` (`_extract_pipeline_tasks`)

**Description**:

The `PipelineTaskDef` dataclass has no `run_after` field. The `_extract_pipeline_tasks` function does not extract `runAfter` from the YAML. There is zero reference to `runAfter` anywhere in the parser or checks codebase (confirmed via grep).

This blocks two proposed checks:
- **TKN-LOGIC-003 (TOCTOU via parallel workspace access)**: Requires knowing which tasks can run in parallel, which requires `runAfter` dependency data.
- **TKN-LOGIC-001 (Security task not in finally block)**: The remediation says "ensure they have no `runAfter` dependencies on failable tasks," but the check needs `runAfter` data to determine whether a non-finally security task is at least protected by explicit ordering.

The spec's "Parser" line for LOGIC-003 says "cross-reference workspace bindings with `runAfter` dependencies and trust status" but does not mention that `runAfter` is not currently parsed. This is an undocumented prerequisite.

**Fix**:

Add `run_after: list[str] = field(default_factory=list)` to `PipelineTaskDef`. In `_extract_pipeline_tasks`, extract `t.get("runAfter", [])`. This is a small parser change but must be done before Phase C (Pipeline Logic).

Alternatively, LOGIC-003 could use `resource.raw` to access runAfter, but that defeats the purpose of the structured data model and would be inconsistent with how other checks use `PipelineTaskDef`.

---

## Finding 3: CHAIN-006 requires cross-check state from TRUST checks -- current architecture does not support inter-check data sharing

**Severity**: HIGH
**Category**: Feasibility blocker
**Location**: Design spec CHAIN-006, `checks/__init__.py:37-61` (`run_checks` function)

**Description**:

TKN-CHAIN-006 is defined as: "cross-reference result-producing tasks with trust status from TKN-TRUST checks." This means CHAIN-006 needs to know which tasks were flagged as untrusted by TRUST-001/002/003.

The current `run_checks` architecture iterates `for resource in resources: for check_fn in all_checks:` and each check function receives only `(resource, config)`. There is no mechanism for one check to consume findings from another check. Checks are completely isolated.

LOGIC-003 has the same problem. It needs workspace + runAfter + trust data. The workspace and runAfter data come from the parser, but the trust status comes from TRUST check results.

**Fix**:

Three options:

1. **Duplicate the trust logic** inside CHAIN-006 and LOGIC-003. Reimplement `is_trusted_git_source()` checks directly in those functions. This works because `ScannerConfig` already exposes `is_trusted_git_source()`, so the trust determination is simple. The downside is that if TRUST checks evolve (e.g., add VerificationPolicy awareness), the duplicated logic diverges. This is the pragmatic option.

2. **Add a shared context object** passed to all checks (e.g., `CheckContext` with a `trust_status: dict[str, bool]` computed in a pre-pass). This is cleaner but requires refactoring the `CheckFn` signature from `(TektonResource, ScannerConfig)` to `(TektonResource, ScannerConfig, CheckContext)`, which breaks all existing checks.

3. **Two-pass execution**: Run TRUST checks first, collect results, then run dependent checks with enriched context. This is the most correct design but the most invasive change.

The spec should pick option 1 (duplicate trust logic) for now and document it as tech debt. Options 2/3 are future architecture improvements.

---

## Finding 4: TRIG-004 (param injection) requires cross-resource correlation between TriggerBinding and TriggerTemplate -- parser and check runner don't support this

**Severity**: HIGH
**Category**: Feasibility blocker
**Location**: Design spec TKN-TRIG-004

**Description**:

TRIG-004's detection logic is: "TriggerTemplate has resourcetemplates containing a PipelineRun where params reference `$(tt.params.*)` that originate from TriggerBinding fields mapped to webhook body."

This requires correlating two separate CRD resources:
1. The TriggerBinding (which maps `$(body.pull_request.title)` to a param name like `pr_title`)
2. The TriggerTemplate (which passes `$(tt.params.pr_title)` into the PipelineRun)

The current check architecture processes one resource at a time (`for resource in resources: for check_fn in all_checks:`). There is no way for a check running on a TriggerTemplate to access the TriggerBinding resources.

Additionally, the EventListener is the resource that connects TriggerBindings to TriggerTemplates (via `spec.triggers[].bindings` and `spec.triggers[].template`). So the full correlation actually requires three CRD resources.

The spec's description of TRIG-004 glosses over this. It says "Parser: extract TriggerTemplate resourcetemplates, find `$(tt.params.*)` interpolations" but the real detection (confirming the param originates from a user-controlled body field) requires the TriggerBinding.

**Fix**:

Two approaches:

1. **Reduce scope of TRIG-004**: Detect any `$(tt.params.*)` interpolation flowing into a PipelineRun script or command within a TriggerTemplate's resourcetemplates, regardless of whether the binding source is user-controlled. This is a simpler, single-resource check that produces more findings (higher FP rate) but is actually implementable. The rationale is that any TriggerTemplate param that flows into a script is risky because TriggerBindings typically map from webhook body fields.

2. **Add multi-resource check support**: Modify `run_checks` to build a lookup (e.g., `resources_by_kind: dict[str, list[TektonResource]]`) and pass it to checks that need cross-resource correlation. This is a bigger change.

The spec should document that TRIG-004 as currently designed requires approach 2, and propose which approach will be used.

---

## Finding 5: TKN-CHAIN-003 (Results missing type hint) is based on incorrect Tekton Chains behavior

**Severity**: MEDIUM
**Category**: Correctness
**Location**: Design spec TKN-CHAIN-003

**Description**:

The spec states: "Task that produces IMAGE_URL or IMAGE_DIGEST results but without `type: string` annotation. Chains uses type-hinting to identify which results to sign."

This is not accurate. Tekton Chains identifies results to sign based on the result **name** (`IMAGE_URL`, `IMAGE_DIGEST`) following the [Tekton Chains Type Hinting](https://tekton.dev/docs/chains/signed-provenance-tutorial/) convention. The `type` field on a result definition (which can be `string` or `array`) is a Tekton Pipeline concept for validation, not a Chains concept for discovery.

In Tekton v0.44+, results default to `type: string` when unspecified. A Task that declares `results: [{name: IMAGE_URL}]` without an explicit `type` field will work correctly with Chains because the default is `string`.

This check would produce false positives on every Task that correctly produces IMAGE_URL/IMAGE_DIGEST without explicitly writing `type: string` (which is the majority of real-world Konflux tasks).

**Fix**:

Either remove CHAIN-003 entirely, or redefine it to check for results declared with `type: array` (which Chains does not handle correctly in some versions). The current definition will generate noise.

---

## Finding 6: TKN-CHAIN-005 references a CVE that does not exist and conflates VerificationPolicy regex semantics

**Severity**: MEDIUM
**Category**: Correctness
**Location**: Design spec TKN-CHAIN-005

**Description**:

The spec references "CVE-2026-25542" as evidence that unanchored regex in VerificationPolicy allows policy bypass. This CVE ID format and number do not correspond to any known vulnerability. CVE IDs follow the pattern CVE-YYYY-NNNNN where YYYY is the year of assignment. While the underlying concern (unanchored regex matching more than intended) is valid, citing a nonexistent CVE reduces credibility and could cause confusion during implementation and documentation.

Additionally, the regex anchoring check is trickier than it appears. Tekton VerificationPolicy uses Go's `regexp.MatchString()`, which does substring matching by default (unlike `regexp.Match()` which requires full-string matching). So unanchored patterns are genuinely a concern. But some patterns are intentionally unanchored (e.g., a pattern like `gcr.io/my-project/` is meant to match any image in that project). A blanket "must have `^` and `$`" rule will produce false positives for prefix-match use cases.

**Fix**:

Remove the CVE reference or mark it as "hypothetical / to be assigned." Add a note that the check should allow patterns that end with `.*$` or start with `^` and end with `/` (prefix patterns) without flagging them. Consider making this check LOW severity or opt-in given the FP potential.

---

## Finding 7: TKN-TRUST-006 (Bundle without VerificationPolicy) requires cross-file scanning that `find_tekton_files` may not support

**Severity**: MEDIUM
**Category**: Feasibility
**Location**: Design spec TKN-TRUST-006, `parser.py:388-410` (`find_tekton_files`)

**Description**:

TKN-TRUST-006 checks whether a bundle reference has a corresponding VerificationPolicy that covers its registry pattern. VerificationPolicy resources are typically deployed as cluster-scoped or namespace-scoped resources, NOT stored alongside PipelineRun definitions in `.tekton/` directories.

The current `find_tekton_files` function only looks for YAML files inside `.tekton/` directories. VerificationPolicy manifests are typically in deployment/infrastructure directories (e.g., `config/`, `deploy/`, `manifests/`). The scanner will never find them.

Even if the scanner does find VerificationPolicy files, the check requires correlating a bundle reference in one resource with a regex pattern in a different resource (the VerificationPolicy). This is the same cross-resource correlation problem described in Finding 4.

**Fix**:

1. Document that TRUST-006 requires either (a) the VerificationPolicy files to be explicitly passed to the scanner, or (b) a `--include-path` flag that scans beyond `.tekton/` directories.
2. Address the cross-resource correlation requirement (same as Finding 4).
3. Consider whether this check is practical as a static analysis check at all. In practice, VerificationPolicies are applied at the cluster level by admins, not stored in the same repo as the pipeline definitions. The check might be better suited as a runtime/cluster check.

---

## Finding 8: TKN-LOGIC-002 (Overridable param default) will fire on nearly every Konflux task

**Severity**: MEDIUM
**Category**: False positive risk
**Location**: Design spec TKN-LOGIC-002

**Description**:

The spec already notes "high FP potential" and revised severity to LOW, but the problem is worse than acknowledged. The proposed detection is: "Task defines a param with a security-relevant default containing keywords (privileged, tls-verify, skip, insecure, allow-all)."

In the Konflux/RHOAI ecosystem, the standard buildah task has params like `TLSVERIFY` (default: `"true"`), `SKIP_UNUSED_STAGES` (default: `"true"`), and several other flag-like params. These are all designed to be overridable by PipelineRuns, and the param-override mechanism is a core Tekton feature, not a vulnerability.

The fundamental issue is that this check conflates "overridable" with "insecure." A param with a secure default that can be overridden to an insecure value is only a problem if the caller is untrusted. But in Tekton, the PipelineRun definition (the caller) is typically authored by the same team and stored in the same `.tekton/` directory.

**Fix**:

If keeping this check, it should ONLY fire when the param is referenced in a PipelineRun from a different trust domain (e.g., a TriggerTemplate-generated PipelineRun where params come from webhook body fields). Without this cross-resource context, the check is pure noise. Recommend keeping it disabled-by-default (in skip_checks) and documenting the narrow conditions under which it is useful.

---

## Finding 9: TRIG-005 (EventListener without interceptor) does not account for Kubernetes Service-level authentication

**Severity**: LOW
**Category**: False positive risk
**Location**: Design spec TKN-TRIG-005

**Description**:

The check flags EventListeners without interceptors as lacking webhook validation. However, EventListeners in OpenShift/Kubernetes environments are commonly deployed behind:
- OpenShift Routes with TLS termination and IP allowlisting
- Kubernetes NetworkPolicies restricting ingress
- API Gateway or service mesh authentication

An EventListener without a webhook interceptor is not necessarily exposed to unauthenticated webhook payloads. The check will fire for EventListeners that are already protected by infrastructure-level controls.

**Fix**:

Document this as a known limitation of static analysis. Consider adding annotation-based suppression (e.g., `tekton-guard.dev/interceptor-external: "true"`) to allow teams to acknowledge that interceptor-equivalent validation happens at a different layer.

---

## Finding 10: TRIG-007 (EventListener SA with excessive permissions) cannot determine actual SA permissions via static analysis

**Severity**: LOW
**Category**: Infeasible as static analysis
**Location**: Design spec TKN-TRIG-007

**Description**:

The check is defined as: "flag if [ServiceAccount is] default or missing." But knowing whether a ServiceAccount has "excessive permissions" requires reading the RBAC bindings (RoleBindings, ClusterRoleBindings) associated with that SA, which are not present in the Tekton YAML being scanned.

Flagging `default` or missing SA is a weak heuristic. A dedicated SA named `el-builder` could have cluster-admin permissions. A `default` SA in a locked-down namespace could have minimal permissions. The check cannot distinguish these cases.

**Fix**:

Rename the check to "EventListener without dedicated ServiceAccount" and reduce severity to LOW. The check should flag only the absence of an explicit `serviceAccountName` (which means Tekton falls back to the namespace default SA). This is a valid hygiene check (use dedicated SAs) without claiming to detect "excessive permissions."

---

## Finding 11: The spec does not account for `_parse_document` gating on `TEKTON_KINDS` -- new CRD kinds will be silently dropped without parser changes

**Severity**: MEDIUM
**Category**: Implementation gap
**Location**: `parser.py:296-299` (`_parse_document`), design spec "Parser Extensions"

**Description**:

The `_parse_document` function has an early return at line 298: `if kind not in TEKTON_KINDS: return None`. The spec correctly identifies that `TEKTON_KINDS` needs to be extended. However, after adding the new kinds to `TEKTON_KINDS`, the `_parse_document` function still has kind-specific extraction blocks (`if kind in ("PipelineRun", "TaskRun"):`, `if kind == "Pipeline":`, `if kind in ("Task", "StepAction"):`). None of these blocks match the new kinds.

This means new-kind resources will be parsed into `TektonResource` objects with only metadata and `raw` populated (no structured field extraction). This is fine if the checks use `resource.raw`, but the spec proposes structured fields like `trigger_template_params` and `event_listener_interceptors`. If those structured fields are added to `TektonResource` but never populated by `_parse_document`, checks that rely on them will silently produce no findings.

**Fix**:

If going with Option A from Finding 1 (use `resource.raw` for new kinds), document explicitly that no new extraction blocks are needed in `_parse_document`. If going with structured fields, the spec must include the `_parse_document` extraction logic for each new kind, not just the field definitions on the dataclass.

---

## Finding 12: Phase ordering creates a dependency trap -- Phase C (Logic) depends on Phase A (Trigger parser extensions) and Phase D (Trust extensions)

**Severity**: LOW
**Category**: Planning
**Location**: Design spec "Phased Implementation"

**Description**:

The phased plan says "Each phase is independently shippable." This is not true for all checks:

- LOGIC-003 needs trust status determination. While it can reuse `config.is_trusted_git_source()` directly (as discussed in Finding 3), the spec's description says "cross-reference with trust status" implying TRUST check results.
- CHAIN-006 explicitly depends on TRUST check results.
- TRUST-006 depends on VerificationPolicy scanning from Phase B (CHAIN-005 introduces VerificationPolicy processing).

The phases are not fully independent. Phase C and D have implicit dependencies on Phase A and B outputs.

**Fix**:

Reorder or annotate dependencies:
- Phase A: Parser extensions + TRIG-004..007 (standalone)
- Phase B: CHAIN-003..005, CHAIN-007 (standalone), defer CHAIN-006 to after Phase D
- Phase C: LOGIC-001..004 (requires runAfter parser addition from its own phase, trust logic can be duplicated)
- Phase D: TRUST-004..006 + CHAIN-006 (CHAIN-006 moves here because it needs trust cross-reference)

---

## Summary

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| 1 | TektonResource God Object grows with 6 disjoint fields | HIGH | Architecture |
| 2 | `runAfter` not parsed, blocks LOGIC-001 and LOGIC-003 | HIGH | Feasibility blocker |
| 3 | No inter-check data sharing for CHAIN-006 trust cross-ref | HIGH | Feasibility blocker |
| 4 | TRIG-004 requires cross-resource correlation (TriggerBinding + TriggerTemplate) | HIGH | Feasibility blocker |
| 5 | CHAIN-003 type-hint check based on incorrect Chains behavior | MEDIUM | Correctness |
| 6 | CHAIN-005 references nonexistent CVE, regex anchoring FP risk | MEDIUM | Correctness |
| 7 | TRUST-006 requires files outside `.tekton/` that scanner cannot find | MEDIUM | Feasibility |
| 8 | LOGIC-002 overridable param check will fire on most Konflux tasks | MEDIUM | False positive risk |
| 9 | TRIG-005 does not account for infra-level auth (NetworkPolicy, Routes) | LOW | False positive risk |
| 10 | TRIG-007 cannot determine actual SA permissions via static analysis | LOW | Infeasible |
| 11 | `_parse_document` gating will silently ignore new CRDs without extraction blocks | MEDIUM | Implementation gap |
| 12 | Phase ordering has undocumented inter-phase dependencies | LOW | Planning |

**Bottom line**: 4 of the 16 proposed checks (TRIG-004, CHAIN-006, LOGIC-003, TRUST-006) have architectural blockers that require changes to the check runner or parser before they can be implemented. The spec should address the cross-resource correlation problem and the missing `runAfter` parser support before committing to the phased plan. The remaining 12 checks are feasible with minor parser additions and the `resource.raw` approach for new CRD kinds.
