# Red Team Audit: Deeper Tekton Checks Spec (2026-06-27)

Reviewer: Red Team Auditor
Scope: /tmp/tekton-guard/docs/specs/2026-06-27-deeper-tekton-checks-design.md
Against: Current codebase state at /tmp/tekton-guard/

---

## 1. "Zero Competition" Claim is False for at Least 5 of 16 Checks

The spec claims these 16 checks cover "zero-competition attack surfaces." This is wrong for several of them.

**TKN-TRIG-005 (EventListener without interceptor):** Tekton's own `tkn` CLI lint mode warns about EventListeners with no interceptors. The Tekton triggers documentation explicitly calls this out as a security misconfiguration. Checkov (Bridgecrew) has a Tekton-adjacent check for webhook validation gaps. This is not zero-competition.

**TKN-TRIG-007 (EventListener SA with excessive permissions):** Kyverno and OPA/Gatekeeper policies routinely enforce ServiceAccount restrictions on any resource that specifies `serviceAccountName`. The CNCF supply-chain security recommendations (SSCP) cover this. Multiple OPA policies exist on artifact-hub that restrict SA usage on Tekton resources. This is a generic K8s policy, not a Tekton-specific gap.

**TKN-CHAIN-004 (Build pipeline without finally signing block) and TKN-LOGIC-001 (Security task not in finally block):** These two overlap substantially. Enterprise Contract (EC) validation in Konflux already checks for the presence of signing and attestation tasks. The EC policy system validates that pipelines include required tasks, including placement requirements. Additionally, TKN-CHAIN-004 and TKN-LOGIC-001 are functionally detecting the same problem (security task in tasks list instead of finally block) with different framing. This is not zero-competition; it is at best partial-competition plus internal self-competition.

**TKN-CHAIN-007 (Build pipeline without SBOM task):** Compliance frameworks (Konflux, EC policies, SLSA verifiers) already check for SBOM generation. The `ec validate` command checks for SBOM task presence as part of its policy evaluation. This is covered territory.

**TKN-LOGIC-004 (Pipeline without finally block):** This is an extremely generic lint rule. Any custom OPA policy can express "Pipeline must have a finally block." Calling this zero-competition overstates the novelty.

Genuinely novel checks from this list: TKN-TRIG-004 (TriggerTemplate param injection), TKN-TRIG-006 (PaC Repository branch validation), TKN-CHAIN-005 (VerificationPolicy unanchored regex), TKN-CHAIN-006 (Chains result from untrusted task), TKN-LOGIC-003 (TOCTOU via parallel workspace), TKN-TRUST-004 (HTTP resolver without digest), TKN-TRUST-005 (cluster resolver in shared namespace), TKN-TRUST-006 (bundle without VerificationPolicy). That is 8 out of 16. The other 8 range from "partially covered" to "solved problem."

**FLAG: COMPETITION-CLAIM - At least 5 of 16 checks are not zero-competition. The spec overstates novelty to justify the 28-to-44 headline. Honest count of genuinely novel checks is ~8.**

---

## 2. Static YAML Feasibility Analysis

### Checks that ARE feasible as pure static YAML analysis:
- TKN-TRIG-004: Yes. TriggerTemplate resourcetemplates and param interpolations are fully visible in YAML.
- TKN-TRIG-005: Yes. EventListener interceptors are a YAML field check.
- TKN-TRIG-006: Yes. PaC Repository branch config is in YAML.
- TKN-TRIG-007: Yes. serviceAccountName is a YAML field.
- TKN-CHAIN-003: Yes. Result type hints are in Task YAML.
- TKN-CHAIN-004: Yes. finally block tasks are in Pipeline YAML.
- TKN-CHAIN-005: Yes. VerificationPolicy resourcePattern is in YAML.
- TKN-CHAIN-007: Yes. Task name heuristics against Pipeline YAML.
- TKN-LOGIC-001: Yes. Same as CHAIN-004 with a wider task name list.
- TKN-LOGIC-002: Yes. Param defaults in Task YAML.
- TKN-LOGIC-004: Yes. Presence of finally key in Pipeline YAML.
- TKN-TRUST-004: Yes. HTTP resolver params are in YAML.
- TKN-TRUST-005: Partial. The namespace param is in YAML, but "shared namespace" is a runtime property. The config-based approach works.

### Checks that are NOT feasible as pure static YAML analysis:

**TKN-CHAIN-006 (Chains-consumed result from untrusted task):** The spec says "cross-reference result-producing tasks with trust status from TKN-TRUST checks." This requires running TKN-TRUST checks first, then correlating their output with the task graph. The current architecture runs every check independently per resource (see `checks/__init__.py` lines 47-59: loop over resources, loop over checks). There is no inter-check communication or shared finding state. Implementing CHAIN-006 requires either:
  (a) Breaking the per-resource/per-check isolation to share trust verdicts across checks, or
  (b) Re-implementing the trust evaluation logic inside CHAIN-006, duplicating TKN-TRUST code.

Neither is acknowledged in the spec. This is a significant architecture change.

**TKN-LOGIC-003 (TOCTOU via parallel workspace access):** This needs three data sources cross-referenced simultaneously: workspace bindings, runAfter dependency graph, and trust status. The current `PipelineTaskDef` dataclass has `workspaces` but no `runAfter` field (see parser.py line 83-89). The parser does not extract `runAfter` from pipeline tasks. This is not a minor omission; adding `runAfter` extraction touches `_extract_pipeline_tasks` and the `PipelineTaskDef` dataclass. Additionally, determining "can run in parallel" requires building a task dependency graph (transitive closure of runAfter + implicit ordering from result references), which is non-trivial and absent from the codebase. The `graph.py` module handles cross-repo dependencies, not intra-pipeline task ordering.

**TKN-TRUST-006 (Bundle without VerificationPolicy):** The spec says "cross-reference bundle references with VerificationPolicy resourcePattern rules." This requires scanning multiple YAML files together: the Pipeline/PipelineRun in one file, the VerificationPolicy in another. The current check architecture processes each resource independently. `run_checks` iterates `for resource in resources: for check_fn in all_checks: check_fn(resource, config)`. A single check invocation sees one resource. To cross-reference, TRUST-006 needs access to all VerificationPolicy resources simultaneously while checking a Pipeline resource. This requires either:
  (a) Passing all resources to the check (breaking the current function signature), or
  (b) A pre-processing step that indexes VerificationPolicies and passes them via config.

The spec mentions "scan as raw YAML without special fields" for VerificationPolicy but does not address how the cross-referencing actually happens within the current architecture.

**FLAG: ARCH-BREAK - Three checks (CHAIN-006, LOGIC-003, TRUST-006) require architectural changes to the check runner that are not spec'd. The per-resource check isolation model does not support inter-resource or inter-check correlation. This will be discovered during implementation and cause scope creep.**

---

## 3. Parser Extension Gaps

The spec adds fields to `TektonResource` for trigger CRDs but misses several things:

**Missing `runAfter` extraction:** TKN-LOGIC-003 requires runAfter, but neither the spec's parser changes nor the current parser extract it. `PipelineTaskDef` has no `run_after` field. This is a prerequisite for Phase C (Pipeline Logic) that should be called out in Phase A or B's parser changes.

**Repository CRD API group mismatch:** The PaC `Repository` CRD uses `apiVersion: pipelinesascode.tekton.dev/v1alpha1`, not `tekton.dev/v1`. The current parser checks `kind` against `TEKTON_KINDS` but does not validate `apiVersion`. Adding `Repository` to `TEKTON_KINDS` will work, but only because the parser is permissive about apiVersion. If the parser ever tightens apiVersion validation (a common hardening step), Repository CRDs will be silently dropped.

**VerificationPolicy is not in TEKTON_KINDS:** The spec says to scan VerificationPolicy "as raw YAML without special fields." But `_parse_document` (parser.py line 296-298) returns `None` for any `kind` not in `TEKTON_KINDS`. The spec only adds TriggerTemplate, TriggerBinding, EventListener, and Repository to `TEKTON_KINDS`. VerificationPolicy is not added. This means the parser will never yield a TektonResource for VerificationPolicy documents, and CHAIN-005 (unanchored regex) will never see them.

The spec's implementation section mentions "For checks that only need raw YAML access (CHAIN-005, TRUST-006), use `resource.raw` without new dataclass fields." But there will be no `resource` at all because the parser will skip VerificationPolicy documents.

**FLAG: PARSER-GAP - VerificationPolicy is never added to TEKTON_KINDS in the spec, so the parser will silently skip it. TKN-CHAIN-005 and TKN-TRUST-006 cannot work as described. This is a hard blocker for Phase B.**

---

## 4. Test Fixture Realism

The spec claims "~35 new test fixtures across the 16 checks." Here is the reality check:

**Current fixture state:** The test suite has 18 fixture YAML files. None contain TriggerTemplate, TriggerBinding, EventListener, Repository, or VerificationPolicy resources (verified via grep). Every fixture uses PipelineRun, Pipeline, Task, or TaskRun kinds exclusively.

**What 35 fixtures actually requires:**
- TriggerTemplate with resourcetemplates containing PipelineRuns with param interpolation chains (TRIG-004): Need TriggerBinding + TriggerTemplate pair
- EventListener with and without interceptors (TRIG-005): Need valid EventListener YAML
- PaC Repository with various branch configs (TRIG-006): Need Repository CRD YAML
- EventListener with various SA configs (TRIG-007): Need EventListener YAML
- Task with IMAGE_URL/IMAGE_DIGEST results, with and without type hints (CHAIN-003): Need Task YAML (doable with existing patterns)
- Pipeline with security tasks in tasks vs finally (CHAIN-004, LOGIC-001): Need Pipeline YAML (doable)
- VerificationPolicy with anchored and unanchored regex (CHAIN-005): Need VerificationPolicy YAML
- Pipeline with untrusted tasks producing Chains results (CHAIN-006): Need Pipeline + trust evaluation context
- Pipeline with and without SBOM tasks (CHAIN-007): Need Pipeline YAML (doable)
- Pipeline with parallel tasks sharing workspaces (LOGIC-003): Need Pipeline with runAfter dependencies
- Task with overridable security params (LOGIC-002): Need Task YAML (doable)
- Pipeline without finally block (LOGIC-004): Need Pipeline YAML (doable)
- HTTP resolver references with and without digest (TRUST-004): Need PipelineRun/Pipeline YAML (doable)
- Cluster resolver with shared namespace (TRUST-005): Need Pipeline YAML (doable)
- Bundle reference with and without VerificationPolicy coverage (TRUST-006): Need Pipeline + VerificationPolicy pair

The count of ~35 is actually reasonable for 16 checks at 2-3 fixtures each. The concern is not the count but the novelty of the fixture kinds. The team has never written TriggerTemplate, EventListener, Repository, or VerificationPolicy fixtures before. These CRDs have different structural patterns than the familiar PipelineRun/Task shapes. Building accurate, representative fixtures for CRDs you have never used in tests before takes longer than the spec implies.

**FLAG: FIXTURE-RISK - 35 fixtures is plausible in count, but ~12 of them require CRD kinds (TriggerTemplate, EventListener, Repository, VerificationPolicy) that have zero precedent in the current test suite. Budget extra time for getting the YAML structure right, especially for TriggerTemplate resourcetemplates (which embed full PipelineRun specs inside the template).**

---

## 5. Is "28 to 44 Checks" a Vanity Metric?

Yes. Here is why.

**Overlap between proposed checks:**
- TKN-CHAIN-004 and TKN-LOGIC-001 detect the same underlying issue (security-relevant task not in finally block). CHAIN-004 is scoped to "build type" pipelines; LOGIC-001 applies to all pipelines. If both fire on the same pipeline, the user sees two findings for one problem.
- TKN-LOGIC-004 (no finally block) is a strict superset trigger for TKN-CHAIN-004 and TKN-LOGIC-001. If a pipeline has no finally block at all, all three checks fire.
- TKN-TRIG-004 (TriggerTemplate param injection) overlaps with existing TKN-RES-001 (param interpolation in scripts) and TKN-RES-003 (PaC-sourced param taint). The injection chain is TriggerBinding -> TriggerTemplate -> PipelineRun params -> Task scripts. TRIG-004 catches the first hop; RES-001/RES-003 catch the last hop. Without a taint-flow analysis connecting them, you get disconnected partial findings.

**Checks that add minimal value:**
- TKN-LOGIC-004 (no finally block): LOW severity, generic lint. Fires on every single Pipeline that doesn't have a finally block, which is most pipelines. This will be the new TKN-LIMIT-001 (too noisy, immediately disabled).
- TKN-CHAIN-007 (no SBOM task): LOW severity, name-matching heuristic. A pipeline with a task named "generate-materials" that produces CycloneDX output would be missed. A pipeline with a task named "sbom-dummy" that does nothing would pass.
- TKN-LOGIC-002 (overridable param default): The spec itself says "high FP potential" and recommends LOW severity and opt-in. Spec-acknowledged as not production-ready.

**The honest count of HIGH-value, novel, implementable checks is approximately 8:**
1. TKN-TRIG-004 (TriggerTemplate param injection) - genuinely novel, high value
2. TKN-TRIG-006 (PaC Repository branch validation) - novel, high value
3. TKN-CHAIN-005 (VerificationPolicy unanchored regex) - novel, references real CVE
4. TKN-CHAIN-006 (Chains result from untrusted task) - novel but needs arch changes
5. TKN-LOGIC-003 (TOCTOU parallel workspace) - novel but needs arch changes
6. TKN-TRUST-004 (HTTP resolver without digest) - novel, easy to implement
7. TKN-TRUST-005 (cluster resolver shared namespace) - novel, easy to implement
8. TKN-TRUST-006 (bundle without VerificationPolicy) - novel but needs arch changes

5 deep, well-tested checks with proven accuracy would deliver more value than 16 checks where 3 need unspec'd architecture changes, 5 duplicate existing coverage, and 3 are acknowledged as noisy.

**FLAG: VANITY-METRIC - "28 to 44" inflates the headline by counting overlapping checks (CHAIN-004/LOGIC-001/LOGIC-004 triple-fire), opt-in disabled checks (LOGIC-002), and generic lint (LOGIC-004). Effective unique coverage increase is closer to 8-10 checks, not 16.**

---

## 6. Phase Ordering is Wrong

The spec proposes Phase A (Triggers) first. This is suboptimal for three reasons:

**Phase B (Supply Chain) should come first because:**
1. It builds on existing CHAIN-001/CHAIN-002 checks that already work. The data model (TektonResource with results, pipeline_tasks) already supports the required access patterns. CHAIN-003 and CHAIN-004 are straightforward additions to `chains.py`.
2. CHAIN-005 (VerificationPolicy regex) is the check with the strongest external justification (references CVE-2026-25542). Shipping that first provides immediate, demonstrable security value.
3. CHAIN-006 is the check that will surface the architecture problem earliest. Better to discover the inter-check correlation issue in Phase B than to defer it.

**Phase A (Triggers) should be second because:**
1. It requires 4 new CRD kinds in the parser, which is the largest parser change.
2. TriggerTemplate parsing is the most complex addition (nested resourcetemplates containing full PipelineRun specs).
3. The trigger CRD fixtures have zero precedent in the test suite.
4. Starting with the highest-risk parser changes before establishing any new-check patterns is backwards.

**Phase D (Resolver Deep) should come before Phase C (Pipeline Logic) because:**
1. TRUST-004 and TRUST-005 are simple field checks that can be added to the existing trust.py module in an afternoon.
2. Phase C contains LOGIC-003 (TOCTOU), which needs the runAfter parser extraction and dependency graph. This is the hardest single check in the entire spec.

Recommended order: B -> D -> A -> C. Ship the easy wins and CVE-referencing checks first. Save the parser-heavy and architecture-breaking work for last, after the simpler checks have proven the pattern.

**FLAG: PHASE-ORDER - Phase A (triggers) is the riskiest phase due to parser complexity and no fixture precedent. It should not be Phase 1. Recommended: B (supply chain, builds on existing) -> D (resolver, trivial additions) -> A (triggers, parser-heavy) -> C (logic, architecture-breaking).**

---

## 7. Contradictions and Internal Inconsistencies

**TKN-CHAIN-003 type hint check is based on incorrect Tekton Chains behavior:** The spec says "Chains uses type-hinting to identify which results to sign" and that results need `type: string`. In reality, Tekton Chains identifies results to sign based on naming convention (IMAGE_URL, IMAGE_DIGEST) plus the pipeline's type-hinting configuration (`chains.tekton.dev/transparency-upload`, `artifacts.taskrun.format`). The `type: string` field on results is a Tekton API structural requirement, not a Chains-specific type hint. Every result is `type: string` by default in the Tekton v1 API. This check may fire on v1beta1 resources that omit the explicit type field, but for v1 resources, the type is always string. This makes CHAIN-003 a v1beta1-only check with no applicability to current Tekton API versions, which is not disclosed in the spec.

**Security task name heuristics are inconsistent across checks:** TKN-TRIG-003 (existing) uses this list: `["scan", "sign", "verify", "attest", "cosign", "enterprise-contract", "sast", "clair", "clamav"]`. The spec's config section lists: `["scan", "sign", "verify", "attest", "cosign", "enterprise-contract", "sast", "clair", "clamav", "sbom", "syft", "cyclonedx"]`. TKN-CHAIN-004 says "security-relevant name (sign, attest, verify, enterprise-contract)," which is a subset. TKN-CHAIN-007 says "syft, cyclonedx, spdx, or sbom," which is a different subset. TKN-LOGIC-001 says "scan, sign, verify, attest, clair, sast," yet another subset. The config section attempts to unify them, but the check descriptions don't reference the config. Each check will likely hardcode its own list unless the implementer catches this.

**FLAG: NAME-HEURISTIC-DRIFT - Four different checks use four different subsets of security task name patterns. Without enforcing that all checks reference `config.security_task_patterns`, these will diverge further over time and produce inconsistent results on the same pipeline.**

---

## 8. Blind Spots: What the Spec Misses Entirely

**BLIND_SPOT: No check for TriggerBinding credential exposure.** TriggerBindings extract fields from webhook payloads. If a TriggerBinding extracts `$(header.X-Hub-Signature-256)` and passes it as a PipelineRun param, the webhook secret hash flows into the pipeline as a readable parameter. No proposed check detects this.

**BLIND_SPOT: No check for EventListener TLS configuration.** EventListeners expose HTTP endpoints. An EventListener without TLS termination (or relying on in-cluster HTTP) accepts webhooks over plaintext, making signature verification pointless if the payload can be MITM'd in transit. No proposed check addresses this.

**BLIND_SPOT: No check for PaC Repository `incoming` webhook secret strength.** PaC Repository CRDs can specify an incoming webhook secret. There is no check for weak or default secrets, which is a common misconfiguration.

**BLIND_SPOT: Existing codebase bugs from review-final.md are not addressed.** The prior review (review-final.md) identified 13 findings including a HIGH-severity SSRF/path-traversal in resolver.py (Finding 1), a MEDIUM URL normalization bug in config.py (Finding 3), and missing resolver test coverage (Finding 12). The spec proposes 16 new checks without mentioning any of these pre-existing bugs. Adding features on top of known security vulnerabilities in the scanner itself is backwards prioritization.

**BLIND_SPOT: The `--resolve` flag and remote resource fetching are not considered for the new CRD kinds.** The resolver module only handles Pipeline and Task resources via git resolver. TriggerTemplate, EventListener, and Repository CRDs are typically not fetched via git resolvers (they live in-cluster). But VerificationPolicy resources referenced by TKN-TRUST-006 need to be available for cross-referencing. If they are in a different directory or namespace, the scanner will not find them. The spec does not address how VerificationPolicy resources are discovered.

---

## Summary Table

| Flag ID | Severity | Issue |
|---------|----------|-------|
| COMPETITION-CLAIM | HIGH | 5 of 16 checks are not zero-competition |
| ARCH-BREAK | HIGH | 3 checks need unspec'd architecture changes to check runner |
| PARSER-GAP | HIGH | VerificationPolicy missing from TEKTON_KINDS, 2 checks broken |
| VANITY-METRIC | MEDIUM | Effective new coverage is ~8 checks, not 16 |
| PHASE-ORDER | MEDIUM | Phase A is highest-risk, should not be first |
| NAME-HEURISTIC-DRIFT | MEDIUM | 4 checks use 4 different security task name lists |
| FIXTURE-RISK | LOW | 12 fixtures need CRD kinds with zero test precedent |

## Blind Spots

| Blind Spot | Description |
|------------|-------------|
| TriggerBinding credential leakage | No check for webhook secret hashes flowing into pipeline params |
| EventListener TLS | No check for plaintext webhook endpoints |
| PaC incoming secret strength | No check for weak webhook secrets in Repository CRDs |
| Pre-existing scanner bugs | 13 findings from review-final.md unaddressed before adding features |
| VerificationPolicy discovery | No mechanism to find VerificationPolicy resources for cross-referencing |

## Recommendation

Do not ship 16 checks. Ship 8 genuinely novel ones, in order B -> D -> A -> C. Fix the parser gap (add VerificationPolicy to TEKTON_KINDS) before starting Phase B. Address the architecture limitation (inter-resource check correlation) as an explicit prerequisite task, not something discovered mid-implementation. Fix the pre-existing scanner bugs from review-final.md before adding new attack surface to the scanner itself.
