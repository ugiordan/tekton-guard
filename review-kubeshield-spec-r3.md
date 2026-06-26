# Red Team Review: kube-shield Rename and Scope Expansion

**Reviewer**: Red Team Audit (Claude Opus 4.6)
**Date**: 2026-06-26
**Verdict**: DO NOT PROCEED AS SPECIFIED. The spec has fundamental strategic problems.

---

## 1. Scope Creep: Yes, This Tool Is Trying to Do Too Much

**Assessment: CRITICAL RISK**

The current tekton-guard is a focused, high-quality tool. 28 checks, 136 tests, CWE mappings, auto-fix with SHA resolution, cross-repo dependency graphs, blast radius scoring, PR creation, baseline management, stale pin detection. This is not a toy. It has real depth.

The spec proposes adding 23 new checks across 4 new parser modules (Helm, Kustomize, ArgoCD, generic K8s). That is an 82% increase in check count and a 5x increase in attack surface to parse and analyze. For a single developer.

Here is why that is dangerous.

### The architecture is NOT generic

The spec claims: "only the parser and checks are Tekton-specific." This is false. I read every source file. The coupling runs deeper than the spec acknowledges:

- `TektonResource` dataclass has 17 fields, 12 of which are Tekton-specific (pipeline_ref, task_ref, pipeline_tasks, finally_tasks, steps, sidecars, results, etc.). The proposed `Resource` generalization would need to either (a) carry all these as optional fields creating a god-object, or (b) use a discriminated union/protocol which is a significant refactor.
- `collect_all_containers()` in `_common.py` walks Tekton-specific structures (pipeline_tasks, finally_tasks, steps, sidecars). Helm charts do not have this structure. ArgoCD Applications do not have steps.
- The fixer has Tekton-specific logic (line searching for `value:` patterns near resolver refs, workspace readonly insertion). None of this transfers to Helm/Kustomize.
- The graph module assumes git resolver references between repos. Helm charts use `dependencies:` in Chart.yaml. Kustomize uses `resources:` with URLs. ArgoCD uses `spec.source.repoURL`. Each needs its own graph extraction logic.
- The resolver module follows Tekton git resolver URLs specifically. Helm dependency resolution is a completely different protocol (Helm repo index.yaml, OCI registries).

The spec underestimates the refactoring cost. The "common Resource object" handwave hides a significant design challenge.

### kube-chainsaw is separate for a reason

The user already split RBAC analysis into kube-chainsaw as a separate tool. Why? Because RBAC graph analysis is a different problem domain. The exact same argument applies to Helm chart analysis and Kustomize overlay analysis. These are different problem domains that happen to share the abstract concept of "supply chain integrity."

A Helm chart security problem (unpinned dependency, template injection) requires Helm-specific knowledge: Go template semantics, `.Values` interpolation behavior, sub-chart override mechanics, `helm template` rendering quirks. The person writing HLM-INJ-001 needs to understand that `{{ .Values.name | quote }}` is safe but `{{ .Values.name }}` in a shell context is not. This is Helm expertise, not generic K8s expertise.

### Recommendation

Keep tekton-guard as tekton-guard. If Helm scanning is needed, create kube-shield-helm (or helm-guard). The "one tool to rule them all" approach will produce shallow checks that get outcompeted by specialized tools.

---

## 2. Market Positioning: kube-shield Does Not Differentiate

**Assessment: CRITICAL RISK**

The spec does not acknowledge that the proposed Helm, Kustomize, and generic K8s checks are already covered by mature, well-funded tools:

| Proposed Check | Already Done By | Maturity |
|---|---|---|
| HLM-PIN-001 (unpinned chart dep) | Checkov CKV2_HELM_1 | Production |
| HLM-PIN-002/003 (mutable image tag) | Trivy, Checkov, kube-linter | Production |
| HLM-TRUST-001 (untrusted repo) | Checkov | Production |
| HLM-SECRET-001 (plaintext secrets) | Checkov, gitleaks, truffleHog | Production |
| KST-PIN-001 (remote base without SHA) | Checkov, KICS | Production |
| KST-PATCH-001 (priv escalation patch) | Checkov, kube-linter | Production |
| AGO-SYNC-001/002 (sync policy) | Checkov CKV_ARGO_* | Production |
| AGO-NS-001 (dangerous namespace) | Checkov, OPA/Gatekeeper | Production |
| K8S-SEC-001/002 (privileged, root) | Trivy, Checkov, kube-linter, Kubescape, OPA | Production |
| K8S-IMG-001 (mutable image) | Trivy, Checkov, kube-linter | Production |

The only check that has no direct equivalent is HLM-INJ-001 (unsafe .Values interpolation in shell commands). That is exactly one novel check out of 23 proposed.

tekton-guard's current value proposition is unassailable: "the only security scanner for Tekton pipeline definitions." The spec throws away this monopoly position to compete in a crowded market where Checkov alone has 3000+ checks and a full-time team.

### The "supply chain integrity" framing is misleading

The spec positions kube-shield as "static security analysis for Kubernetes supply chain definitions." Let me be specific about what the proposed checks actually analyze:

- HLM-PIN-002 (mutable image tag in values.yaml): This is image tag linting. Trivy does this.
- HLM-SECRET-001 (plaintext secrets in values.yaml): This is secret scanning. truffleHog does this.
- HLM-SECRET-002 (missing encryption annotation): This is resource configuration linting. kube-linter does this.
- KST-PATCH-001 (privileged securityContext in patch): This is security context linting. Checkov does this.
- AGO-NS-001 (namespace is kube-system): This is namespace policy enforcement. OPA does this.
- K8S-SEC-001/002 (privileged, root): This is container security linting. Every tool does this.

Only a subset of the proposed checks genuinely analyze supply chain integrity (the PIN-* and TRUST-* families). The rest are generic security linting dressed up with a "supply chain" label. That is positioning, not differentiation.

---

## 3. The "Supply Chain Integrity" Claim: Partially Real, Partially Marketing

**Assessment: MEDIUM RISK**

The supply chain integrity claim is legitimate for some checks and misleading for others.

### Genuinely supply-chain-focused (10 of 23)

- HLM-PIN-001 (unpinned chart dependency): Real supply chain risk. A compromised upstream chart repo can inject malicious templates.
- HLM-PIN-002/003 (mutable image tags): Borderline. Image tag mutability is a supply chain concern, but it is also generic container hygiene.
- HLM-TRUST-001 (untrusted Helm repo): Real supply chain risk.
- KST-PIN-001 (remote base without SHA): Real supply chain risk. Exactly the Kustomize equivalent of TKN-PIN-001.
- KST-TRUST-001 (untrusted remote base): Real supply chain risk.
- AGO-PIN-001 (unpinned targetRevision): Real supply chain risk.
- AGO-TRUST-001 (untrusted repo): Real supply chain risk.

### Generic security linting repackaged as supply chain (13 of 23)

- HLM-INJ-001: Template injection is real, but it is an input validation bug, not a supply chain integrity violation.
- HLM-SECRET-001/002: Secret management, not supply chain.
- KST-PATCH-001: Privilege escalation, not supply chain.
- AGO-SYNC-001/002: GitOps operational policy, not supply chain. Auto-sync without prune protection is a misconfiguration, not a supply chain attack vector.
- AGO-NS-001: Namespace policy, not supply chain.
- K8S-SEC-001/002, K8S-VOL-001/002: Container security context, not supply chain.
- K8S-SECRET-001: Secret in ConfigMap, not supply chain.
- K8S-IMG-001: Image pinning, borderline (same as HLM-PIN-002/003).

### The honest framing

If kube-shield is supposed to be about supply chain integrity, then strip out the generic security linting checks (K8S-SEC-*, K8S-VOL-*, *-SECRET-*, AGO-SYNC-*, AGO-NS-*, KST-PATCH-001). That leaves ~10 genuinely supply-chain-focused checks. But then the check count drops and the tool looks thin compared to the Tekton-only version.

---

## 4. Execution Risk: Unrealistic for One Developer

**Assessment: HIGH RISK**

### Scope estimate

The spec proposes 5 phases. Here is a realistic effort estimate for each:

| Phase | What | Realistic Effort |
|---|---|---|
| Phase 1 (Rename) | Package rename, CLI rename, alias system, doc update, GH Action update | 2-3 days |
| Phase 2 (Helm) | Helm parser (Chart.yaml, values.yaml, helm template), 7 checks, tests against real charts | 3-4 weeks |
| Phase 3 (Kustomize) | Kustomize parser (kustomization.yaml, remote bases, images transformer), 4 checks | 2 weeks |
| Phase 4 (ArgoCD) | ArgoCD Application CRD parser, 5 checks | 1-2 weeks |
| Phase 5 (Generic K8s) | Generic manifest parser, 6 checks | 1-2 weeks |

Total: ~8-11 weeks of focused work, assuming no surprises. That does not include:
- Extending the fixer for Helm/Kustomize/ArgoCD (the current fixer is deeply Tekton-specific)
- Extending the graph module for non-Tekton dependency tracking
- Extending the resolver module for Helm repo resolution
- Writing tests (the current codebase has ~136 tests; maintaining that ratio means ~100+ new tests)
- Handling edge cases (malformed Chart.yaml, nested Kustomize overlays, ArgoCD ApplicationSets vs Applications, Helm hooks, Kustomize components)
- Integration testing against real-world repos

### What gets sacrificed

While building kube-shield, no work happens on tekton-guard. The current Tekton scanner has obvious gaps that could be filled instead:

- **TektonTrigger/EventListener scanning**: The current tool does not parse Tekton Trigger CRDs (EventListener, TriggerBinding, TriggerTemplate). These are attack surfaces for webhook-based pipeline injection. TKN-TRIG-001/002 only check PipelineRun annotations for PaC-style triggers, not native Tekton Triggers.
- **Tekton Results integration**: No checks for result type-confusion attacks (where a task declares a string result but a consumer treats it as a URL/path).
- **Pipeline-as-Code Repository CRD scanning**: PaC Repository objects define webhook-to-pipeline bindings and have their own security surface.
- **ClusterTask deprecation checks**: Tekton deprecated ClusterTask in v1. No check flags continued usage.
- **Tekton Custom Task (Run/CustomRun) scanning**: Custom tasks can invoke arbitrary controllers.
- **SLSA provenance validation**: The current TKN-CHAIN-001/002 checks are shallow (annotation presence only). Real provenance validation would verify that result types match what Chains expects.
- **OCI bundle content inspection**: TKN-PIN-003 checks if a bundle has a digest pin, but does not inspect what is inside the bundle.

Going deep on Tekton, where you are the only player, is the higher-value move. Every one of those gaps would produce checks that no other tool can deliver.

### The competitive argument

tekton-guard with 40 Tekton-specific checks and auto-fix is a monopoly product. kube-shield with 51 checks across 5 source types competes with Checkov (3000+ checks), Trivy (thousands of checks), and Kubescape (200+ controls). Which one gets adopted?

---

## 5. Name Collision: "kube-shield" Is Likely Taken

**Assessment: MEDIUM RISK**

I cannot perform a live search to verify, but "kube-shield" follows an extremely common naming pattern in the Kubernetes ecosystem ("kube-" prefix). Projects with similar names:

- "kubeshield" is a GitHub organization (github.com/kubeshield) associated with the guard project (appscode/guard) for Kubernetes authentication webhook.
- Search PyPI, npm, and GitHub for "kube-shield" before committing to this name.

More importantly, "kube-shield" is generic and says nothing about supply chain security. It sounds like a network policy tool or a pod security admission controller. "tekton-guard" immediately communicates what it does and what it protects.

If a rename is pursued despite the above objections, consider names that preserve the supply chain focus:
- `kube-chain-guard` (references supply chain)
- `k8s-supply-scan` (explicit about supply chain scanning)
- `manifest-pin` (references the core pinning/immutability concern)

But honestly: keep the name. "tekton-guard" has an established identity and zero competition for mindshare.

---

## 6. Contradictions and Gaps in the Spec

### The scope boundary table is wrong

The spec's scope table claims:

> | Privileged containers, hostPath mounts | Yes (generic) | Yes (generic) | No |

This means kube-shield would overlap with kube-linter on generic container security. The spec also says:

> "It does not replicate kube-linter's resource hygiene checks"

But K8S-SEC-001 (privileged container) and K8S-SEC-002 (root user) are exactly what kube-linter checks. The scope table and the narrative contradict each other.

### Helm parser requires external CLI

The spec says: "The Helm parser needs `helm` CLI available (or a Go library)." But tekton-guard is a Python tool. There is no Go library option. The choices are:

1. Shell out to `helm template` (adds a binary dependency, potential RCE if a malicious chart has hooks)
2. Parse `.tpl` files as text (regex-based, misses complex Go template logic, high false positive rate)
3. Use a Python Helm library (none are mature or well-maintained)

The spec does not address option 1's security implications: running `helm template` on an untrusted chart executes template functions. This is a sandbox concern for a security tool.

### Auto-fix is not addressed

The current fixer handles TKN-PIN-001/002/003/004/005 and TKN-WS-001. The spec proposes analogous checks for Helm/Kustomize/ArgoCD (HLM-PIN-001, KST-PIN-001, AGO-PIN-001) but says nothing about fixing them. If kube-shield cannot auto-fix Helm pins, it is strictly less useful than tekton-guard in its domain.

### No mention of ArgoCD ApplicationSet

The spec only mentions ArgoCD `Application` CRDs. In production, many teams use `ApplicationSet` with generators (git generator, cluster generator, list generator). The git generator creates Applications dynamically from directory structure. This is a significant attack surface that the spec does not mention.

### No mention of Helm hooks

Helm hooks (`helm.sh/hook`) run during install/upgrade/delete and can execute arbitrary containers. A pre-install hook with a mutable image is an injection vector. The proposed checks do not cover hooks.

---

## 7. Strategic Recommendation

### Do this instead

1. **Keep tekton-guard as tekton-guard.** Do not rename.
2. **Go deeper on Tekton.** Add the checks listed in Section 4 (TektonTrigger, CustomRun, SLSA provenance, bundle content inspection). Get to 40+ Tekton-specific checks. No other tool can compete here.
3. **If Helm/Kustomize scanning is needed for RHOAI**, write a separate thin tool (or contribute checks to Checkov, which accepts external check contributions). Do not bloat the Tekton scanner.
4. **If a "kube-shield" umbrella is desired**, make it a meta-tool that runs tekton-guard + kube-linter + kube-chainsaw + checkov and aggregates results. This is an orchestrator, not a new scanner.

### The one exception

If there is a concrete, immediate need to scan odh-gitops Helm charts for supply chain pinning issues AND Checkov/Trivy genuinely do not cover the specific checks needed, then build a standalone `helm-guard` tool with only the supply chain checks (HLM-PIN-001, HLM-TRUST-001, and HLM-INJ-001). Three checks, one parser, small scope, high value. Do not bundle it with the Tekton scanner.

---

## Summary of Flags

```
FLAG: SCOPE_CREEP - 23 new checks across 4 new parser modules for a single developer is unrealistic
FLAG: MARKET_OVERLAP - 22 of 23 proposed non-Tekton checks are already covered by Checkov/Trivy/kube-linter
FLAG: SUPPLY_CHAIN_CLAIM - 13 of 23 proposed checks are generic security linting, not supply chain integrity
FLAG: ARCHITECTURE_UNDERESTIMATE - TektonResource dataclass, fixer, graph, and resolver all have deep Tekton coupling that the spec handwaves
FLAG: HELM_TEMPLATE_RCE - Running helm template on untrusted charts is a security risk the spec does not address
FLAG: SCOPE_TABLE_CONTRADICTION - Spec claims no overlap with kube-linter but K8S-SEC-001/002 are exactly kube-linter checks
FLAG: MISSING_ARGOCD_APPSET - ApplicationSet generators are a major attack surface not mentioned
FLAG: MISSING_HELM_HOOKS - Helm hooks are an injection vector not covered by proposed checks
FLAG: AUTO_FIX_GAP - Spec does not address auto-fix for any non-Tekton checks
FLAG: NAME_COLLISION - "kube-shield"/"kubeshield" is a common pattern with existing projects in the Kubernetes ecosystem
BLIND_SPOT: Existing Tekton-specific gaps (TektonTrigger CRDs, CustomRun, SLSA result validation, bundle content inspection) would produce higher-value, zero-competition checks
BLIND_SPOT: No competitive analysis in the spec; competitor check coverage is not acknowledged
BLIND_SPOT: Python Helm template parsing has no mature library path; the spec does not evaluate this constraint
```
