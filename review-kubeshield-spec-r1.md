# kube-shield Rename and Scope Expansion Design Spec Review (R1)

**Reviewer**: Adversarial Architecture Review
**Date**: 2026-06-26
**Spec**: `docs/specs/2026-06-26-kube-shield-rename-design.md`
**Code baseline**: tekton-guard current codebase (28 checks, parser.py, checks/, cli.py, fixer.py, config.py, formatter.py)

---

## Finding 1: TektonResource dataclass does not generalize to a common Resource

**Severity**: HIGH
**Category**: Architecture
**Location**: Spec "Parser modules" section, current `parser.py` lines 93-119

**What's wrong**: The spec says "Each parser produces a common Resource object (generalized from TektonResource) that checks operate on. Tekton-specific fields remain but are optional." This is hand-waved. Looking at the actual `TektonResource` dataclass, it has 15+ Tekton-specific fields (`pipeline_ref`, `task_ref`, `pipeline_tasks`, `finally_tasks`, `service_account`, `steps`, `sidecars`, `results`, `workspaces`, `params`). The supporting data structures (`ResolverRef`, `StepDef`, `TaskRefDef`, `PipelineTaskDef`, `WorkspaceBinding`) are all Tekton-domain objects.

A Helm chart has none of these. An ArgoCD Application has none of these. Making all of these "optional" creates a God Object where every parser populates a different subset of fields, checks need to know which fields to expect for which source type, and type safety is effectively lost. The `collect_all_containers()` helper in `_common.py` (line 77-96) hardcodes kind checks against `Task`, `StepAction`, `TaskRun`, `Pipeline`, `PipelineRun`. Every new source type would need similar dispatching.

**Recommendation**: Define a lean `Resource` base with truly common fields (`kind`, `api_version`, `name`, `namespace`, `file_path`, `line_offset`, `labels`, `annotations`, `raw`, `containers: list[ContainerSpec]`, `images: list[ImageRef]`, `volumes: list[VolumeSpec]`). Then use composition, not inheritance: `TektonResource` wraps `Resource` and adds `pipeline_ref`, `task_ref`, etc. Helm checks receive `HelmResource` with `dependencies`, `values`, `rendered_manifests`. ArgoCD checks receive `ArgoCDResource` with `source`, `sync_policy`, `destination`. Checks declare which resource type they operate on via the `@register_check` decorator (e.g., `@register_check(resource_type=TektonResource)`). The K8S-* checks operate on the base `Resource` type and fire for all source types.

---

## Finding 2: Scope boundary between kube-shield and kube-linter has a confirmed overlap on privileged containers / hostPath

**Severity**: MEDIUM
**Category**: Scope
**Location**: Spec "Identity and Scope" table, row "Privileged containers, hostPath mounts"

**What's wrong**: The scope table explicitly shows "Yes (generic)" for both kube-shield and kube-linter on "Privileged containers, hostPath mounts." The spec acknowledges the overlap but does not explain why both tools should check the same thing, or how users avoid duplicate findings when running both tools in the same CI pipeline. This is the exact kind of ambiguity that makes users question whether they need both tools.

**Recommendation**: Pick a lane. Option A: kube-shield checks these only in the context of supply chain attack paths (e.g., "privileged container + hostPath that mounts runtime socket = container escape during build"), and defers generic runtime security posture checks to kube-linter. Option B: kube-shield checks these universally and kube-linter is told to skip them via a shared exclusion config. Either way, document the deconfliction strategy. If both tools will fire, provide a `--skip-linter-overlap` flag or a config option that disables the overlapping K8S-SEC-* and K8S-VOL-* checks.

---

## Finding 3: Check prefix convention creates a combinatorial problem for cross-cutting checks

**Severity**: MEDIUM
**Category**: Design
**Location**: Spec "Check prefix convention" and "Existing checks migration" sections

**What's wrong**: The prefix scheme (TKN-, HLM-, KST-, AGO-, K8S-) ties check identity to source type. But the spec also says "TKN-SEC-001/002 and TKN-VOL-001/002 become aliases for K8S-SEC-001/002 and K8S-VOL-001/002 (fire on any K8s manifest, not just Tekton)." This means the same check fires under two different IDs depending on the source type. Baseline files, SARIF reports, and skip_checks config all key on rule_id. Users who baseline TKN-SEC-001 will get the same finding again as K8S-SEC-001. Users who skip K8S-SEC-001 still get TKN-SEC-001.

Beyond that, mutable image tags (currently TKN-PIN-004) will need to fire on Helm rendered templates (HLM-PIN-003), Kustomize images (KST-PIN-002), and generic K8s manifests (K8S-IMG-001). That is four different rule IDs for the same underlying check logic. The formatter's `_category_from_rule()` function (line 12-25) parses the second segment of the rule ID to determine category. It will need to handle HLM, KST, AGO prefixes, and each new source type introduces new prefix-to-category mappings.

**Recommendation**: Use a two-level scheme. The check ID encodes the concern, not the source: `PIN-001` (mutable ref), `SEC-001` (privileged container), etc. The source type is metadata on the finding, not part of the ID. If you must keep source prefixes for human readability, make them display-only (not the canonical ID used for baselines and skip_checks). The current `_finding()` helper already has `resource_kind` as a field. Extend it with `source_type` and use that for filtering.

---

## Finding 4: `helm template` dependency creates CI portability and security issues

**Severity**: HIGH
**Category**: Portability / Security
**Location**: Spec "Helm Parser Design" section

**What's wrong**: The spec says the Helm parser needs the `helm` CLI and calls `helm template` to render templates. Three problems.

First, portability. Not every CI environment has `helm` installed, and the spec's fallback ("skip step 3") means the tool silently skips HLM-PIN-003 and HLM-INJ-001 (the injection check, which is the most valuable Helm-specific check). Users won't know they're getting incomplete coverage.

Second, security. `helm template` executes template functions including `lookup` (which queries a live cluster if available) and can pull dependencies from arbitrary Helm repos. Running `helm template` on untrusted chart input is a code execution risk. This contradicts kube-shield's identity as a static analysis tool.

Third, reproducibility. `helm template` output depends on the Helm version, the values file used, and whether dependencies are already pulled (`helm dependency build`). The spec does not specify how values files are selected or whether `helm dependency update` is run first.

**Recommendation**: For HLM-INJ-001 (injection detection), parse `.tpl` files directly with a regex/AST approach instead of rendering. The spec already mentions this as "optional" (step 4), but it should be the primary approach. For HLM-PIN-003 (mutable images in rendered output), offer `helm template` as an opt-in mode (`--helm-render`) with clear documentation that it requires the `helm` CLI and that it executes template logic. Default mode should be pure static analysis: parse Chart.yaml, values.yaml, and template files without rendering. Always emit a warning (not silent skip) when `helm` is unavailable and rendering would have been needed.

---

## Finding 5: Kustomize parser design omits `components:`, `helmCharts:`, `generators:`, and `configMapGenerator/secretGenerator`

**Severity**: MEDIUM
**Category**: Completeness
**Location**: Spec "Kustomize Parser Design" section

**What's wrong**: The spec covers `resources:`, `images:`, and `patchesStrategicMerge:`. But Kustomize has several other features with supply chain security implications that are not mentioned:

1. `components:` can reference remote URLs just like `resources:`, so KST-PIN-001 and KST-TRUST-001 need to cover them.
2. `helmCharts:` (built-in Kustomize Helm support) allows embedding Helm chart references with mutable versions. This is a cross-cutting concern between Helm and Kustomize.
3. `generators:` / `configMapGenerator:` / `secretGenerator:` can reference files or literal values that contain secrets.
4. `patchesJson6902:` can modify securityContext just like strategicMerge patches.
5. `replacements:` (Kustomize v5) can override image fields.
6. `openapi:` customization can alter merge key behavior in surprising ways.

**Recommendation**: At minimum, add `components:` to KST-PIN-001 and KST-TRUST-001 scope. Add KST-SECRET-001 for secrets in generators. Add KST-PATCH-002 for JSON6902 patches that modify securityContext. Document `helmCharts:` as a phase 3 stretch goal or explain that it's covered by the Helm parser when detected.

---

## Finding 6: ArgoCD checks miss several critical security concerns

**Severity**: MEDIUM
**Category**: Completeness
**Location**: Spec "ArgoCD (AGO-*)" check table

**What's wrong**: The ArgoCD checks cover pinning, trust, sync policy, and destination namespace. Missing checks with real supply chain impact:

1. **AGO-RBAC-001**: ArgoCD Application with `spec.project: default`. The default AppProject has no restrictions on destinations, sources, or cluster resources. This is the most common ArgoCD misconfiguration.
2. **AGO-SYNC-003**: `spec.syncPolicy.syncOptions` containing `CreateNamespace=true`. This allows ArgoCD to create arbitrary namespaces, which is a privilege escalation vector.
3. **AGO-SYNC-004**: `spec.syncPolicy.syncOptions` containing `Replace=true` or `ServerSideApply=true`. Replace mode deletes and recreates resources, which can cause downtime and bypass admission controllers.
4. **AGO-HELM-001**: `spec.source.helm.values` or `spec.source.helm.valuesObject` inline. Secrets or mutable image refs in inline Helm values.
5. **AGO-MULTI-001**: `spec.sources` (multi-source Application) where one source is untrusted. This is the ArgoCD equivalent of the shared workspace attack.

**Recommendation**: Add AGO-RBAC-001 (default project, HIGH) and AGO-SYNC-003 (CreateNamespace, MEDIUM) at minimum. These are the most commonly exploited ArgoCD misconfigurations. The others can be stretch goals for Phase 4.

---

## Finding 7: Phase dependency chain is underspecified and Phase 1 is not purely mechanical

**Severity**: MEDIUM
**Category**: Migration Plan
**Location**: Spec "Migration Path" section

**What's wrong**: The phases are listed but their dependencies and blockers are not explicit. Issues:

Phase 1 says "Rename package, CLI, repo" and "Promote SEC/VOL to K8S-* (keep TKN-* as aliases)." The promotion to K8S-* is not just a rename. It requires the common Resource type from Finding 1 to be in place, because K8S-SEC-001 needs to fire on any K8s manifest (not just Tekton CRDs). But the current `check_sec_001` function calls `collect_all_containers()` which hardcodes Tekton kind checks. So Phase 1 actually depends on the Resource generalization, which is a major refactor, not a rename.

Phase 5 (Generic K8s) says "Full scan of any K8s YAML directory." This changes the file discovery logic fundamentally. Currently `find_tekton_files()` only returns files in `.tekton/` directories. Scanning all YAML files in a repo will produce massive noise (every ConfigMap, Service, Namespace YAML will be scanned). The spec does not discuss filtering, scope limiting, or performance implications.

**Recommendation**: Split Phase 1 into 1a (pure rename: package, CLI, repo, docs, GitHub Action, no logic changes) and 1b (Resource generalization + K8S-* promotion). Make 1b a prerequisite for Phases 2-5. For Phase 5, define the file discovery strategy. Options: require `--type k8s` flag (no auto-detection for generic manifests), limit to known deployment directories, or scan all YAML but only fire HIGH+ checks. Document the expected finding volume increase and how users should manage it.

---

## Finding 8: Fixer engine and auto-fix PR workflow are hardcoded for Tekton and will break

**Severity**: HIGH
**Category**: Architecture
**Location**: `fixer.py` (entire file), `cli.py` lines 17-52

**What's wrong**: The fix engine (`FixEngine.fix_findings`) has a hardcoded rule ID dispatch table: `TKN-PIN-001`, `TKN-PIN-002`, `TKN-PIN-005`, `TKN-WS-001`, `TKN-PIN-003`, `TKN-PIN-004`. The auto-fix PR function creates branches named `tekton-guard/auto-pin-*`, commit messages referencing "tekton-guard --fix", and PR bodies saying "tekton-guard auto-fix." The User-Agent header in `_resolve_git_sha` and `_resolve_image_digest` is `tekton-guard/1.1`.

The spec does not mention updating the fixer at all. When HLM-PIN-001, KST-PIN-001, and AGO-PIN-001 are added, they will all be classified as "skipped (manual_review_required)" by the fixer. The Helm chart dependency pinning fix (resolve chart version to digest or exact version) requires completely different resolution logic than git SHA resolution.

**Recommendation**: Add a "Fixer Migration" section to the spec. At minimum: rename branch prefix to `kube-shield/`, update all User-Agent strings, update PR body references. For new checks, define which are auto-fixable. HLM-PIN-002/003 (image pinning) can reuse the existing `_resolve_image_digest()` logic. KST-PIN-002 (image transformer pinning) similarly. But HLM-PIN-001 (chart dependency version pinning) and AGO-PIN-001 (targetRevision pinning) need new resolution logic. Make the fixer dispatch extensible (register fix strategies per rule ID pattern rather than hardcoding).

---

## Finding 9: Config (ScannerConfig) needs new trust list types but the spec does not define them

**Severity**: MEDIUM
**Category**: Design
**Location**: Spec "Compatibility" section (last line: "new fields for Helm repos, Kustomize bases trust lists"), current `config.py`

**What's wrong**: The spec mentions "new fields for Helm repos, Kustomize bases trust lists" in a single line under Compatibility. But the existing config has very specific trust-checking methods (`is_trusted_git_source`, `is_trusted_registry`) that are called directly by check functions. New trust checks need:

- `trusted_helm_repos` (for HLM-TRUST-001)
- `trusted_kustomize_bases` (for KST-TRUST-001) 
- `trusted_argocd_repos` (for AGO-TRUST-001)

The question is whether `trusted_git_sources` should also cover ArgoCD repos and Kustomize remote bases (since they're all git URLs), or whether each source type has its own trust list. The spec does not clarify this, and getting it wrong means users have to duplicate trust config across multiple lists.

**Recommendation**: Define a unified `trusted_sources` list that applies to all git-based references (Tekton git resolvers, Kustomize remote bases, ArgoCD repo URLs) and a separate `trusted_helm_repos` list specifically for Helm chart repository URLs (which are not git URLs but OCI/HTTP repos). Document this in the spec. Update `is_trusted_git_source()` to be generic (rename to `is_trusted_source()`) and add `is_trusted_helm_repo()`.

---

## Finding 10: Formatter is hardcoded for tekton-guard and needs rename coordination

**Severity**: LOW
**Category**: Completeness
**Location**: `formatter.py` lines 37, 39, 97-98, 110

**What's wrong**: The formatter has hardcoded strings: `"scanner": "tekton-guard"` in JSON output, `"name": "tekton-guard"` in SARIF output, `"informationUri": "https://github.com/opendatahub-io/tekton-guard"` in SARIF, and `"Tekton Security Scan"` in text output. The `_category_from_rule()` function only handles TKN-* prefix segments (PIN, TRUST, SA, WS, RES, CHAIN, SEC, VOL, TRIG, LIMIT, EXFIL). It will return "unknown" for all HLM-*, KST-*, AGO-*, and K8S-* checks.

**Recommendation**: This is straightforward but easy to miss. Add it to Phase 1 checklist: update all scanner name strings to "kube-shield", update informationUri to new repo URL, update text output header to "kube-shield Security Scan". Extend `_category_from_rule()` to handle new prefixes or switch to a check-metadata-based category lookup.

---

## Finding 11: Auto-detection heuristics have ambiguity and false-positive risk

**Severity**: MEDIUM
**Category**: Design
**Location**: Spec "Source type auto-detection" table

**What's wrong**: The auto-detection table lists five patterns but does not define priority or conflict resolution:

1. A repo can have `.tekton/*.yaml` AND `Chart.yaml` AND `kustomization.yaml` AND ArgoCD Application manifests all at once. The spec does not say whether all are scanned (union) or only one (first match).
2. "ArgoCD Application kind" requires reading the YAML to check `kind: Application`, while all other checks are filesystem-based. This creates an inconsistency: a file could be detected as "Generic K8s" first, then on parsing turn out to be an ArgoCD Application.
3. "Other K8s YAML" matches literally everything. Without scoping (e.g., excluding `vendor/`, `test/`, `node_modules/`), this will scan test fixtures, example files, and documentation snippets.

**Recommendation**: Make auto-detection a union (scan all detected source types). Define the priority order for individual file classification: if a YAML file contains `kind: Application` with `apiVersion: argoproj.io/*`, it's ArgoCD. If it contains a Tekton kind, it's Tekton. Otherwise it's generic K8s. Add a `--exclude` flag for directory patterns and default-exclude common non-deployment directories. Document this decision.

---

## Finding 12: HLM-INJ-001 (template injection) detection approach is vague and likely high false-positive

**Severity**: MEDIUM
**Category**: Completeness
**Location**: Spec "New Checks" Helm table, HLM-INJ-001

**What's wrong**: HLM-INJ-001 is described as detecting "Unsafe `.Values` interpolation in templates (e.g., `{{ .Values.name }}` in shell commands without `quote`)." This is conceptually correct but extremely hard to implement with low false positives. Nearly every Helm template uses `{{ .Values.* }}` interpolation. The check needs to distinguish between:

- Safe: `{{ .Values.name | quote }}` in a label
- Safe: `{{ .Values.replicas }}` in a numeric field
- Dangerous: `{{ .Values.command }}` in a container command/args
- Dangerous: `{{ .Values.script }}` in a ConfigMap that gets mounted as a script

The spec does not define the detection heuristic. Without careful scoping, this check will fire on every `.Values` reference and be immediately disabled by users.

**Recommendation**: Scope HLM-INJ-001 to specific dangerous contexts only: `.Values.*` interpolation inside `command:`, `args:`, `script:`, `lifecycle:` hooks, and `initContainers:` fields, specifically where the value is not piped through `quote`, `squote`, or `toYaml`. Document that this is a heuristic and may require baseline entries for legitimate uses. Consider splitting into HLM-INJ-001 (command/args injection, HIGH) and HLM-INJ-002 (unquoted interpolation in other contexts, LOW).

---

## Finding 13: Backward compatibility for baseline files is not fully achievable with aliases

**Severity**: MEDIUM
**Category**: Compatibility
**Location**: Spec "Compatibility" section

**What's wrong**: The spec says "Baseline files from tekton-guard work in kube-shield" and "All TKN-* rule IDs are stable." But the spec also says TKN-SEC-001 becomes an alias for K8S-SEC-001. If the tool starts emitting K8S-SEC-001 as the canonical rule_id for findings that were previously TKN-SEC-001, existing baselines keyed on TKN-SEC-001 will not suppress the K8S-SEC-001 findings. The baseline matching logic in `cli.py` (lines 251-259) uses `(rule_id, file, content_hash)` as the dedup key. Changing the rule_id breaks the match.

The spec also does not address the config file compatibility. If `skip_checks: [TKN-SEC-001]` is in `.tekton-guard.yaml`, does the new tool also skip K8S-SEC-001? The current `should_run_check()` does an exact match on check_id.

**Recommendation**: For the alias mechanism to work, the baseline and skip_checks matching logic must resolve aliases bidirectionally. When checking baselines, expand both the finding's rule_id and the baseline entry's rule_id through the alias map before comparing. When checking skip_checks, expand aliases before matching. Define the alias map explicitly in the spec and code (e.g., `ALIASES = {"TKN-SEC-001": "K8S-SEC-001", "TKN-SEC-002": "K8S-SEC-002", "TKN-VOL-001": "K8S-VOL-001", "TKN-VOL-002": "K8S-VOL-002"}`). Test this specifically in the migration test suite.

---

## Finding 14: HLM-SECRET-002 (encryption-at-rest annotation) is poorly defined and not actionable

**Severity**: LOW
**Category**: Design
**Location**: Spec "New Checks" Helm table, HLM-SECRET-002

**What's wrong**: HLM-SECRET-002 detects "Secret resource without encryption-at-rest annotation." There is no standard Kubernetes annotation for encryption-at-rest. Kubernetes encryption at rest is configured at the API server level (`EncryptionConfiguration`), not via annotations on individual Secret resources. Some tools like Sealed Secrets or SOPS use their own annotations, but these are implementation-specific.

Checking for a non-standard annotation will either always fire (useless) or require users to configure which annotation to look for (complexity for minimal value).

**Recommendation**: Replace HLM-SECRET-002 with a more actionable check: HLM-SECRET-002 "Plaintext Secret in Helm template (not SealedSecret/ExternalSecret)." Detect `kind: Secret` resources in Helm templates that are not `kind: SealedSecret` or `kind: ExternalSecret`, indicating the secret value will be committed to the chart or values file in base64 (not encrypted). This is a genuine supply chain risk.

---

## Finding 15: No plan for test fixture expansion or integration testing across source types

**Severity**: LOW
**Category**: Test Plan
**Location**: Spec overall (no test section)

**What's wrong**: The current test suite has 136 tests, all against Tekton fixtures in `tests/fixtures/`. The spec proposes 22 new checks across 4 source types but does not mention test fixtures, integration tests, or a test plan. Testing Helm checks requires Helm chart structures, Kustomize checks require kustomization.yaml structures, and ArgoCD checks require Application manifests. The spec mentions "Test against odh-gitops charts/" for Helm but nothing for the other types.

**Recommendation**: Add a test plan section to the spec. For each phase, define: (1) unit test fixtures to create, (2) at least one real-world integration target (odh-gitops for Helm, kubeflow manifests for Kustomize, an ArgoCD-managed repo for ArgoCD), (3) expected false positive rate targets. This is especially important for HLM-INJ-001 and the auto-detection logic, which are high FP risk.

---

## Summary

| # | Severity | Finding |
|---|----------|---------|
| 1 | HIGH | TektonResource is a God Object that cannot generalize cleanly |
| 2 | MEDIUM | Explicit scope overlap with kube-linter on privileged/hostPath |
| 3 | MEDIUM | Check prefix convention creates alias/baseline nightmares |
| 4 | HIGH | `helm template` creates portability, security, and reproducibility problems |
| 5 | MEDIUM | Kustomize parser omits components, generators, JSON6902 patches |
| 6 | MEDIUM | ArgoCD checks miss default project, CreateNamespace, multi-source |
| 7 | MEDIUM | Phase dependencies underspecified, Phase 1 is not purely mechanical |
| 8 | HIGH | Fixer engine completely hardcoded for Tekton, not mentioned in spec |
| 9 | MEDIUM | Trust list config for new source types undefined |
| 10 | LOW | Formatter hardcoded for tekton-guard name and TKN-* prefixes |
| 11 | MEDIUM | Auto-detection has ambiguity, no conflict resolution, no exclusion |
| 12 | MEDIUM | HLM-INJ-001 injection detection will be high false-positive |
| 13 | MEDIUM | Baseline backward compatibility breaks when aliases change rule_id |
| 14 | LOW | HLM-SECRET-002 checks for non-existent annotation standard |
| 15 | LOW | No test plan for 22 new checks across 4 source types |

**HIGH findings (3)**: The Resource generalization (1), helm template dependency (4), and fixer omission (8) are architectural blockers. Each will cause rework if not addressed before implementation starts.

**MEDIUM findings (9)**: The check prefix design (3), Kustomize/ArgoCD completeness gaps (5, 6), phase dependencies (7), config trust lists (9), auto-detection ambiguity (11), injection FP risk (12), and baseline compatibility (13) are all design decisions that need explicit answers in the spec before coding.
