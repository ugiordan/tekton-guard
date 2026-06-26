# Review: Deeper Tekton Checks Design Spec (2026-06-27)

**Reviewer**: Security specialist (round 2)
**Spec**: `/tmp/tekton-guard/docs/specs/2026-06-27-deeper-tekton-checks-design.md`
**Scope**: Severity calibration, missing attack vectors, exploitability, false positive risk, architectural feasibility

---

## Finding 1: TKN-TRIG-004 severity is correct at HIGH, but the check as designed cannot actually detect the full attack chain

**Severity**: HIGH (design gap)

**Description**: TKN-TRIG-004 is labeled HIGH for TriggerTemplate param injection, and that severity is appropriate. The real problem is that the check as designed only looks at `$(tt.params.*)` interpolations inside TriggerTemplate `resourcetemplates`, but it does not trace the data flow end-to-end. The spec says "detect params that originate from TriggerBinding fields mapped to webhook body", but the check only looks at the TriggerTemplate in isolation. To confirm that a `$(tt.params.foo)` actually flows from a user-controlled webhook field, you need to:

1. Find the TriggerBinding that maps `$(body.pull_request.title)` to param `foo`
2. Find the EventListener that wires that TriggerBinding to the TriggerTemplate
3. Confirm the param flows into a script or command in the generated PipelineRun

Without cross-resource correlation (TriggerBinding + EventListener + TriggerTemplate), this check will fire on every TriggerTemplate that uses `$(tt.params.*)` in resourcetemplates, regardless of whether the param source is user-controlled. This makes it HIGH false-positive, not HIGH severity.

The current scanner architecture (per the `run_checks` function in `checks/__init__.py`) iterates over individual resources and passes each to every check function. There is no mechanism to correlate multiple resources in a single check invocation. The `run_checks` signature is `check_fn(resource, config)`, one resource at a time.

**Fix**: Either (a) add a cross-resource correlation pass that groups TriggerBinding + TriggerTemplate + EventListener before running TKN-TRIG-004, or (b) downgrade to MEDIUM and document that the check is a heuristic that flags all `$(tt.params.*)` usage without confirming the source. Option (a) requires a new `run_cross_checks(resources, config)` phase similar to how TKN-CHAIN-006 needs cross-referencing. This is a design decision that should be made explicit in the spec.

---

## Finding 2: TKN-CHAIN-007 (missing SBOM) at LOW is correctly calibrated, but TKN-CHAIN-003 at HIGH is wrong

**Severity**: MEDIUM (severity miscalibration)

**Description**: TKN-CHAIN-007 (missing SBOM task) at LOW is fine. SBOM absence is a compliance gap, not a direct security vulnerability. No objection there.

However, TKN-CHAIN-003 (results missing type hint for Chains) is labeled HIGH, which is wrong. The spec claims that Chains uses `type: string` on results to identify which results to sign. This is not how Tekton Chains works. Chains identifies results to sign based on the result name matching specific patterns (`IMAGE_URL`, `IMAGE_DIGEST`, `*_IMAGE_URL`, `*_IMAGE_DIGEST`). The `type` field on a result is a Tekton API field that defaults to `string`. Adding or omitting `type: string` has no effect on Chains behavior because `string` is already the default type. The only type that would matter is `type: object` or `type: array`, which would change the result structure.

This check will produce false positives on every Task with IMAGE_URL/IMAGE_DIGEST results that doesn't explicitly write `type: string`, even though omitting it is functionally identical. That is the vast majority of Tekton Tasks in the wild.

**Fix**: Either remove TKN-CHAIN-003 entirely, or redesign it to check for something that actually affects Chains signing (e.g., a Task that produces results with names that do NOT match the Chains naming convention but should, or a Task that uses `type: object` for image results). If kept, severity should be INFO at most.

---

## Finding 3: TKN-LOGIC-003 (TOCTOU via parallel workspace) is not exploitable as described

**Severity**: HIGH (incorrect threat model)

**Description**: The spec describes a TOCTOU race condition where "two tasks share a workspace and can run in parallel." This needs careful analysis of Tekton's execution model:

1. **Steps within a single Task** share a pod and run sequentially. No parallelism, no race.
2. **Tasks within a Pipeline** run in separate pods. If two tasks share a workspace backed by a PersistentVolumeClaim (PVC), they can potentially run in parallel if there is no `runAfter` dependency. However, PVCs with `ReadWriteOnce` access mode (the default for most storage classes) can only be mounted by one pod at a time. Tekton's PVC handling schedules tasks to the same node using affinity, but the second pod must wait for the first to release the volume.
3. With `ReadWriteMany` PVCs, parallel access is theoretically possible, but Tekton's workspace scheduling still serializes pod starts in many implementations.
4. With `volumeClaimTemplate` (the most common workspace binding in Tekton pipelines), each PipelineRun gets its own PVC, and Tekton serializes access.

The scenario where this is actually exploitable is narrow: `ReadWriteMany` PVC, no `runAfter` dependency, an untrusted task that writes to the workspace while a trusted task reads from it, and the Tekton controller happens to schedule them truly in parallel. In practice, Tekton's `AffinityAssistant` (enabled by default) pins all tasks sharing a PVC to the same node and serializes their execution.

The severity should be LOW or MEDIUM at most, not HIGH. The check itself is still valuable as a defense-in-depth recommendation, but calling it HIGH misrepresents the actual exploitability.

**Fix**: Downgrade TKN-LOGIC-003 to MEDIUM. Add a note in the check description that the race is only possible with `ReadWriteMany` PVCs and when AffinityAssistant is disabled. Consider checking the workspace binding type (PVC vs volumeClaimTemplate) to further reduce false positives.

---

## Finding 4: TKN-CHAIN-005 (VerificationPolicy unanchored regex) references a CVE but the check is still valid post-patch

**Severity**: LOW (documentation issue)

**Description**: The spec references "CVE-2026-25542" as the motivation for TKN-CHAIN-005. Regardless of whether this CVE has been patched in Tekton Pipelines, the check remains valid for two reasons:

1. Users may run older, unpatched versions of Tekton.
2. Even if the Tekton controller now enforces full-match semantics on `resourcePattern`, the VerificationPolicy YAML definition itself is still worth scanning because (a) the YAML represents intent, and an unanchored regex suggests the author may not understand what they're matching, and (b) if the cluster is later downgraded or if the YAML is ported to another cluster with an older version, the unanchored regex becomes exploitable again.

The check is valid. The severity at HIGH is acceptable because a VerificationPolicy bypass directly undermines supply chain trust.

However, the spec should note that post-patch, this is a "defense in depth" check rather than an active vulnerability. The remediation should mention checking the Tekton Pipelines version to determine actual risk.

**Fix**: Add a note to TKN-CHAIN-005 description: "On Tekton Pipelines versions >= X.Y.Z (post CVE-2026-25542 fix), the controller enforces full-match semantics. This check remains valuable as defense-in-depth and for portability across versions." Keep severity at HIGH.

---

## Finding 5: TKN-TRUST-006 (bundle without VerificationPolicy) has a fundamental observability gap

**Severity**: HIGH (design gap)

**Description**: The spec says the check will "cross-reference bundle references with VerificationPolicy resourcePattern rules" from "the scanned files." This is a critical architectural limitation.

VerificationPolicies are namespace-scoped Kubernetes resources. They are almost never stored in the same git repository as the Tekton pipeline definitions. In Konflux and OpenShift Pipelines deployments, VerificationPolicies are:
- Created by cluster administrators via GitOps (a separate infra repo)
- Created by operators (e.g., the Tekton operator deploys default policies)
- Created manually via kubectl

The scanner (per `parser.py` `find_tekton_files`) only scans `.tekton/` directories in git repos. It will almost never find VerificationPolicy resources. This means TKN-TRUST-006 will fire on every bundle reference in every scanned repo, because the scanner will never find a matching VerificationPolicy. This is a 100% false positive rate in practice.

The existing scanner architecture has no mechanism to query a live cluster, accept out-of-band VerificationPolicy files, or maintain a policy inventory.

**Fix**: Three options, from least to most effort:
1. **Disable by default** (like TKN-LIMIT-001). Add to `skip_checks` default list. Users opt in and provide VerificationPolicy files via config.
2. **Add a `verification_policy_files` config option** that accepts a list of paths to VerificationPolicy YAML files outside the scanned repo. The check only runs if this config is provided.
3. **Add a `--policy-dir` CLI flag** that allows scanning a separate directory for VerificationPolicies.

Option 2 is the minimum viable approach. The spec must address this or the check ships broken.

---

## Finding 6: TKN-CHAIN-006 requires cross-resource correlation that the current architecture does not support

**Severity**: HIGH (design gap)

**Description**: TKN-CHAIN-006 says to "cross-reference result-producing tasks with trust status from TKN-TRUST checks." This requires:
1. Running TKN-TRUST-002 on each pipeline task to determine trust status
2. Checking which tasks produce IMAGE_URL/IMAGE_DIGEST results
3. Correlating 1 and 2 within the same Pipeline

The current check architecture calls each check function independently per resource. There is no mechanism for one check to consume the output of another check. The `run_checks` function in `checks/__init__.py` returns a flat list of findings with no inter-check dependency resolution.

TKN-CHAIN-006 cannot simply "cross-reference with TKN-TRUST checks" because it has no access to TKN-TRUST findings. It would need to re-implement the trust determination logic inline.

This is the same architectural limitation as Finding 1 (TKN-TRIG-004). The spec proposes at least 3 checks (TKN-TRIG-004, TKN-CHAIN-006, TKN-TRUST-006) that require cross-resource or cross-check correlation, but never addresses the architectural changes needed.

**Fix**: The spec needs a new section on "Cross-Resource Analysis Architecture." Options:
1. Add a second pass in `run_checks` that receives all resources and all findings from the first pass.
2. Duplicate trust-determination logic inside each check that needs it (simple but violates DRY).
3. Add a shared `TrustOracle` object to `ScannerConfig` that is populated during the first pass and queried by subsequent checks.

Option 3 is cleanest. The spec should define this before implementation starts.

---

## Finding 7: Missing attack vector: PaC incoming webhook secret rotation and theft

**Severity**: MEDIUM (missing coverage)

**Description**: The spec extends coverage to EventListeners and TriggerBindings but misses a critical PaC-specific attack vector. In Pipelines-as-Code, the Repository CRD references a `spec.git_provider.secret` containing the webhook secret and API token. If this secret:
- Has overly broad permissions (GitHub token with `repo` scope instead of minimal scopes)
- Is shared across multiple Repository CRDs
- Is stored in a namespace where pipeline tasks can read secrets

Then a compromised pipeline task can steal the git provider token and use it to push malicious code, create releases, or modify branch protection rules. This is a privilege escalation from "can run pipelines" to "can write to the source repository."

The existing checks (TKN-WS-001, TKN-WS-002) only look at workspace-mounted secrets, not at secrets referenced by Repository CRDs.

**Fix**: Add a new check (e.g., TKN-TRIG-008): "PaC Repository git_provider secret in shared namespace." Detect when a Repository CRD's `spec.git_provider.secret.name` is in a namespace where untrusted pipeline tasks also run. Severity MEDIUM.

---

## Finding 8: Missing attack vector: Step/sidecar image override via PipelineRun params

**Severity**: MEDIUM (missing coverage)

**Description**: The spec adds TKN-LOGIC-002 for overridable security-relevant params (e.g., `--skip-tls-verify`), but misses the more dangerous case: task step images referenced via params.

Many Tekton Tasks define step images as params:
```yaml
params:
  - name: builder-image
    default: registry.redhat.io/ubi8/go-toolset:1.19
steps:
  - image: $(params.builder-image)
```

A PipelineRun caller can override `builder-image` to point to a malicious image. This is a direct code execution vector, more dangerous than toggling a flag. The existing checks (TKN-PIN checks) look at hardcoded image references but do not flag parameterized images that can be overridden by the caller.

**Fix**: Add a check (or extend TKN-LOGIC-002) that detects step images using `$(params.*)` interpolation where the param has no validation. Severity HIGH (this is a code execution vector).

---

## Finding 9: Missing attack vector: `onError: continue` on security-critical steps

**Severity**: MEDIUM (missing coverage)

**Description**: Tekton supports `onError: continue` on individual steps, which causes the step to report success even if the script exits non-zero. If a security scanning step has `onError: continue`, a failed scan will not fail the task, silently passing insecure builds.

This is distinct from TKN-LOGIC-001 (security task not in finally block) and TKN-TRIG-003 (conditional skip). The `onError: continue` pattern is harder to detect from the Pipeline level because it's defined inside the Task spec.

**Fix**: Add a check in the security module that flags any step with `onError: continue` in a task with a security-relevant name. Severity MEDIUM.

---

## Finding 10: TKN-TRIG-006 (PaC Repository allows all branches) will have high false positive rate

**Severity**: MEDIUM (false positive risk)

**Description**: TKN-TRIG-006 checks PaC Repository CRDs for branch restrictions. However, many legitimate Repository CRDs intentionally allow all branches because they use per-branch `.tekton/` PipelineRun definitions with `on-target-branch` annotations for access control. The Repository CRD itself is not where branch filtering happens in PaC. Branch filtering happens at the PipelineRun level via PaC annotations.

Firing HIGH on every Repository CRD without branch restrictions will produce false positives on the majority of PaC deployments. The existing TKN-TRIG-002 check already catches the PipelineRun-level branch filtering gap.

**Fix**: Downgrade TKN-TRIG-006 to MEDIUM. Add a condition: only fire if the Repository CRD's namespace contains PipelineRuns without `on-target-branch` annotations. Alternatively, make this an INFO-level best-practice recommendation rather than a HIGH security finding.

---

## Finding 11: TKN-LOGIC-002 self-contradicts on severity

**Severity**: LOW (spec inconsistency)

**Description**: TKN-LOGIC-002 is initially listed as MEDIUM severity in the check definition, then the "note" at the bottom says "Revised severity: LOW" and recommends opt-in. The spec contradicts itself on the same page. The note also says "this check has high FP potential" but the check is still being added to the registered count (44 checks total).

The check count math is also inconsistent: the spec says "TKN-LOGIC-002 registered but opt-in (disabled by default in skip_checks, same as TKN-LIMIT-001)" but the expected count says "43 registered" implying one disabled. The text says 44 total but 43 registered, which is correct if TKN-LOGIC-002 is disabled. But the first count says "28 + 16 = 44" without clarifying.

**Fix**: Pick one severity (LOW is correct given FP risk), state it once, and clarify the registered vs. active count. The spec should say: "44 total checks, 42 active by default (TKN-LIMIT-001 and TKN-LOGIC-002 disabled)."

---

## Finding 12: TKN-CHAIN-004 (build pipeline without finally signing block) has naming-based heuristic problems

**Severity**: MEDIUM (false positive risk)

**Description**: TKN-CHAIN-004 and TKN-LOGIC-001 both use the `security_task_patterns` name list to identify security-relevant tasks. This list includes generic terms like "scan", "sign", and "verify". Common false positive scenarios:

- A task named `sign-off-review` (not a cryptographic signing task)
- A task named `verify-deployment` (verifying a deployment is live, not signature verification)
- A task named `scan-resources` (scanning for resource availability, not vulnerability scanning)

The spec acknowledges this risk for TKN-LOGIC-002 but not for TKN-CHAIN-004 or TKN-LOGIC-001, which use the same heuristic at MEDIUM severity.

**Fix**: Add a `taskRef` name check in addition to the task name check. If the task references a known security tool bundle (e.g., `quay.io/redhat-appstudio/build-definitions` tasks like `clair-scan`, `sast-snyk-check`), elevate confidence. If only the task name matches, lower confidence. Consider adding a confidence field to findings.

---

## Finding 13: Missing attack vector: `securityContext` escalation in inline taskSpecs

**Severity**: MEDIUM (missing coverage)

**Description**: The spec focuses on pipeline execution flow and trigger surfaces but does not add checks for `securityContext` escalation in the newly-supported inline `taskSpec` within TriggerTemplate `resourcetemplates`. A TriggerTemplate can embed a full PipelineRun with inline task specs that include `privileged: true`, `hostPID: true`, or capabilities like `SYS_ADMIN`. Since the existing security context checks (in `security.py`) only run on parsed TektonResources, and TriggerTemplate resourcetemplates are embedded PipelineRuns that need to be extracted and parsed separately, the existing checks will miss these.

**Fix**: When parsing TriggerTemplate `resourcetemplates`, extract embedded PipelineRun/TaskRun specs and parse them as additional TektonResources. Apply all existing checks to these extracted resources. This should be specified in the parser extensions section.

---

## Summary

| # | Category | Severity | Summary |
|---|----------|----------|---------|
| 1 | Design gap | HIGH | TKN-TRIG-004 cannot trace data flow without cross-resource correlation |
| 2 | Miscalibration | MEDIUM | TKN-CHAIN-003 misunderstands Chains type-hint behavior, will FP heavily |
| 3 | Threat model | HIGH | TKN-LOGIC-003 TOCTOU not exploitable with default AffinityAssistant |
| 4 | Documentation | LOW | TKN-CHAIN-005 valid post-patch, needs version context |
| 5 | Design gap | HIGH | TKN-TRUST-006 will have ~100% FP rate without VerificationPolicy input mechanism |
| 6 | Design gap | HIGH | TKN-CHAIN-006 needs cross-check correlation architecture |
| 7 | Missing vector | MEDIUM | PaC Repository git_provider secret theft |
| 8 | Missing vector | MEDIUM | Parameterized step images overridable by PipelineRun caller |
| 9 | Missing vector | MEDIUM | `onError: continue` on security-critical steps |
| 10 | FP risk | MEDIUM | TKN-TRIG-006 will FP on standard PaC deployments |
| 11 | Spec quality | LOW | TKN-LOGIC-002 severity self-contradicts |
| 12 | FP risk | MEDIUM | Name-based security task heuristic too broad |
| 13 | Missing vector | MEDIUM | Inline taskSpecs in TriggerTemplate resourcetemplates bypass existing checks |
