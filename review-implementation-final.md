# Final Implementation Review: 14 New Deeper Checks

**Reviewer**: Adversarial code review agent
**Date**: 2026-06-27
**Scope**: All new check modules, correlation infrastructure, parser extensions, config additions, test fixtures

---

## Finding 1: TKN-CHAIN-004 reports empty URL for hub resolver tasks

**Severity**: LOW (incorrect diagnostic output, not logic bug)
**File**: `/tmp/tekton-guard/tekton_guard/checks/chains.py`, line 111
**Type**: Misleading finding output

**Description**: When `ref.resolver_type == "hub"`, `ref.url` returns `""` (hub resolvers use `catalog`/`name` params, not `url`). The finding message says `"but is from an untrusted source (hub: )"` with an empty string after the colon. This produces a confusing diagnostic.

Compare with how `check_trust_002` handles the same case in `trust.py` line 56: it overrides `url` with `ref.params.get("catalog", "tekton")` for hub resolvers. CHAIN-004 does not.

**Fix**: Add the same hub URL override:
```python
url = ref.url
if ref.resolver_type == "hub":
    url = ref.params.get("catalog", "tekton") or "tekton"
# then use url in the message
```

---

## Finding 2: TKN-CHAIN-003 remediation suggests naive anchoring that breaks valid regex

**Severity**: LOW (misleading remediation, not detection bug)
**File**: `/tmp/tekton-guard/tekton_guard/checks/chains.py`, line 80
**Type**: Incorrect remediation text

**Description**: The remediation says `f"Anchor the pattern: ^{pattern}$"`. If the pattern already has `^` but is missing `$` (partial anchor, like `^quay.io/my-org/` in the fixture), the remediation produces `^^quay.io/my-org/$` with a double `^`. The detection logic is correct (it checks both anchors), but the fix suggestion is wrong for partial-anchor cases.

**Fix**: Construct the remediation conditionally:
```python
suggested = pattern
if not pattern.startswith("^"):
    suggested = "^" + suggested
if not pattern.endswith("$"):
    suggested = suggested + "$"
remediation=f"Anchor the pattern: {suggested}"
```

---

## Finding 3: TKN-LOGIC-003 TOCTOU check only considers direct runAfter, not transitive ordering

**Severity**: MEDIUM (false negatives)
**File**: `/tmp/tekton-guard/tekton_guard/checks/logic.py`, lines 93-97
**Type**: Incomplete analysis / false negative

**Description**: The parallel workspace check only considers direct `runAfter` dependencies. If task A has `runAfter: [B]` and task C has `runAfter: [A]`, then B and C are ordered (B -> A -> C), but the code only checks `t2 in t1_deps or t1 in t2_deps`. Since C's deps contain only `[A]` and B's deps are empty, the code concludes B and C can run in parallel. This is a false positive.

Conversely, consider task X with `runAfter: [Z]` and task Y with `runAfter: [Z]`. These CAN run in parallel (both just wait for Z), and the check correctly does not skip them. So the false positive direction is the problem: tasks with transitive ordering are treated as parallel.

For the test fixture `edge-pipeline-logic.yaml`, the `parallel-untrusted-workspace` pipeline has `clone` and `untrusted-scan` with NO `runAfter` on either, so the test passes correctly. But in real pipelines with chains of 3+ tasks, the check will over-report.

**Fix**: Build transitive closure of `runAfter` dependencies before checking parallelism. Or document this as a known limitation in the check.

---

## Finding 4: TKN-TRUST-006 correlation check uses raw dict output instead of _finding helper

**Severity**: LOW (inconsistent output format)
**File**: `/tmp/tekton-guard/tekton_guard/checks/trust.py`, lines 188-204
**Type**: Inconsistency

**Description**: Every other check in the codebase uses `_finding()` to build the result dict, which guarantees consistent field structure. `check_trust_006` constructs the dict manually. While the fields are functionally correct, this means:
1. If `_finding()` adds new default fields in the future, TRUST-006 won't get them.
2. The `extra` fields (`task_name`, `bundle`) are inlined into the top-level dict instead of being merged via `_finding`'s `extra=` parameter. This works identically at runtime (since `_finding` does `result.update(extra)` anyway), but the code style is inconsistent.

**Fix**: Refactor to use `_finding()` with `extra={"task_name": ..., "bundle": ...}`. This requires the function to accept a `TektonResource`, so pass `r` as the resource argument.

---

## Finding 5: TKN-TRIG-004 scans entire resourcetemplate dict via str() coercion

**Severity**: MEDIUM (false positives)
**File**: `/tmp/tekton-guard/tekton_guard/checks/triggers.py`, lines 137-138
**Type**: False positive risk

**Description**: The check converts the entire resource template dict to a string (`tmpl_str = str(tmpl)`) and then searches for `$(tt.params.*)` patterns in that string representation. Python's `str()` on a dict produces Python repr format, not YAML. This means:
1. It works for detection (if the value exists in the dict, `str()` will include it), but is overly broad.
2. A nested dict key containing the literal string `tt.params` would also match, though this is unlikely in practice.
3. More importantly, the `len(matches)` count in the message could be inflated if the same param appears in multiple nested levels. `str(tmpl)` flattens the entire tree, so a param appearing in both `metadata.name` and `spec.params[0].value` gets counted once per occurrence in the string representation, which may overcount or undercount vs. the YAML structure.

This is not a high-severity issue since it only affects finding quality, not detection correctness. The detection itself is sound: if `$(tt.params.*)` appears anywhere in the template, the finding is legitimate.

**Fix**: Accept as-is with a comment explaining the approach, or walk the dict recursively to find string values containing the pattern for more precise location reporting.

---

## Finding 6: TKN-TRIG-006 Repository check relies on `incoming` field that may not exist in all PaC versions

**Severity**: LOW (potential false positives)
**File**: `/tmp/tekton-guard/tekton_guard/checks/triggers.py`, lines 186-199
**Type**: API version sensitivity

**Description**: The PaC `Repository` CRD's `incoming` field is used for incoming webhook restrictions. However, many PaC repositories restrict branches via the PipelineRun annotations (`on-target-branch`, `on-cel-expression`) rather than via the Repository CR's `incoming` field. The check assumes that a Repository without `incoming` rules means "any branch can trigger" - but in practice, the PipelineRun YAML files in the repo's `.tekton/` directory contain the actual branch filters.

This means any PaC Repository that uses the standard annotation-based filtering (which is the majority) will be flagged as "allows all branches" even though branch filtering exists at the PipelineRun level.

**Fix**: Consider lowering severity to INFO, or document that this check is about the Repository CR's own restrictions (which is a defense-in-depth measure beyond PipelineRun annotations).

---

## Finding 7: Test for TKN-CHAIN-003 partial anchor uses fragile assertion

**Severity**: LOW (test quality)
**File**: `/tmp/tekton-guard/tests/test_deeper_checks.py`, lines 38-41
**Type**: Brittle test

**Description**: `test_partial_anchor_flagged` asserts `len(partial) == 1` where `partial` filters for findings with `"quay.io"` in `f.get("pattern", "")`. Looking at the fixture, the unanchored policy has TWO resource patterns: one fully unanchored (`https://github.com/opendatahub-io/`) and one partially anchored (`^quay.io/my-org/`). The test correctly expects only 1 finding with "quay.io" (the partial anchor). But if someone adds another pattern with "quay.io" to the fixture, the test breaks in a non-obvious way.

Additionally, the first test `test_unanchored_regex_flagged` filters by `"unanchored" in f["resource_name"]` which matches `resource_name == "unanchored-policy"`. The unanchored policy has two patterns that should both trigger, so there should be 2 CHAIN-003 findings for `unanchored-policy` (both patterns lack `$` anchoring). The test only asserts `>= 1`. The fully unanchored pattern (`https://github.com/opendatahub-io/`) lacks both `^` and `$`, and the partial pattern (`^quay.io/my-org/`) lacks `$`. So `unanchored-policy` should produce exactly 2 CHAIN-003 findings, and the test under-asserts.

**Fix**: Assert `len(unanchored) == 2` in `test_unanchored_regex_flagged` to catch both patterns. Use a more specific fixture reference in `test_partial_anchor_flagged`.

---

## Finding 8: No test coverage for TKN-TRUST-006 (correlation check)

**Severity**: MEDIUM (missing test coverage)
**File**: `/tmp/tekton-guard/tests/test_deeper_checks.py`
**Type**: Missing test

**Description**: There are zero tests for `TKN-TRUST-006` (bundle without VerificationPolicy coverage). This is the only correlation check among the 14 new checks, and it has the most complex logic (regex matching bundle refs against VP patterns across multiple resources). It also requires multi-resource fixtures (a VerificationPolicy + a Pipeline with bundle refs in the same scan), which is a different testing pattern from the single-fixture tests.

The check has a notable early-return: if no VerificationPolicy resources exist in the scan, it returns empty (line 165). This is the right behavior, but it's never tested. Neither is the happy path where a bundle IS covered by a VP pattern.

**Fix**: Add a multi-document fixture with:
1. A VerificationPolicy with a pattern covering `quay.io/trusted-org/.*`
2. A Pipeline with a bundle ref to `quay.io/trusted-org/task:v1` (should be clean)
3. A Pipeline with a bundle ref to `quay.io/untrusted-org/task:v1` (should fire)
4. A test with no VerificationPolicy resources (should produce zero findings)

---

## Finding 9: TKN-CHAIN-004 and TKN-TRUST-002 double-fire on the same task

**Severity**: LOW (noise, not bug)
**File**: `/tmp/tekton-guard/tekton_guard/checks/chains.py` lines 86-117, `/tmp/tekton-guard/tekton_guard/checks/trust.py` lines 43-67
**Type**: Overlapping detection

**Description**: A Pipeline task from an untrusted hub source with a build-related name (e.g., `build-image` from hub resolver) triggers BOTH `TKN-TRUST-002` (untrusted source) AND `TKN-CHAIN-004` (chains-consumed result from untrusted task). In the test fixture `edge-chain-deep.yaml`, the `build-image` task from hub resolver fires both checks. This is expected behavior (different risk dimensions), but the overlap should be documented so users understand why the same task appears in two findings.

Looking at the fixture: `build-pipeline` has `build-image` (hub) and `push-container` (untrusted git). Both `build-image` and `push-container` match the name heuristic ("build", "push", "image", "container"). TRUST-002 fires on both. CHAIN-004 also fires on both. That's 4 findings on this one pipeline from these two checks alone, plus CHAIN-005 (no SBOM), LOGIC-001 (no finally), LOGIC-004 (no finally block), PIN-002 (mutable git revision for push-container). High finding density on a single pipeline may overwhelm users.

**Fix**: Consider deduplication guidance in documentation, or group related findings in the report output.

---

## Finding 10: LOGIC-003 TOCTOU check misidentifies workspace name for tasks using workspace binding aliases

**Severity**: MEDIUM (false negatives)
**File**: `/tmp/tekton-guard/tekton_guard/checks/logic.py`, lines 83-84
**Type**: Incorrect workspace correlation

**Description**: The code does `ws_name = ws.workspace or ws.name` to determine which pipeline workspace a task binds to. In Tekton, `workspace` is the pipeline-level workspace name being mapped, and `name` is the task-level workspace name. The `workspace` field is correct for grouping tasks that share the same pipeline workspace. However, if `workspace` is empty (which happens when the task workspace name matches the pipeline workspace name and the binding is implicit), the code falls back to `ws.name`, which is the task-level name.

If two tasks each have a workspace binding with `name: source` but different `workspace` values (or one has `workspace` set and the other doesn't), the fallback to `ws.name` could incorrectly correlate them as sharing the same workspace when they don't.

In the fixture (`edge-pipeline-logic.yaml`), `clone` has `workspace: shared` under its workspace binding, and `untrusted-scan` also has `workspace: shared`. Both explicitly specify the pipeline workspace, so the test passes. But in real-world Tekton manifests where implicit workspace binding is used, this could produce false positives or miss true positives.

**Fix**: Always use `ws.workspace` for pipeline-level correlation. If `ws.workspace` is empty, skip the workspace (it's a task-declared workspace not bound to a pipeline workspace, which means no sharing).

---

## Summary

| # | Finding | Severity | Type |
|---|---------|----------|------|
| 1 | CHAIN-004 shows empty URL for hub resolvers | LOW | Bad diagnostic |
| 2 | CHAIN-003 remediation double-anchors partial patterns | LOW | Bad remediation text |
| 3 | LOGIC-003 TOCTOU only checks direct runAfter, not transitive | MEDIUM | False positives on chains |
| 4 | TRUST-006 uses raw dict instead of _finding helper | LOW | Code inconsistency |
| 5 | TRIG-004 uses str(dict) for template scanning | MEDIUM | Imprecise detection |
| 6 | TRIG-006 Repository check ignores PipelineRun-level branch filters | LOW | False positive risk |
| 7 | Test under-asserts on CHAIN-003 partial anchor count | LOW | Test quality |
| 8 | No tests for TRUST-006 correlation check | MEDIUM | Missing coverage |
| 9 | CHAIN-004 + TRUST-002 double-fire on same task | LOW | Noise |
| 10 | LOGIC-003 workspace alias fallback can misgroup tasks | MEDIUM | False neg/pos risk |

**Verdict**: 0 blocking issues. 3 MEDIUM issues that should be addressed before shipping (findings 3, 8, 10). The remaining LOW findings are quality improvements that can be addressed in a follow-up. The core detection logic for all 14 checks is sound. The correlation check infrastructure in `__init__.py` works correctly.
