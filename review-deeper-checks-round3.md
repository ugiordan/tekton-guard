# Adversarial Review Round 3: Deeper Tekton Checks Design Spec

**Reviewer**: Adversarial code review specialist
**Date**: 2026-06-27
**Scope**: Final round after 45 findings addressed across R1/R2. Find remaining genuine issues.
**Source**: `/tmp/tekton-guard/docs/specs/2026-06-27-deeper-tekton-checks-design.md`

---

## Finding 1: `--policy-dir` with `parse_directory` will find zero files because `find_tekton_files` requires `.tekton/` path components

**Severity**: HIGH
**Category**: Implementation blocker (inadequate fix for R2-F8)

**Description**:

Lines 203-205 specify the `--policy-dir` implementation:

> cli.py calls `parse_directory(policy_dir)` separately and appends the results to the resource list before running checks.

Line 202 also says:

> The `find_tekton_files` function is NOT modified.

These two statements are contradictory. `parse_directory` (parser.py line 413-418) calls `find_tekton_files`. `find_tekton_files` (parser.py lines 388-410) only returns YAML files that are inside a `.tekton/` directory. Specifically:

- If `root/.tekton` is a directory, it globs from there (line 396-402).
- Otherwise, it only returns files where `.tekton` appears in the path parts (lines 404-409).

A typical policy directory like `/path/to/verification-policies/` contains flat YAML files with no `.tekton` subdirectory. Calling `parse_directory("/path/to/verification-policies/")` will return an empty list because `find_tekton_files` will find nothing.

The Round 2 resolution appendix (line 250) says "Added section specifying separate parse_directory call for policy files." But the added section just restates the approach without addressing the fundamental incompatibility. The spec needs either:

1. A new function (e.g., `parse_yaml_directory`) that globs all YAML/YML files without the `.tekton/` constraint, or
2. Modification to `find_tekton_files` with a `scan_all_yaml=True` parameter, or
3. Direct `parse_file` calls on each YAML file in the policy directory from `cli.py`.

Without this fix, TRUST-006 (the only correlation check) will never see VerificationPolicy resources from `--policy-dir`, making the feature dead on arrival.

---

## Finding 2: Per-resource vs. correlation count is wrong (13+1, not 12+2)

**Severity**: MEDIUM
**Category**: Spec arithmetic error

**Description**:

Line 210 states: "New: 14 checks (12 per-resource + 2 correlation)"

Counting per-resource checks from the spec:
- TRIG-004, 005, 006, 007: 4 per-resource (lines 78, 85, 91, 97)
- CHAIN-003, 004, 005: 3 per-resource (lines 108, 114, 120)
- LOGIC-001, 002, 003, 004: 4 per-resource (lines 129, 136, 143, 150)
- TRUST-004, 005: 2 per-resource (lines 158, 164)

Total per-resource: 4 + 3 + 4 + 2 = 13

Counting correlation checks:
- TRUST-006: 1 correlation (line 170)

Total: 13 + 1 = 14. Correct total, wrong breakdown.

The "2 correlation" number appears to be a leftover from before CHAIN-004 was reclassified as per-resource (R2-F2 resolution on line 246). The breakdown was never updated after that reclassification.

This also cascades into the "39 registered" claim on line 211. With 28 existing + 14 new = 42 total, and 2 disabled by default (LIMIT-001, LOGIC-002), there are 40 active checks. The "3 disabled" claim on line 211 counts "correlation checks without policy data" as disabled, but silently skipping due to missing input data is not the same as being disabled via `skip_checks`. All 42 checks are registered; 40 are in the default active set.

**Fix**: Correct line 210 to "14 checks (13 per-resource + 1 correlation)". Correct line 211 to "42 checks (42 registered, 40 active by default: LIMIT-001 and LOGIC-002 in skip_checks)".

---

## Finding 3: Architecture section references stale check IDs that have been renumbered

**Severity**: LOW
**Category**: Spec inconsistency

**Description**:

Line 19-20 in the "Cross-resource correlation" section says:

> Three new checks (CHAIN-006, LOGIC-003, TRUST-006) need to see multiple resources simultaneously.

"CHAIN-006" no longer exists. It was renumbered to CHAIN-004 (line 114: "renumbered from CHAIN-006") and then reclassified as a per-resource check (line 117-118). LOGIC-003 was also reclassified as per-resource (line 148).

After all reclassifications, only TRUST-006 needs to see multiple resources. The architecture section's motivating statement ("three new checks need correlation") overstates the need for the correlation infrastructure by 3x. The infrastructure is still valuable for future expansion, but the justification text is stale.

**Fix**: Update line 19-20 to reflect that only TRUST-006 currently requires correlation, with the framework designed for future checks.

---

## Finding 4: Correlation checks cannot use the `_finding` helper without adaptation

**Severity**: LOW
**Category**: Design gap

**Description**:

The `_finding` helper function in `_common.py` (lines 40-67) has this signature:

```python
def _finding(rule_id, severity, title, resource: TektonResource, line, message, ...)
```

It uses `resource.file_path`, `resource.kind`, and `resource.name` to populate the finding dict. Correlation checks operate on `list[TektonResource]` and may produce findings that reference multiple resources (e.g., TRUST-006 correlates a bundle reference in one file with VerificationPolicy patterns from another file).

The spec's correlation check code (lines 41-53) calls `check_fn(resources, config)` and iterates the returned dicts, but never specifies how correlation checks construct findings. They can't use `_finding` without picking one resource as the "primary." They would need to construct finding dicts manually or the spec should define a `_correlation_finding` helper that accepts multiple resources.

This is a minor design gap. Correlation check authors will figure it out during implementation. But since the spec includes the `_finding` helper pattern as the standard, it should note that correlation checks construct findings differently.

---

## Summary

| # | Severity | Category | Summary |
|---|----------|----------|---------|
| 1 | HIGH | Implementation blocker | `parse_directory(policy_dir)` returns empty because `find_tekton_files` requires `.tekton/` paths. TRUST-006 cannot receive policy data. |
| 2 | MEDIUM | Arithmetic error | Per-resource/correlation split is 13+1, not 12+2. "39 registered" count is also wrong (should be 42 registered, 40 active). |
| 3 | LOW | Stale references | Architecture section still says "CHAIN-006" and claims 3 checks need correlation. Only TRUST-006 does. |
| 4 | LOW | Design gap | Correlation checks cannot use `_finding` helper without picking a primary resource. |

**Bottom line**: The spec is in good shape after 2 rounds of fixes. Finding 1 is the only actionable blocker: the `--policy-dir` implementation approach literally cannot work with the current `parse_directory`/`find_tekton_files` code without either modifying `find_tekton_files` or adding a new file-discovery function. The R2-F8 resolution acknowledged the gap but the spec text still says "The `find_tekton_files` function is NOT modified" while relying on it to find files it structurally cannot find. Findings 2-4 are spec quality issues that should be cleaned up before implementation but won't block it.
