# Adversarial Review Round 2: Deeper Tekton Checks Design Spec

**Reviewer**: Adversarial code review specialist
**Date**: 2026-06-27
**Scope**: Verify Round 1 fixes are adequate, find remaining issues
**Source**: `/tmp/tekton-guard/docs/specs/2026-06-27-deeper-tekton-checks-design.md`
**Prior findings**: 37 across R1 (12), R2 (13), R3 (7 flags + 5 blind spots)

---

## Finding 1: CorrelationCheckFn is defined but `run_checks` is not updated to call it

**Severity**: HIGH
**Category**: Design gap (inadequate fix)
**Original**: R1-F3, R1-F4, R2-F1, R2-F6, R3-ARCH-BREAK

**Description**:

The spec adds `CorrelationCheckFn`, `_CORRELATION_REGISTRY`, and `register_correlation_check` (lines 26-31), then states: "The `run_checks` function runs per-resource checks first, then correlation checks over the full resource list."

But the spec never shows the actual `run_checks` modification. The current `run_checks` in `checks/__init__.py` (lines 37-61) iterates `for resource in resources: for check_fn in all_checks:` using only `_REGISTRY` via `get_all_checks()`. There is no code path that invokes `_CORRELATION_REGISTRY`.

The fix requires `run_checks` to:
1. Import or access `_CORRELATION_REGISTRY` from `_common.py`
2. After the per-resource loop, iterate `for corr_fn in _CORRELATION_REGISTRY: corr_fn(resources, config)`
3. Apply the same dedup, severity filtering, and `should_run_check` logic to correlation findings

This is not just "additive" as claimed. The dedup logic (line 55: `dedup_key = (f["rule_id"], f["file"], ...)`) uses `f["file"]`, but correlation checks produce findings that may reference multiple files or a Pipeline resource that contains references to tasks in other files. The dedup key design may silently drop valid correlation findings.

Additionally, `_CORRELATION_REGISTRY` is defined in the spec's code snippet but is never connected to `get_all_checks()` or any export from `_common.py`. The `checks/__init__.py` module only calls `get_all_checks()`, which returns `list(_REGISTRY)`. A new `get_correlation_checks()` function is needed but not specified.

**What the spec should add**: The concrete `run_checks` modification, including how correlation check findings are deduplicated and how check IDs are extracted (correlation checks don't have `__doc__` following the same `"TKN-XXX: description"` pattern since they may produce multiple finding types).

---

## Finding 2: CHAIN-004 (result from untrusted task) says "correlation check" but only needs single-Pipeline data

**Severity**: MEDIUM
**Category**: Design inconsistency

**Description**:

TKN-CHAIN-004 (line 94-96) is labeled as a "correlation check (needs all resources)" with the rationale: "For each Pipeline, find tasks with IMAGE_URL/IMAGE_DIGEST in results, check trust status of their taskRef."

But this analysis operates on a single Pipeline resource. The Pipeline's `pipeline_tasks` already contain `task_ref` with resolver information. The `config.is_trusted_git_source()` function can determine trust status directly from the taskRef's resolver URL. No cross-resource correlation is needed.

The only case where correlation is genuinely needed is when the Task definition is referenced by name (not inline) and the check needs to inspect the Task's `results` field to confirm it produces IMAGE_URL/IMAGE_DIGEST. But the spec already acknowledges this limitation: "only feasible when the Task definition is available (inline taskSpec or via --resolve). When the Task is remote and not resolved, the check is skipped with an INFO note."

For inline taskSpecs, the results are already in `pt.steps` / embedded taskSpec data within the Pipeline resource. For resolved remote Tasks, they are separate `TektonResource` objects. The spec should clarify: if the Task is resolved via `--resolve`, CHAIN-004 needs to correlate the Pipeline with the resolved Task resources. That is a genuine correlation need. But if the Task is inline or the check only looks at the taskRef trust status (not the result names), it can be a per-resource check.

The current classification as a correlation check forces CHAIN-004 into the `_CORRELATION_REGISTRY`, which means it runs in a second pass. If most users don't use `--resolve`, this check will mostly emit "skipped" INFO notes. Alternatively, implement the trust-status-only check as a per-resource check (flag untrusted taskRefs in Pipelines that are build-type) and reserve the result-name verification for the correlation pass.

---

## Finding 3: Config additions (`shared_namespaces`, `security_task_patterns`) are not loaded by `load_config`

**Severity**: MEDIUM
**Category**: Implementation gap

**Description**:

The spec adds two new config fields (lines 157-175):
- `shared_namespaces` (used by TKN-TRUST-005)
- `security_task_patterns` (used by TKN-TRIG-003, TKN-LOGIC-001, TKN-CHAIN-005)

The current `ScannerConfig` dataclass (config.py lines 13-55) and `load_config` function (lines 58-82) have no knowledge of these fields. `load_config` only processes `trusted_git_sources`, `trusted_registries`, `skip_checks`, `min_severity`, and `known_safe_secret_workspaces`. New fields in the YAML config file will be silently ignored.

The spec lists these as "Config additions" but does not mention that `ScannerConfig.__init__`, `load_config`, and the `should_run_check` logic need updating. This is not a complex change, but it is a prerequisite for 4 checks (TRUST-005, TRIG-003 centralization, LOGIC-001, CHAIN-005) and should be called out as a required change.

Additionally, the spec says TKN-TRIG-003 already exists and will use the centralized `security_task_patterns` config (line 177). But the current TKN-TRIG-003 implementation (triggers.py lines 92-93) hardcodes its own pattern list: `["scan", "sign", "verify", "attest", "cosign", "enterprise-contract", "sast", "clair", "clamav"]`. Migrating TKN-TRIG-003 to use `config.security_task_patterns` is a change to an existing check, not just a new check addition. The spec should flag this as a modification to an existing check during Phase A or B.

---

## Finding 4: TRIG-004 (TriggerTemplate param injection) is classified as per-resource but describes cross-resource logic in prose

**Severity**: MEDIUM
**Category**: Spec inconsistency

**Description**:

Line 57-58 says: "These params originate from TriggerBinding webhook body fields, enabling code injection via crafted webhook payloads."

Line 60 says: "Implementation: per-resource check on TriggerTemplate kind, scan `raw["spec"]["resourcetemplates"]` for `$(tt.params.*)` patterns"

The first sentence implies the check traces data flow through TriggerBindings (cross-resource). The second sentence describes a single-resource pattern match. Round 1 identified this contradiction (R1-F4, R2-F1). The resolution appendix (line 198) says "Added `CorrelationCheckFn` type", but TRIG-004 is not listed as a correlation check. It is listed as "per-resource check on TriggerTemplate kind."

The fix from Round 1 addressed the architecture gap generically but did not resolve the specific contradiction within TRIG-004's description. The description still claims the check detects params that "originate from TriggerBinding webhook body fields" when the implementation only detects `$(tt.params.*)` usage in resourcetemplates. These are different things.

The description should be revised to match the implementation: "Detect TriggerTemplate `resourcetemplates` containing `$(tt.params.*)` interpolations in PipelineRun scripts or commands. Any TriggerTemplate param used in a script is a potential injection vector because TriggerBindings typically map from user-controlled webhook body fields." This makes it clear the check is a heuristic that does not confirm the binding source.

---

## Finding 5: Expected check count math has an error

**Severity**: LOW
**Category**: Spec inconsistency

**Description**:

Line 181-183 states:
- Existing: 28 checks (27 registered + 1 disabled TKN-LIMIT-001)
- New: 14 checks (12 per-resource + 2 correlation)
- Total: 42 checks (39 registered, 3 disabled by default: LIMIT-001, LOGIC-002, and correlation checks without policy data)

The math: 27 registered + 12 new per-resource + 2 new correlation = 41 registered. Not 39. If LOGIC-002 is disabled, that is 40 active. If the 2 correlation checks are "disabled without policy data," that is 38 active. But 39 registered means 42 total minus 3 disabled = 39, which implies 3 checks are "not registered." But disabled-by-default checks (in `skip_checks`) are still registered in `_REGISTRY`; they are just skipped by `should_run_check`. The correlation checks without policy data are described as "skipped silently" (line 153), not disabled via `skip_checks`.

The spec conflates three different concepts:
1. Registered (in `_REGISTRY` or `_CORRELATION_REGISTRY`)
2. Active by default (not in `skip_checks`)
3. Silently skipped at runtime (correlation checks that find no data to correlate)

All 42 checks should be registered. 40 are active by default (LIMIT-001 and LOGIC-002 in `skip_checks`). Some may produce zero findings at runtime depending on input data. The count "39 registered" is wrong.

---

## Finding 6: Phase B includes correlation check infrastructure, but the first correlation check (CHAIN-004) needs resolved Task data

**Severity**: MEDIUM
**Category**: Phase dependency gap

**Description**:

Line 187 says Phase B includes "CHAIN-003..005 + VerificationPolicy in TEKTON_KINDS + correlation check infrastructure."

CHAIN-004 (result poisoning) is a correlation check. But Phase B is before Phase D (resolver deep, which includes TRUST-004..006 and `--policy-dir`). CHAIN-004's description says it needs to "check trust status of their taskRef" and is "only feasible when the Task definition is available (inline taskSpec or via --resolve)."

The `--resolve` flag already exists (cli.py line 119-123), so resolved Task resources are available. But CHAIN-004 needs to find the resolved Task resource that corresponds to a Pipeline task's `taskRef`. This lookup requires iterating all resources to find a Task whose name/source matches the Pipeline task's `taskRef`. This is the correlation part.

The issue is that Phase B builds the correlation infrastructure and ships CHAIN-004 together. This means Phase B is both building the framework and shipping the first consumer, with no intermediate testing of the framework in isolation. If the framework has bugs, they will be discovered while trying to get CHAIN-004 working. Better to split: build the correlation infrastructure as a standalone change in Phase B, then ship CHAIN-004 as the first consumer.

This is a planning concern, not a blocker.

---

## Finding 7: LOGIC-003 (TOCTOU) is listed as per-resource but needs trust status from other resources

**Severity**: MEDIUM
**Category**: Spec inconsistency

**Description**:

Line 126 says LOGIC-003 detects: "Pipeline tasks sharing a workspace that can run in parallel (no `runAfter` between them) where at least one is untrusted."

Line 127-128 says: "Implementation: per-resource check on Pipeline kind (has all task data within one resource)"

The parenthetical "(has all task data within one resource)" is only true for workspace and runAfter data. The trust determination requires checking `pt.task_ref.resolver.url` against `config.is_trusted_git_source()`, which IS available per-resource (the taskRef is embedded in the Pipeline). So the trust logic can be inlined without cross-resource correlation.

However, the round 1 findings (R1-F3, R2-F6) specifically flagged that LOGIC-003 needs "trust status from TRUST check results." The resolution appendix (line 198) says this was addressed by adding CorrelationCheckFn. But LOGIC-003 is not classified as a correlation check. The resolution is inconsistent: the appendix says the architecture gap was fixed for checks that need cross-resource data, but LOGIC-003 is listed as per-resource.

If LOGIC-003 uses `config.is_trusted_git_source()` directly (duplicating the trust logic from TKN-TRUST checks), this should be stated explicitly. The R3 reviewer's recommendation was "duplicate trust logic as tech debt." The spec implicitly does this by marking LOGIC-003 as per-resource, but never acknowledges the duplication or its implications (if trust logic evolves in TRUST checks, LOGIC-003 won't pick up the changes).

---

## Finding 8: `--policy-dir` flag interaction with `find_tekton_files` is unspecified

**Severity**: MEDIUM
**Category**: Implementation gap

**Description**:

Line 49 says: "Add `--policy-dir` CLI flag for specifying a directory containing VerificationPolicy YAML files."

The current `find_tekton_files` function (parser.py lines 388-410) only scans `.tekton/` directories. The `main` function in cli.py calls either `parse_file` or `parse_directory`, both of which use `find_tekton_files`.

The `--policy-dir` flag requires a separate code path:
1. `parse_directory(args.policy_dir)` to find and parse VerificationPolicy files from the policy directory
2. These parsed resources must be added to the main `resources` list before `run_checks` is called
3. But `find_tekton_files` will not find them unless the policy directory contains a `.tekton/` subdirectory (unlikely for cluster policy files)

The spec should specify that `--policy-dir` uses direct YAML globbing (not `find_tekton_files`) and that the parsed resources are merged into the main resource list. Alternatively, `find_tekton_files` could be extended with a `scan_all=True` mode that globs all YAML files regardless of directory structure.

This is not a design flaw, but it's an implementation detail that will cause confusion during Phase D if not documented.

---

## Resolutions adequacy summary

| Round 1 Finding | Resolution | Adequate? |
|----------------|------------|-----------|
| R1-F1: God Object | Use raw dict for new CRDs | YES. Clean solution. |
| R1-F2: Missing runAfter | Added `run_after: list[str]` to PipelineTaskDef | YES. Correct fix. |
| R1-F3: No inter-check data sharing | Added CorrelationCheckFn | PARTIAL. Type defined but run_checks not updated (Finding 1 above). |
| R1-F4: TRIG-004 cross-resource | Reduced to per-resource heuristic + CorrelationCheckFn | PARTIAL. Description still claims cross-resource behavior (Finding 4 above). |
| R1-F5: CHAIN-003 wrong behavior | Removed. | YES. Correct removal. |
| R1-F6: CVE reference | Kept with defense-in-depth note | YES. Reasonable. |
| R1-F7: TRUST-006 needs external files | Added --policy-dir | YES, concept is correct. Implementation gap remains (Finding 8 above). |
| R1-F8: LOGIC-002 FP risk | Disabled by default, LOW severity | YES. |
| R1-F9: TRIG-005 infra auth | Acknowledged as static analysis limitation | YES. |
| R1-F10: TRIG-007 SA permissions | Renamed focus to default/missing SA | YES. |
| R1-F11: _parse_document gating | Added new kinds to TEKTON_KINDS | YES. |
| R1-F12: Phase ordering | Reordered B->D->A->C | YES. |
| R2-F2: CHAIN-003 miscalibration | Removed | YES. |
| R2-F3: LOGIC-003 severity | Lowered to MEDIUM | YES. |
| R2-F10: TRIG-006 FP | Lowered to MEDIUM | YES. |
| R2-F11: LOGIC-002 self-contradiction | Fixed to LOW, disabled | YES. |
| R3-COMPETITION-CLAIM | Acknowledged, kept with pre-deploy justification | YES. Reasonable trade-off. |
| R3-PARSER-GAP | Added VerificationPolicy to TEKTON_KINDS | YES. |
| R3-VANITY-METRIC | Reduced from 16 to 14 checks, merged CHAIN-004/LOGIC-001 | YES. Honest count now. |
| R3-PHASE-ORDER | Reordered B->D->A->C | YES. |
| R3-NAME-HEURISTIC-DRIFT | Centralized in config | PARTIAL. TKN-TRIG-003 still hardcodes its own list (Finding 3 above). |

---

## Summary of remaining issues

| # | Severity | Category | Summary |
|---|----------|----------|---------|
| 1 | HIGH | Design gap | `run_checks` not updated to invoke `_CORRELATION_REGISTRY`. Dedup and check-ID extraction unspecified for correlation checks. |
| 2 | MEDIUM | Design inconsistency | CHAIN-004 classified as correlation check but mostly operates on single Pipeline data. Should clarify when correlation is actually needed (resolved remote Tasks only). |
| 3 | MEDIUM | Implementation gap | `shared_namespaces` and `security_task_patterns` not loaded by `load_config`. TKN-TRIG-003 migration to config not flagged as existing-check modification. |
| 4 | MEDIUM | Spec inconsistency | TRIG-004 description claims cross-resource data flow tracing but implementation is per-resource pattern matching. |
| 5 | LOW | Spec inconsistency | Check count math is wrong. 42 total, 40 active by default (not "39 registered"). Conflates registration, activation, and runtime skip. |
| 6 | MEDIUM | Phase dependency | Phase B ships correlation infrastructure and first correlation consumer (CHAIN-004) simultaneously. No isolated framework validation. |
| 7 | MEDIUM | Spec inconsistency | LOGIC-003 per-resource classification silently duplicates trust logic from TRUST checks. Duplication not acknowledged. |
| 8 | MEDIUM | Implementation gap | `--policy-dir` flag interaction with `find_tekton_files` unspecified. Policy files likely won't be in `.tekton/` directories. |

**Bottom line**: The revised spec addressed the majority of Round 1 findings well. The biggest remaining gap is Finding 1: the `CorrelationCheckFn` type is defined but never wired into `run_checks`. Without the concrete `run_checks` modification, the two correlation checks (CHAIN-004, TRUST-006) are still architecturally infeasible. The other 7 findings are MEDIUM/LOW spec quality issues that won't block implementation but will cause confusion or rework during development.
