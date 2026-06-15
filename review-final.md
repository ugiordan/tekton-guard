# tekton-guard Final Review

## Finding 1: SSRF / Path Traversal in Resolver

**Severity:** HIGH
**Module:** `tekton_guard/resolver.py`

**What's wrong:** Both `_fetch_via_api` and `_fetch_via_clone` accept `url`, `revision`, and `path` values directly from the parsed YAML without any validation. An attacker who controls Tekton pipeline definitions being scanned can craft:

1. A `pathInRepo` value like `../../etc/passwd` or `../../../.ssh/id_rsa` to read arbitrary files from cloned repos (path traversal in `_fetch_via_clone`, line 55: `target = Path(tmpdir) / path`).
2. A `url` value that points to an internal network endpoint (e.g., `http://169.254.169.254/latest/meta-data/`) in `_fetch_via_api`, which performs an HTTP fetch to it without any URL validation (SSRF, line 83-85).
3. The `revision` parameter is injected directly into a git command line at line 39 (`"--branch", revision`), which could inject additional arguments if revision contains shell metacharacters (though `subprocess.run` with a list mostly prevents this).

**How to fix:**
- Validate that `url` starts with `https://github.com/` (or other allowed schemes/domains) before fetching.
- Validate that `path` does not contain `..` segments. Use `Path(path).resolve()` and verify it stays within the expected directory.
- Consider adding a URL allowlist option for resolver targets.

---

## Finding 2: Deduplication Silently Drops Legitimate Findings for TKN-LIMIT-002

**Severity:** MEDIUM
**Module:** `tekton_guard/checks/__init__.py`, line 55

**What's wrong:** The dedup key is `(rule_id, file, line_start)`. For `TKN-LIMIT-002`, both the pipeline timeout finding and the tasks timeout finding share the same `rule_id`, `file`, and `line_start` (which is `resource.line_offset` for both). This means only one of two genuine distinct findings survives. The test `test_excessive_task_timeout_flagged` in `test_phase2_checks.py` even documents this as a known issue (line 126-127: "only one survives dedup").

This is a real data loss bug, not a cosmetic issue. A user with an excessive pipeline timeout AND an excessive task timeout sees only one of them.

**How to fix:** The `check_limit_002` function should use distinct `line_start` values for each finding. For example, look up the actual line numbers of the `pipeline` and `tasks` keys within the `timeouts` block from the raw data. Alternatively, include the finding title or a sub-key in the dedup tuple to distinguish the two findings at the same line.

---

## Finding 3: `is_trusted_git_source` Has Incorrect URL Normalization

**Severity:** MEDIUM
**Module:** `tekton_guard/config.py`, line 37

**What's wrong:** The method strips `.git` with `rstrip(".git")`, not `removesuffix(".git")`. `str.rstrip()` removes individual characters from the set, not the substring. So for a URL like `https://github.com/org/my-dotgit.git`, `rstrip(".git")` would strip more than just `.git` from the end, potentially stripping characters from the repo name itself. For example:
- `"https://github.com/org/testing".rstrip(".git")` produces `"https://github.com/org/tes"` because `rstrip` strips any character in the set `{'.', 'g', 'i', 't'}`.

This can cause false negatives (untrusted sources matching trusted prefixes) or false positives (trusted sources failing to match).

**How to fix:** Change `rstrip(".git")` to `removesuffix(".git")` on line 37:
```python
normalized = url.rstrip("/").removesuffix(".git")
```

---

## Finding 4: `--diff-base` Fails on Single File Targets

**Severity:** MEDIUM
**Module:** `tekton_guard/cli.py`, line 123

**What's wrong:** When `--diff-base` is used, the code runs `git -C str(target)`, where `target` is the path from `args.target`. If the user passes a single YAML file as the target (which is valid and supported), `git -C` expects a directory, not a file path. This will cause the git command to fail, and the fallback behavior is to scan all files with a warning, which defeats the purpose of `--diff-base` entirely. The error is silently swallowed by the bare `except Exception`.

**How to fix:** Use `target.parent` when `target.is_file()`, or resolve the git repo root using `git rev-parse --show-toplevel`. Also, the path comparison logic on line 131-133 needs to handle the case where `target` is a file: if the file itself is not in `changed_tekton`, the scan should report zero findings.

---

## Finding 5: Fixer Writes to Arbitrary Paths Without Validation

**Severity:** MEDIUM  
**Module:** `tekton_guard/fixer.py`, line 88-92

**What's wrong:** `FixEngine.fix_findings` accepts a `file_path` from the finding's `file` field and writes to it using `_apply_changes`. Findings contain `file` paths that come from `resource.file_path`, which is set during parsing. If `--resolve` was used, `file_path` can be a synthetic path like `remote:org/repo@revision/path`. The `_apply_changes` method at line 224 calls `os.rename(tmp_path, str(path))`, which could overwrite arbitrary files if the path is crafted.

In the current code, `Path(file_path).exists()` at line 93 protects against most abuse (synthetic remote paths won't exist on disk). But there's no explicit check that the file being written is within the scanned directory, and the `file_path` values flow from untrusted YAML content through the parser.

**How to fix:** Add explicit validation that `file_path` is within the target directory before writing. For example, resolve both paths and check `resolved_path.is_relative_to(target_dir)`. Reject any `file_path` that starts with `remote:`.

---

## Finding 6: `--fix` After `--baseline` Fixes Already-Suppressed Findings

**Severity:** LOW  
**Module:** `tekton_guard/cli.py`, lines 162-226

**What's wrong:** When both `--baseline` and `--fix` are used together, the code flow is:
1. Run checks, get all findings (line 160)
2. Apply baseline suppression, reduce findings (lines 162-178)
3. Run fixer on the reduced findings (lines 202-217)
4. Re-scan to get post-fix findings (lines 219-226)
5. The re-scan findings are NOT baseline-filtered again (lines 228-238)

This means the final output after `--fix` will include baseline-suppressed findings in the output. The re-scan findings bypass the baseline filter.

**How to fix:** Apply baseline filtering again after the re-scan at line 226, or restructure the code so the baseline filter applies once at the end, right before formatting.

---

## Finding 7: Atomic Write Uses `os.rename` Which Fails Across Filesystems

**Severity:** LOW  
**Module:** `tekton_guard/fixer.py`, line 229

**What's wrong:** The "atomic write" implementation creates a tempfile in the same directory as the target (`dir=str(path.parent)`) and uses `os.rename`. This is correct for same-filesystem atomicity on POSIX. However, the `tempfile.mkstemp` call may fail if the directory is read-only, and `os.rename` can fail on some systems if the source and destination are on different mount points (though `dir=str(path.parent)` usually prevents this). More concretely, the original file permissions are preserved via `os.chmod`, but the file's ownership and xattrs are not. This is a minor robustness issue.

The more real problem: `os.rename` on Windows is not atomic and does not overwrite existing files. If this tool ever runs on Windows (e.g., in a CI runner), the fixer will fail.

**How to fix:** Use `os.replace` instead of `os.rename` for cross-platform atomic overwrite. `os.replace` is guaranteed to be atomic and overwrite-capable on all platforms.

---

## Finding 8: Module-Level Cache in Resolver Creates State Leak Between Test Runs

**Severity:** LOW  
**Module:** `tekton_guard/resolver.py`, line 15

**What's wrong:** The `_cache` dict is a module-level global. Once populated, it persists across all calls within the same process. In test suites, this means resolver results from one test can bleed into another. More importantly, in a long-running process or repeated CLI invocations from the same Python process (e.g., a daemon or web service wrapping tekton-guard), stale cache entries will silently serve outdated remote resources.

There is no cache invalidation or TTL mechanism.

**How to fix:** Move the cache into the resolver functions as a parameter, or provide a `clear_cache()` function. For test isolation, add a pytest fixture that clears `_cache` between tests. For production use, consider adding a TTL or size limit.

---

## Finding 9: `check_id` Extraction From Docstrings Is Fragile

**Severity:** LOW  
**Module:** `tekton_guard/checks/__init__.py`, line 49

**What's wrong:** The code extracts `check_id` from `check_fn.__doc__.split(":")[0].strip()`. This relies on every check function having a docstring formatted exactly as `"TKN-XYZ-NNN: description"`. If any check function lacks a docstring, has a different format, or has a colon in the rule ID, the `check_id` extraction will produce incorrect values. When `check_id` is empty or wrong, `config.should_run_check(check_id)` will fail to match entries in `skip_checks`, making the check unskippable.

Currently all check functions follow the convention, but this is a maintenance trap. Adding `check_limit_001` (currently unregistered) without a docstring, or having a contributor omit the colon, would cause a silent failure.

**How to fix:** Add a `check_id` attribute to each check function via the `@register_check` decorator. For example:
```python
def register_check(func: CheckFn) -> CheckFn:
    doc = func.__doc__ or ""
    func.check_id = doc.split(":")[0].strip() if ":" in doc else ""
    _REGISTRY.append(func)
    return func
```
Then use `check_fn.check_id` instead of parsing the docstring each time in `run_checks`.

---

## Finding 10: `_parse_duration_hours` Fails on ISO 8601 Durations

**Severity:** LOW  
**Module:** `tekton_guard/checks/limits.py`, lines 31-43

**What's wrong:** The duration parser only handles Go-style durations like `6h0m0s`. Kubernetes/Tekton also accepts ISO 8601 duration format (e.g., `P1DT6H`) and bare second values (e.g., `21600` meaning 21600 seconds). The current parser would return `0` for these formats, causing excessive timeouts to go undetected.

Additionally, the parser has a bug with the `"s"` suffix: if the value is `"30m0s"`, after splitting on `"h"` it gets `"30m0s"`, then splits on `"m"` to get `["30", "0s"]`. The `"0s"` is ignored because there's no `"s"` handler, which is fine. But if the value is just `"3600s"` (seconds only), the parser returns 0 because neither `"h"` nor `"m"` is present.

**How to fix:** Add handling for seconds (`"s"` suffix) and ideally for ISO 8601 durations. At minimum, add a seconds handler:
```python
if "s" in val:
    parts = val.split("s")
    hours += float(parts[0]) / 3600
```

---

## Finding 11: TaskRun pipelineRef Handling Mismatch

**Severity:** LOW  
**Module:** `tekton_guard/parser.py`, lines 319-328

**What's wrong:** The parser handles `pipelineRef` for both `PipelineRun` and `TaskRun` kinds (line 319: `if kind in ("PipelineRun", "TaskRun")`). A `TaskRun` does not have a `pipelineRef` field. While this doesn't cause a crash (if `pipelineRef` is absent, it just skips), it means the parser would incorrectly populate `pipeline_ref` on a `TaskRun` resource if someone put a `pipelineRef` key in a TaskRun spec. More importantly, checks like `check_pin_001` only check `resource.kind == "PipelineRun"`, so a misparsed TaskRun with a pipelineRef would silently bypass pinning checks. This is a minor spec-compliance issue.

**How to fix:** Move the `pipelineRef` extraction to only run when `kind == "PipelineRun"`, and handle `taskRef` for `TaskRun` separately. This also makes the code more self-documenting.

---

## Finding 12: No Test Coverage for `--resolve` Flag or Resolver Module

**Severity:** LOW  
**Module:** `tests/`

**What's wrong:** There are no tests for the `resolve_remote_refs` function, `_fetch_via_api`, or `_fetch_via_clone`. The `--resolve` CLI flag is not tested. This is a significant gap because:
1. The resolver performs network I/O and subprocess calls (git clone).
2. It constructs URLs from untrusted input (see Finding 1).
3. The caching behavior has no test coverage.
4. The rewrite of `file_path` on resolved resources could affect downstream checks and dedup.

**How to fix:** Add unit tests for the resolver module using mocked HTTP responses and mocked subprocess calls. Test at least:
- URL construction/validation
- Cache hit/miss behavior
- Path traversal rejection
- `file_path` rewriting on resolved resources
- Error handling for network failures

---

## Finding 13: `--fix` + `--fix-dry-run` Can Be Combined Without Error

**Severity:** INFO  
**Module:** `tekton_guard/cli.py`, line 202

**What's wrong:** The CLI allows both `--fix` and `--fix-dry-run` to be specified simultaneously. The condition on line 202 is `if args.fix or args.fix_dry_run`. When both are set, `FixEngine` is initialized with `dry_run=args.fix_dry_run` (True), so no changes are applied. But the re-scan on lines 220-226 only runs when `not args.fix_dry_run`, so with both flags, it acts as dry-run. The behavior is not harmful but is confusing. The user may expect `--fix` to override `--fix-dry-run`.

**How to fix:** Add mutual exclusion to the argument parser:
```python
fix_group = parser.add_mutually_exclusive_group()
fix_group.add_argument("--fix", ...)
fix_group.add_argument("--fix-dry-run", ...)
```

---

## Summary

| # | Severity | Module | Issue |
|---|----------|--------|-------|
| 1 | HIGH | resolver.py | SSRF and path traversal in remote resolver |
| 2 | MEDIUM | checks/__init__.py | Dedup drops legitimate LIMIT-002 findings |
| 3 | MEDIUM | config.py | `rstrip(".git")` strips wrong characters |
| 4 | MEDIUM | cli.py | `--diff-base` fails on single file targets |
| 5 | MEDIUM | fixer.py | No path validation before writing files |
| 6 | LOW | cli.py | `--fix` + `--baseline` re-scan bypasses filter |
| 7 | LOW | fixer.py | `os.rename` not cross-platform atomic |
| 8 | LOW | resolver.py | Module-level cache has no invalidation |
| 9 | LOW | checks/__init__.py | Fragile docstring-based check_id extraction |
| 10 | LOW | checks/limits.py | Duration parser fails on seconds-only and ISO 8601 |
| 11 | LOW | parser.py | TaskRun incorrectly handles pipelineRef |
| 12 | LOW | tests/ | Zero test coverage for resolver module |
| 13 | INFO | cli.py | `--fix` and `--fix-dry-run` not mutually exclusive |
