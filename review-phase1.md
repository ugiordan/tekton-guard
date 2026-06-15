# Auto-Fix Engine Review: Phase 1 Findings

## Finding 1: TOCTOU Race and Double-Close in _apply_changes

**Severity:** HIGH
**Location:** `tekton_guard/fixer.py`, lines 219-227 (`_apply_changes`)

**Description:**

The `_apply_changes` method has a double-close bug in the error path. If `os.write()` succeeds but `os.rename()` fails, the code falls through to the `except` block and calls `os.close(fd)` again, but the fd was already closed on line 221. This raises `OSError: [Errno 9] Bad file descriptor` from the error handler, masking the original exception.

```python
fd, tmp_path = tempfile.mkstemp(suffix=".yaml", dir=str(path.parent))
try:
    os.write(fd, new_content.encode("utf-8"))
    os.close(fd)          # fd closed here
    os.rename(tmp_path, str(path))
except Exception:
    os.close(fd)          # double-close if os.write succeeded but os.rename failed
    os.unlink(tmp_path)
    raise
```

Additionally, `os.rename()` is not atomic on cross-filesystem moves and not atomic on Windows. On Linux ext4/xfs within the same filesystem it is atomic. The code creates the temp file in the same directory (`dir=str(path.parent)`) which mitigates the cross-filesystem issue, but the double-close remains a real bug.

**Fix recommendation:**

Use a flag or restructure with `try/finally`:

```python
fd, tmp_path = tempfile.mkstemp(suffix=".yaml", dir=str(path.parent))
closed = False
try:
    os.write(fd, new_content.encode("utf-8"))
    os.close(fd)
    closed = True
    os.rename(tmp_path, str(path))
except Exception:
    if not closed:
        os.close(fd)
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)
    raise
```

---

## Finding 2: _fix_git_ref Replaces First Occurrence of Value String, Not the YAML Key

**Severity:** HIGH
**Location:** `tekton_guard/fixer.py`, lines 176-187 (`_fix_git_ref`)

**Description:**

The method uses `old_line.replace(current, sha, 1)` where `current` is the mutable revision value (e.g., `"main"`, `"v1.2.3"`). This is a naive string replacement that does not validate context. If the revision value appears elsewhere on the same line (in a comment, in the key name, or as a substring of another value), the replacement will corrupt the file.

Real-world example from the fixture `pipelinerun-mutable.yaml`:

```yaml
    - name: revision
      value: main
```

If the value were something like `dev` and the line were `      value: dev  # development branch`, the replacement would produce `value: abcdef...1234  # abcdef...1234elopment branch` (if "dev" appears in the SHA). More critically, a value like `test` appearing in a YAML comment on the same line would get replaced.

The fallback search (lines 178-183) expands to +/-3 lines, which could match the wrong line entirely in files with repeated revision patterns (multi-document YAML with several git resolvers using the same branch name).

**Fix recommendation:**

Use a regex-aware replacement that anchors to the YAML value context:

```python
# Match the value in YAML context: after "value:" or as a bare value
pattern = re.compile(
    r'(value:\s*["\']?)' + re.escape(current) + r'(["\']?\s*(?:#.*)?)$'
)
new_line, count = pattern.subn(r'\1' + sha + r'\2', old_line)
if count == 0:
    return None
```

---

## Finding 3: Quoted YAML Values Produce Broken YAML After Replacement

**Severity:** MEDIUM
**Location:** `tekton_guard/fixer.py`, lines 176-187 (`_fix_git_ref`)

**Description:**

YAML values can be quoted: `value: 'main'` or `value: "main"`. The `current_value` extracted by the parser is the unquoted string `main`, but the line in the file contains `'main'` or `"main"`. Since `old_line.replace(current, sha, 1)` searches for the unquoted value, it will still match (the unquoted value exists as a substring of the quoted form). However, this produces a semantically correct but stylistically inconsistent result: `value: 'abcdef1234567890abcdef1234567890abcdef12'`, which is fine.

The real problem is when the value does NOT appear unquoted on the line. Consider PaC templates where the parser strips `{{ }}` or quotes. If `current_value` is `main` but the line is `value: '{{revision}}'`, the replacement silently fails (returns None) and the finding goes to `failed`. This is actually correct behavior, but there is no test covering quoted values.

More problematically, if `current_value` is something like `refs/heads/main`, the `replace()` call will work but may match a URL substring on the same line or a nearby line that contains the same path fragment.

**Fix recommendation:**

Add explicit handling for quoted values in the replacement logic. At minimum, add tests for `value: 'main'`, `value: "main"`, and values like `refs/heads/main`.

---

## Finding 4: _fix_workspace_readonly Corrupts Line Array Structure

**Severity:** HIGH
**Location:** `tekton_guard/fixer.py`, lines 189-202 (`_fix_workspace_readonly`)

**Description:**

The method creates a "new line" by concatenating the old line with a newline and the readOnly insertion:

```python
return (i, lines[i], lines[i] + "\n" + new_line)
```

This embeds a `\n` inside a single element of the `lines[]` array. When `_apply_changes` later does `"\n".join(lines)`, the embedded newline produces correct output. However, if there are multiple changes to the same file, the line index tracking becomes wrong because the array entry at index `i` now represents two visual lines, but the indices of subsequent entries have not shifted.

If a file has both a git ref pinning fix AND a workspace readOnly fix, and the workspace fix comes first in the file, the git ref fix's line_idx will be off by the number of inserted lines. The reverse-sort in `_apply_changes` (line 211) partially mitigates this if the readOnly fix is at a higher line number, but if it's at a lower line number, subsequent changes will target wrong lines.

**Fix recommendation:**

Instead of embedding newlines in array elements, use a proper insertion approach:

```python
# Insert the new line after index i
return (i, lines[i], lines[i])  # keep original
# And separately track the insertion
```

Or better, switch to a proper YAML-aware modification using ruamel.yaml's round-trip capabilities, since the project already depends on it.

---

## Finding 5: No SHA Validation on Resolved Value Before Writing

**Severity:** HIGH  
**Location:** `tekton_guard/fixer.py`, lines 168-169 and 44-47

**Description:**

The `_resolve_git_sha` function validates the returned SHA against `_SHA_RE` (40-char hex), which is good. However, `_cached_resolve_sha` returns whatever is in the cache without re-validation. Test code and any caller can inject arbitrary strings into the cache:

```python
engine._sha_cache["https://github.com/org/repo.git@main"] = "a" * 40
```

This is the expected test pattern. But since `_fix_git_ref` does not independently validate that `sha` is actually a valid SHA before writing it to the file (line 186), a compromised or buggy cache population could write arbitrary content into YAML files. In production this flows through `_resolve_git_sha` which validates, but the architectural defense-in-depth is missing.

More concerning: the SHA regex `^[0-9a-f]{40}$` accepts any 40-char lowercase hex string. An attacker who can control the GitHub API response (MITM, DNS poisoning, compromised token) can return a valid-looking SHA that points to a malicious commit. This is inherent to the SHA resolution approach and not a bug per se, but worth noting.

**Fix recommendation:**

Add validation in `_fix_git_ref` before using the SHA:

```python
sha = self._cached_resolve_sha(url, current)
if not sha or not _SHA_RE.match(sha):
    return None
```

---

## Finding 6: Binary File and Encoding Errors Unhandled

**Severity:** LOW
**Location:** `tekton_guard/fixer.py`, line 95

**Description:**

`path.read_text(encoding="utf-8")` will raise `UnicodeDecodeError` on binary files. The `fix_findings` method has no try/except around the file read, so a binary file or a file with invalid UTF-8 will crash the entire fix run, not just skip the problematic file. The parser uses `errors="replace"` (parser.py line 357), but the fixer does not, creating inconsistent behavior: the parser can scan a file but the fixer crashes trying to fix findings in it.

**Fix recommendation:**

Add `errors="replace"` to match the parser, or wrap in try/except and add to `result.failed`:

```python
try:
    content = path.read_text(encoding="utf-8")
except UnicodeDecodeError:
    for finding in findings:
        if finding.get("file") == file_path:
            result.failed.append({"rule_id": finding["rule_id"], "file": file_path,
                                  "reason": "binary_or_invalid_encoding"})
    return result
```

---

## Finding 7: File Permissions Not Preserved During Atomic Write

**Severity:** MEDIUM
**Location:** `tekton_guard/fixer.py`, lines 219-223

**Description:**

`tempfile.mkstemp()` creates a file with mode `0o600` (owner read/write only). When `os.rename()` replaces the original file, the new file retains the temp file's permissions, not the original file's permissions. If the original YAML file was mode `0o644` (readable by group/others, common in repos), after the fix it becomes `0o600`, which can break CI pipelines, container builds, or other tools that expect the file to be world-readable.

**Fix recommendation:**

Preserve the original file's permissions:

```python
original_stat = path.stat()
fd, tmp_path = tempfile.mkstemp(suffix=".yaml", dir=str(path.parent))
try:
    os.write(fd, new_content.encode("utf-8"))
    os.close(fd)
    os.chmod(tmp_path, original_stat.st_mode)
    os.rename(tmp_path, str(path))
except Exception:
    ...
```

---

## Finding 8: CLI Reports Original (Unfixed) Findings After --fix

**Severity:** MEDIUM
**Location:** `tekton_guard/cli.py`, lines 106-148

**Description:**

The `--fix` flag applies fixes to files on disk, but the findings list used for output (lines 125-135) and for exit code determination (lines 140-148) is the original pre-fix list. After a successful fix, the output will still show all the original findings as if they were not fixed, and the exit code will still be non-zero.

This means a CI pipeline using `tekton-guard --fix --fail-on HIGH` will always fail even if all HIGH findings were successfully fixed. Users will see the scan report unfixed findings that were actually patched.

**Fix recommendation:**

After applying fixes, either re-scan the file, or filter the findings list to remove successfully fixed items:

```python
if args.fix and not args.fix_dry_run:
    fixed_keys = {(r["file"], r["line"], r["rule_id"]) for result in all_results for r in result.fixed}
    findings = [f for f in findings if (f["file"], f.get("line_start", 0), f["rule_id"]) not in fixed_keys]
```

---

## Finding 9: No Test for Multi-Document YAML Fix Interaction

**Severity:** MEDIUM (test coverage gap)
**Location:** `tests/test_fixer.py`

**Description:**

The test suite has no test for fixing findings across a multi-document YAML file (documents separated by `---`). The `_fix_git_ref` fallback search (lines 178-183 of fixer.py) searches +/-3 lines from the reported line number, which could cross document boundaries in multi-doc files and match the wrong document's revision value.

For example, if two PipelineRuns in the same file both use `revision: main` but point to different repos, and only one finding is emitted, the fallback search could match the wrong one.

**Missing tests:**
- Multi-document YAML with multiple git resolver refs
- Files where the same revision value (`main`) appears on multiple lines
- Edge case where `line_start` from the parser is off by 1 due to document separators

**Fix recommendation:**

Add a test with a multi-document fixture containing two PipelineRuns with different URLs but the same mutable revision, and verify the fixer patches the correct one.

---

## Finding 10: Conflicting Changes to Same Line Not Detected

**Severity:** MEDIUM
**Location:** `tekton_guard/fixer.py`, lines 210-214

**Description:**

If two findings target the same `line_idx`, the `changes` list will contain two entries for that index. The reverse-sort and sequential application means the second change (in original order) overwrites the first. There is no conflict detection or merging.

This can happen when a single YAML line triggers multiple rules. For instance, a line might match both TKN-PIN-001 and TKN-PIN-002 if the parser emits overlapping findings (unlikely with current checks, but no guard prevents it).

**Fix recommendation:**

Deduplicate changes by line index, keeping only the first change per line, and logging a warning for conflicts:

```python
seen_lines = set()
deduped = []
for change in changes:
    if change[0] not in seen_lines:
        seen_lines.add(change[0])
        deduped.append(change)
    else:
        logger.warning("Conflicting fix at line %d, skipping", change[0] + 1)
changes = deduped
```
