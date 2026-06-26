# Architecture & Correctness Review: tekton-guard latest changes

## Finding 1: verify_pins resolves against repo default HEAD, not the original branch

**Severity:** HIGH
**File:** `/tmp/tekton-guard/tekton_guard/fixer.py`, lines 116-151

**Description:**
`verify_pins` detects stale SHA pins by resolving the literal string `"HEAD"` via the GitHub API (`_resolve_git_sha(ref.url, "HEAD")`). Once a revision field has been replaced with a SHA (e.g., `main` became `abcdef12...`), the original branch name is lost. The function always compares against `HEAD` of the repo, which is typically the default branch (e.g., `main`).

If the original reference pointed to a non-default branch (e.g., `release-1.2`, `stable`, a feature branch), the comparison will be against the wrong branch entirely. This produces false positives (flagging a pin as "stale" when it is current on its intended branch) and false negatives (not detecting actual staleness on the correct branch).

The code has a docstring mentioning "traceability comments or the pathInRepo context" but neither mechanism is implemented. There is no comment parsing, no annotation lookup, and no metadata stored alongside the SHA to record the original branch.

**Fix:**
Store the original branch name as a YAML comment (e.g., `# tekton-guard: pinned from branch=release-1.2`) or as an annotation on the resource when auto-pinning via `--fix`. Then in `verify_pins`, parse that metadata and use it as the ref argument to `_resolve_git_sha` instead of the hardcoded `"HEAD"`.

---

## Finding 2: OCI digest resolution fails silently for quay.io, ghcr.io, and all authenticated registries

**Severity:** HIGH
**File:** `/tmp/tekton-guard/tekton_guard/fixer.py`, lines 54-104

**Description:**
`_resolve_image_digest` only handles Docker Hub authentication (the `if "docker.io" in registry` branch at line 81). For all other registries (quay.io, ghcr.io, ECR, GCR, private registries), the function sends an unauthenticated request to the `/v2/.../manifests/` endpoint.

- **quay.io** requires a bearer token obtained via `https://quay.io/v2/auth` (WWW-Authenticate challenge/response). Without it, the request returns 401.
- **ghcr.io** requires a GitHub token via `https://ghcr.io/token`.
- Private registries return 401 or 403.

In all these cases, `_resolve_image_digest` catches the exception and silently returns `None`, causing the fix to be recorded as "failed" with reason "digest_resolution_failed" but no useful diagnostic. This means `--fix` for TKN-PIN-003/004 only works for public Docker Hub images.

Additionally, the Docker Hub token flow has a subtle issue: if the `repository` path contains a registry prefix (e.g., if someone writes `docker.io/library/python:3.12`), the segments parsing at line 69-75 will set `registry = "docker.io"` and then line 81-82 re-sets it to `registry-1.docker.io`, but the token scope URL uses the `repository` variable which still contains `library/python` (correct in this case). However, for images like `docker.io/myorg/myimage:tag`, the split at line 69 produces `registry = "docker.io"` and `repository = "myorg/myimage"`, which works. But an image written as `index.docker.io/myorg/myimage:tag` would have `registry = "index.docker.io"` and the `"docker.io" in registry` check at line 81 would match, then override to `registry-1.docker.io`, which is correct. The edge case that breaks: an image like `myorg/myimage:tag` (no dots in the first segment) gets `registry = "registry-1.docker.io"` at line 74 but then the Docker Hub token branch at line 81 (`"docker.io" in registry`) does match, so it fetches a token. This path works. So the Docker Hub logic itself is OK for standard cases.

The real gap is every non-Docker-Hub registry.

**Fix:**
Implement the standard OCI WWW-Authenticate challenge/response flow: make an initial unauthenticated request, parse the 401 response's `WWW-Authenticate` header to extract the realm/service/scope, then fetch a bearer token (using credentials from `~/.docker/config.json` or environment variables), and retry with that token. Libraries like `skopeo` or the `oras` Python SDK can be used as a reference.

---

## Finding 3: _create_fix_pr does not handle dirty working tree, detached HEAD, or missing remote

**Severity:** MEDIUM
**File:** `/tmp/tekton-guard/tekton_guard/cli.py`, lines 16-52

**Description:**
`_create_fix_pr` runs `git checkout -b <branch>`, `git add -A`, `git commit`, and `git push` without checking preconditions:

1. **Dirty working tree with unrelated changes:** `git add -A` stages ALL changes in the working tree, not just the files modified by the fix engine. If the user has uncommitted work, it gets silently included in the auto-fix PR.

2. **Detached HEAD:** `git checkout -b <branch>` from a detached HEAD creates a branch at that commit, but the user's original branch context is lost. The PR's base branch will be whatever GitHub infers from the default branch, which may be wrong.

3. **No remote named "origin":** `git push -u origin <branch>` will fail if the remote is named something else (e.g., `upstream`). The error is caught by the generic `CalledProcessError` handler, but the user gets a cryptic error message.

4. **No cleanup on failure:** If `git commit` fails (e.g., nothing to commit after `add -A`), the new branch is left checked out. The user is stranded on `tekton-guard/auto-pin-XXXX` instead of their original branch.

5. **PR duplicate check is fragile:** Line 28 searches for PRs with `--head "tekton-guard/"` (a prefix), but `gh pr list --head` does exact match on the head ref. This means the check will never match any existing PR (the branch name is `tekton-guard/auto-pin-XXXX`, not `tekton-guard/`), so the deduplication is broken and multiple PRs can be created on repeated runs.

**Fix:**
- Record the current branch (`git rev-parse --abbrev-ref HEAD`) before branching, and restore it in a finally block on failure.
- Use `git add` with the specific list of files from `FixResult.fixed` instead of `git add -A`.
- Check for the remote name dynamically (`git remote` or check for `origin` specifically with a useful error).
- Fix the PR dedup: use `--head "tekton-guard/"` with `--search` or `--label`, or use `gh pr list --json headRefName` and filter for the prefix `tekton-guard/auto-pin-`.

---

## Finding 4: TKN-LIMIT-001 does not flag partial resource specs (requests without limits, or vice versa)

**Severity:** MEDIUM
**File:** `/tmp/tekton-guard/tekton_guard/checks/limits.py`, lines 11-31

**Description:**
The check at lines 18-19 uses:
```python
has_requests = bool(res.get("requests"))
has_limits = bool(res.get("limits"))
if has_requests or has_limits:
    continue
```

This means a step that has `resources.requests` but no `resources.limits` (or vice versa) is silently skipped. In Kubernetes, having requests without limits allows unbounded resource consumption (the pod can burst without cap), which is exactly the CWE-400 DoS risk the check claims to detect. A step with `requests: {cpu: "100m"}` but no limits can still consume all available CPU on the node.

The rule description says "Missing resource requests/limits" (plural) but the logic only fires when BOTH are missing. This is a false negative gap.

**Fix:**
Change the condition to flag when either requests or limits is missing:
```python
if has_requests and has_limits:
    continue
```
Or better, produce distinct findings: one for missing requests, one for missing limits, since the security implications differ (missing limits = unbounded burst; missing requests = scheduler cannot guarantee resources).

---

## Finding 5: Konflux task has shell injection via parameter substitution in Python f-strings

**Severity:** HIGH
**File:** `/tmp/tekton-guard/tekton-guard-task.yaml`, lines 64-92

**Description:**
The shell script in the `scan` step uses Tekton parameter substitution (e.g., `$(params.fail-on)`, `$(params.format)`) which are expanded by the Tekton controller before the shell runs. The arguments are properly quoted on line 56 (`"$SOURCE_DIR"`, `"$FORMAT"`, `"$FAIL_ON"`) via environment variables, so the main command line is safe.

However, the Python inline scripts on lines 80-92 use shell variable interpolation inside Python string literals:
```python
python3 -c "
...
    'result': '$RESULT',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'failures': int('$FINDING_COUNT'),
    'note': 'tekton-guard found $FINDING_COUNT security finding(s)',
...
"
```

The `$RESULT` and `$FINDING_COUNT` variables are derived from controlled sources (the tool's own output), so the immediate injection risk is low. However, `$(date -u +%Y-%m-%dT%H:%M:%SZ)` is a shell command substitution inside the Python string. If a malicious Tekton parameter value somehow influenced the shell environment, or if the date command is not available (minimal containers), the timestamp generation would fail or produce unexpected output.

More importantly, the entire approach of embedding shell variable interpolation inside Python code passed via `python3 -c` is fragile. If `FINDING_COUNT` ever contains a value like `0'); import os; os.system('malicious` (it won't from `json.load` + `.get()`, but defense-in-depth matters), it would be interpreted as Python code.

**Fix:**
Pass values to the Python script via environment variables and read them with `os.environ` inside Python, or write a proper Python script file instead of inline `python3 -c`. Example:
```bash
FINDING_COUNT="$FINDING_COUNT" RESULT="$RESULT" python3 -c "
import json, os
output = {
    'result': os.environ['RESULT'],
    ...
}
"
```

---

## Finding 6: Risk score formula allows same display_score across different severity tiers

**Severity:** LOW
**File:** `/tmp/tekton-guard/tekton_guard/graph.py`, lines 100-138

**Description:**
The scoring formula is:
```
BASE_SCORES = {"INFO": 1, "LOW": 5, "MEDIUM": 10, "HIGH": 36, "CRITICAL": 62}
TIER_WEIGHTS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
display_score = tier_weight * 100 + risk_score
risk_score = base_score + blast_bonus  (blast_bonus: 0, 5, or 10)
```

Working through the numbers:
- MEDIUM with blast_bonus=10: display_score = 2*100 + (10+10) = 220
- HIGH with blast_bonus=0: display_score = 3*100 + (36+0) = 336
- HIGH with blast_bonus=10: display_score = 3*100 + (36+10) = 346
- CRITICAL with blast_bonus=0: display_score = 4*100 + (62+0) = 462

The tier gap of 100 is large enough to prevent cross-tier inversions (MEDIUM max = 220, HIGH min = 336; HIGH max = 346, CRITICAL min = 462). So the math is correct for preventing inversions.

However, within a tier, `risk_score` ranges overlap: a LOW finding with blast=10 has risk_score=15 and display_score=115, while a MEDIUM finding with blast=0 has risk_score=10 and display_score=210. The within-tier differentiation is fine.

One concern: `calculate_risk_scores` is defined but never called from the CLI or any other code path. It is dead code. If it was intended to be integrated into the output pipeline, it is missing.

**Fix:**
If risk scoring is intended for use, integrate it into the CLI pipeline (e.g., after `run_checks` and blast radius calculation). If it is not ready, mark it clearly as experimental or add a `--risk-scores` flag. The formula itself is sound.

---

## Finding 7: _fix_image_digest produces invalid image references (tag AND digest)

**Severity:** MEDIUM
**File:** `/tmp/tekton-guard/tekton_guard/fixer.py`, lines 318-342

**Description:**
`_fix_image_digest` pins an image by appending the digest to the full image:tag reference:
```python
pinned = f"{current}@{digest}"
```
This produces references like `python:3.12-slim@sha256:abc123...`. While Docker/containerd will accept this (they ignore the tag and pull by digest), this is technically problematic:

1. When `verify_pins` or future checks scan the result, the `@sha256:` early-exit in `_resolve_image_digest` (line 59) means the image can never be re-resolved or updated.
2. The tag portion becomes stale metadata. If someone bumps the tag in a later edit without removing the digest, the tag and digest will refer to different images, creating confusion.
3. Some OCI tooling (particularly `skopeo copy` and certain admission controllers) may reject or misinterpret references with both tag and digest.

The conventional approach is to replace the tag with the digest entirely: `python@sha256:abc123...`, or to keep the tag as a comment for human reference.

**Fix:**
Replace the tag with the digest: `pinned = f"{repo_part}@{digest}"` where `repo_part` is everything before the `:tag`. Add the original tag as a YAML comment for traceability. Alternatively, keep the `image:tag@digest` format but document it explicitly and ensure all downstream consumers understand it.

---

## Finding 8: No test coverage for verify_pins, _resolve_image_digest, _create_fix_pr, or calculate_risk_scores

**Severity:** MEDIUM
**File:** `/tmp/tekton-guard/tests/`

**Description:**
Several significant features added in the latest changes have zero test coverage:

1. **`verify_pins`**: No tests at all. The function has non-trivial logic (iterating pipeline_tasks and finally_tasks, SHA matching, API resolution). No test validates the stale-pin detection, the "HEAD" comparison behavior, or error handling when GITHUB_TOKEN is missing.

2. **`_resolve_image_digest`**: No unit tests. The Docker Hub token flow, registry detection heuristics, and digest extraction from response headers are all untested. The existing `test_pin003_004_fail_without_network` only confirms failure when the network is unreachable; it does not test the parsing logic with mocked responses.

3. **`_create_fix_pr`**: No tests. The git workflow with subprocess calls is complex and has multiple failure modes (Finding 3). Without mocked subprocess tests, all the edge cases (dirty tree, detached HEAD, duplicate PR) are unverified.

4. **`calculate_risk_scores`**: No tests at all, and the function is not called from anywhere (Finding 6). There is no verification that the scoring formula prevents inversions.

5. **TKN-LIMIT-001**: No dedicated test for the check. The only related test (`test_no_limits_on_clean_fixture`) verifies that a clean fixture produces zero LIMIT findings, but there is no positive test that verifies the check fires on a fixture with missing resources. There is also no test for the partial-resources false negative (Finding 4).

**Fix:**
Add tests for each:
- `verify_pins`: mock `_resolve_git_sha` to return known SHAs, test stale detection, test skip-if-already-pinned, test non-git resolvers.
- `_resolve_image_digest`: mock `urllib.request.urlopen` to simulate Docker Hub and non-Docker-Hub registries, test parsing of `Docker-Content-Digest` header.
- `_create_fix_pr`: mock `subprocess.run` to verify the sequence of git/gh commands, test cleanup on failure, test duplicate PR detection.
- `calculate_risk_scores`: test with concrete numbers to verify no cross-tier inversions, test blast_bonus thresholds.
- `check_limit_001`: create a fixture with partial resources (requests but no limits) and verify the check behavior.

---

## Finding 9: Image reference parsing breaks on ports and nested paths

**Severity:** LOW
**File:** `/tmp/tekton-guard/tekton_guard/fixer.py`, lines 63-75

**Description:**
The image reference parser at line 65 splits on `:` to separate the tag:
```python
parts = image.split(":")
if len(parts) < 2:
    return None
tag = parts[-1]
repo_part = ":".join(parts[:-1])
```

For an image like `myregistry.com:5000/myimage:latest`, the split produces `["myregistry.com", "5000/myimage", "latest"]`. Then `tag = "latest"` and `repo_part = "myregistry.com:5000/myimage"`, which is correct.

But for `myregistry.com:5000/myimage` (no tag, implicitly `latest`), the split produces `["myregistry.com", "5000/myimage"]`, so `tag = "5000/myimage"` and `repo_part = "myregistry.com"`. The function would attempt to resolve a manifest for tag `5000/myimage` on registry `myregistry.com`, which will fail.

Another edge case: images with no tag and no port (e.g., `myorg/myimage`) return `None` at line 65 because `len(parts) < 2` (there is no `:`). This is actually correct (no tag to resolve), but the function cannot resolve implicit `:latest` tags.

**Fix:**
Use a proper OCI reference parser. At minimum, detect the port vs. tag ambiguity: if the last `:` segment is purely numeric and follows a hostname (contains dots), treat it as a port, not a tag. Or use a regex like `^(?:(?P<registry>[^/]+(?:\.[^/]+)+(?::\d+)?)/)?(?P<repo>[^:@]+)(?::(?P<tag>[^@]+))?(?:@(?P<digest>.+))?$`.

---

## Finding 10: Atomic write in _apply_changes does not preserve original file's newline termination

**Severity:** LOW
**File:** `/tmp/tekton-guard/tekton_guard/fixer.py`, lines 344-377

**Description:**
The file content is split into lines (`content.split("\n")`) and then joined back with `"\n".join(lines)`. If the original file ended with a trailing newline (as all POSIX-compliant text files should), `split("\n")` produces an empty string as the last element. After modifications and `"\n".join(lines)`, this is preserved. However, if a multi-line replacement (line 354-357) is applied via `new_line.split("\n")`, the splice operation modifies the lines list in ways that could add or remove the trailing empty element depending on the change.

This is a minor concern but can cause spurious diffs in git when the trailing newline is added or removed.

**Fix:**
Track whether the original file ended with `\n` and ensure the output preserves that property. For example:
```python
had_trailing_newline = content.endswith("\n")
# ... process ...
new_content = "\n".join(lines)
if had_trailing_newline and not new_content.endswith("\n"):
    new_content += "\n"
```
