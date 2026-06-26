# Completeness and Edge-Case Review: tekton-guard latest changes

Reviewer: Completeness/Edge-Case Agent
Date: 2026-06-23
Files reviewed: fixer.py, cli.py, graph.py, checks/limits.py, test_fixer.py, test_graph.py, test_cli.py, tekton-guard-task.yaml

---

## Finding 1: Baseline content_hash is trivially collidable and allows cross-finding suppression

**Severity:** HIGH
**File:** `tekton_guard/cli.py`, lines 249-257

**Description:**
The baseline suppression key is `(rule_id, file, content_hash)` where `content_hash` is a 16-hex-char (64-bit) truncation of SHA-256 of `current_value` or `message`. An attacker who controls the baseline file can craft a `content_hash` that matches a different finding in the same file/rule. More critically, the hash input is the finding's `current_value` (e.g., the string `"main"` for a mutable branch ref). If two different findings in the same file share the same `current_value` (e.g., two different task refs both using `"main"`), a single baseline entry suppresses ALL of them, even if only one was intentionally accepted.

Additionally, because `content_hash` uses only the `current_value` field (not the line number or resolver URL), an attacker who gets one legitimate baseline entry accepted can then change which finding it suppresses by modifying the YAML so a different line produces the same `current_value`.

The `--update-baseline` auto-generated entries all share `reason: "Accepted via --update-baseline"` which provides no auditability for what was actually accepted.

**Fix:**
1. Include `line_start` (or a line-range hint) in the baseline key tuple so that the same `content_hash` at a different location doesn't match.
2. Include the `resolver_url` or a broader context fingerprint in the hash input (not just `current_value`).
3. Consider full SHA-256 instead of 64-bit truncation. Birthday collisions at 64 bits are feasible at ~2^32 findings which is unrealistic for this tool, but the real issue is the narrow hash input, not the truncation.
4. Require a meaningful `reason` field, not a generic auto-generated string, or at minimum log a warning when using auto-generated reasons.

---

## Finding 2: Malformed or timezone-naive expiry dates silently accepted as non-expired

**Severity:** MEDIUM
**File:** `tekton_guard/cli.py`, lines 241-248

**Description:**
When a baseline entry has an `expires` field, the code parses it with `datetime.fromisoformat(expires)`. If parsing fails (malformed date), the `except (ValueError, TypeError): pass` block silently treats the entry as having no expiry, meaning it never expires and suppresses the finding forever.

Additionally, there is a timezone comparison bug. `now` is `datetime.now(timezone.utc)` (timezone-aware), but `datetime.fromisoformat()` on a string like `"2025-01-01"` returns a timezone-naive datetime. Comparing a timezone-aware `now` with a timezone-naive `exp_dt` raises a `TypeError` in Python 3.12+, which is caught by the `except (ValueError, TypeError)` handler, again silently treating the entry as non-expired.

This means an attacker can set `expires: "not-a-date"` or `expires: "2020-01-01"` (without timezone info) and the baseline entry will never expire.

**Fix:**
1. When `fromisoformat` fails, reject the entry (do not add it to `baseline_keys`), and print a warning.
2. When the parsed datetime is timezone-naive, either reject it or attach UTC explicitly: `if exp_dt.tzinfo is None: exp_dt = exp_dt.replace(tzinfo=timezone.utc)`.
3. Add a test case for malformed expiry dates and naive-vs-aware datetime comparison.

---

## Finding 3: OCI digest resolution fails silently on multi-arch (manifest list) images

**Severity:** MEDIUM
**File:** `tekton_guard/fixer.py`, lines 54-104

**Description:**
The `Accept` header in `_resolve_image_digest` requests only `application/vnd.docker.distribution.manifest.v2+json` and `application/vnd.oci.image.manifest.v1+json`. It does not include `application/vnd.docker.distribution.manifest.list.v2+json` or `application/vnd.oci.image.index.v1+json` (the OCI index media type).

For multi-architecture images (the norm for most public images like `python:3.12-slim`, `alpine`, UBI images), the registry returns a manifest list / OCI index. When the server honors the `Accept` header strictly, it may return a 404 or a manifest list that doesn't match the requested media types, causing the resolution to fail silently (`return None`). When it does return a manifest list, the `Docker-Content-Digest` header will be the digest of the manifest list, not a platform-specific manifest. This digest is valid but pins to the multi-arch manifest, which is correct behavior. However, the silent failure path means `--fix` for TKN-PIN-003/004 will report `digest_resolution_failed` for many common images without explaining why.

**Fix:**
1. Add `application/vnd.docker.distribution.manifest.list.v2+json` and `application/vnd.oci.image.index.v1+json` to the `Accept` header.
2. When a manifest list is returned, use its digest (pinning to the manifest list is the correct supply-chain practice).
3. Log a DEBUG message distinguishing "registry unreachable" from "manifest type mismatch" failures.

---

## Finding 4: --create-pr crashes on detached HEAD or non-git directory

**Severity:** MEDIUM
**File:** `tekton_guard/cli.py`, lines 16-52

**Description:**
`_create_fix_pr` runs `git checkout -b <branch>` without first verifying: (a) the current directory is a git repository, (b) the user is on a branch (not detached HEAD), (c) the `origin` remote exists. The `subprocess.CalledProcessError` handler prints a generic error but does not clean up the branch that may have been partially created.

Specific failure modes:
- Non-git directory: `git checkout -b` fails with exit 128. The error message is unhelpful ("Error creating PR: ...").
- Detached HEAD: `git checkout -b` succeeds, but after the PR the user is left on the new branch with no way to know what branch they were originally on.
- No `origin` remote: `git push -u origin` fails. The local branch and commit are created but not cleaned up.
- Dirty working tree from non-tekton files: `git add -A` stages everything in the repo, not just the files modified by `--fix`. This could include unrelated unstaged changes.

**Fix:**
1. Before any git operations, verify `git rev-parse --is-inside-work-tree` succeeds.
2. Save and restore the original branch: `git rev-parse --abbrev-ref HEAD` (and detect `HEAD` for detached state).
3. Replace `git add -A` with `git add <specific files>`, using the list of files actually modified by `FixEngine`.
4. On failure, attempt to switch back to the original branch and delete the new branch.

---

## Finding 5: TKN-LIMIT-001 fires on every step in every Task/Pipeline fixture (noise problem)

**Severity:** LOW
**File:** `tekton_guard/checks/limits.py`, lines 11-31

**Description:**
TKN-LIMIT-001 fires whenever a step has no `resources.requests` or `resources.limits`. None of the 25 test fixtures include resource requests/limits on any step. This means TKN-LIMIT-001 produces a finding for every step and sidecar in every Task and Pipeline fixture.

In real-world Konflux/Tekton usage, resource limits are typically set by LimitRange objects at the namespace level, not in the Task spec. Reporting a LOW finding for every single step creates significant noise that buries higher-severity findings.

No test in the test suite validates TKN-LIMIT-001 behavior at all (the `TestTimeout` class tests only TKN-LIMIT-002).

**Fix:**
1. Consider making TKN-LIMIT-001 severity INFO by default, or off-by-default in the config.
2. Add a config option like `checks.TKN-LIMIT-001.enabled: false` or `checks.TKN-LIMIT-001.severity: INFO`.
3. Add explicit test coverage for TKN-LIMIT-001, including a fixture with resource limits set to verify the check correctly skips those steps.
4. Document that LimitRange-based enforcement is the recommended approach and this check is informational.

---

## Finding 6: Zero test coverage for verify_pins, _resolve_image_digest, _create_fix_pr, and calculate_risk_scores

**Severity:** HIGH
**File:** Multiple

**Description:**
Four public/semi-public functions have zero test coverage:

1. **`verify_pins()`** (`fixer.py:107-151`): Iterates resources checking stale SHA pins. No test mocks the GitHub API call or validates the iteration logic. The function has a subtle bug: it resolves against `"HEAD"` (line 123) regardless of the original branch the SHA was pinned from. If a repo has multiple branches, comparing the pinned SHA to the default branch HEAD is misleading.

2. **`_resolve_image_digest()`** (`fixer.py:54-104`): OCI registry interaction with Docker Hub token negotiation. No test validates the image reference parsing logic (which has edge cases: port numbers in registries like `localhost:5000/image:tag` where the colon-split on line 63 produces wrong results for `registry:port/repo:tag`).

3. **`_create_fix_pr()`** (`cli.py:16-52`): Entire git+gh workflow untested. The `--head "tekton-guard/"` filter on line 28 uses a prefix match that could match unrelated branches.

4. **`calculate_risk_scores()`** (`graph.py:104-138`): Risk scoring with blast radius bonuses. No test validates the tier boundaries, the bonus thresholds (2 and 6 consumers), or edge cases like unknown severity strings.

**Fix:**
1. Add unit tests for `verify_pins` with mocked `_resolve_git_sha` (patch the function, inject controlled return values).
2. Add unit tests for `_resolve_image_digest` parsing logic, at minimum testing: `registry:port/repo:tag`, `library/image:tag`, `image:tag` (Docker Hub shorthand), `image@sha256:...` (already pinned). Network calls should be mocked.
3. Add unit tests for `_create_fix_pr` with mocked `subprocess.run`. Test the happy path, missing `gh`, detached HEAD, and existing PR detection.
4. Add unit tests for `calculate_risk_scores` covering: zero blast radius, threshold boundaries (1, 2, 6 consumers), unknown severity strings, empty findings list.

---

## Finding 7: Placeholder image digest in Konflux task will fail in production

**Severity:** CRITICAL
**File:** `tekton-guard-task.yaml`, line 41

**Description:**
The task step image is `python:3.12-slim@sha256:abc123`. The digest `sha256:abc123` is a placeholder, not a real SHA-256 digest (real digests are 64 hex characters). This task definition will fail with an image pull error in any cluster that attempts to run it.

Additionally, the task installs tekton-guard at runtime via `pip install -q git+https://github.com/ugiordan/tekton-guard.git` (line 54), which:
- Fetches the latest commit from the default branch (mutable reference, the exact problem tekton-guard detects as TKN-PIN-001).
- Adds network latency and a PyPI/GitHub dependency to every scan run.
- Could fail if GitHub is unreachable or rate-limited.

The task would flag itself with TKN-PIN-003 (unpinned step image, since the digest is invalid) and the pip install line represents a supply-chain risk.

**Fix:**
1. Replace `sha256:abc123` with the actual digest of `python:3.12-slim`. Run `crane digest python:3.12-slim` or `skopeo inspect` to get the real value.
2. Pin the pip install to a specific commit or tag: `pip install git+https://github.com/ugiordan/tekton-guard.git@v1.1.0` (or a SHA).
3. Better yet, build a dedicated container image with tekton-guard pre-installed and use that as the step image, eliminating the runtime pip install entirely.

---

## Finding 8: _resolve_image_digest misparses images with registry port numbers

**Severity:** MEDIUM
**File:** `tekton_guard/fixer.py`, lines 62-66

**Description:**
The image reference parser splits on `:` to separate tag from repository:

```python
parts = image.split(":")
if len(parts) < 2:
    return None
tag = parts[-1]
repo_part = ":".join(parts[:-1])
```

For an image like `localhost:5000/myimage:v1`, `parts` becomes `["localhost", "5000/myimage", "v1"]`. `tag` = `"v1"` (correct), `repo_part` = `"localhost:5000/myimage"` (correct). This case works.

But for `localhost:5000/myimage` (no tag, implicit `latest`), `parts` becomes `["localhost", "5000/myimage"]`. `tag` = `"5000/myimage"` (wrong), `repo_part` = `"localhost"` (wrong). The function then tries to resolve `localhost/v2/5000/myimage/manifests/localhost` which will fail.

This also affects images like `myregistry.io:443/org/repo` (HTTPS on explicit port, no tag).

**Fix:**
Use a proper OCI reference parser. At minimum, check if `parts[-1]` looks like a tag (no `/` characters) before treating it as one. If the last segment contains `/`, it's a registry port, not a tag. Fall back to `latest` as the implicit tag.

---

## Finding 9: verify_pins always compares against HEAD of default branch, not the original branch

**Severity:** LOW  
**File:** `tekton_guard/fixer.py`, lines 122-123

**Description:**
`verify_pins` calls `_resolve_git_sha(ref.url, "HEAD")` for every pinned SHA. This resolves to the HEAD of the repo's default branch. If the pipeline was originally pinned to a feature or release branch (e.g., `release-1.0`), comparing against the default branch HEAD will always show a mismatch, producing a false positive "stale pin" report.

There is no way to recover the original branch name from the pinned SHA alone (since the revision field was replaced with a SHA), so the function would need traceability metadata (e.g., a comment like `# was: release-1.0`) or a resolver param like `branch` to know what to compare against.

**Fix:**
1. Document this limitation clearly: `verify_pins` only detects drift from the default branch.
2. Add support for a `branch` hint, either from a YAML comment or a new resolver param.
3. Consider comparing the pinned SHA against ALL branch heads and reporting stale only if the SHA is not the HEAD of any branch (more expensive but avoids false positives).

---

## Finding 10: Baseline entries without content_hash match findings with empty content_hash

**Severity:** MEDIUM
**File:** `tekton_guard/cli.py`, line 249

**Description:**
The baseline key construction uses `entry.get("content_hash", "")`. If a baseline entry is missing the `content_hash` field entirely, it gets `""`. The finding-side key uses `hashlib.sha256(f.get("current_value", f.get("message", "")).encode()).hexdigest()[:16]` which will never be `""` (it's always a 16-char hex string from SHA-256 of at least an empty string).

This means a baseline entry without `content_hash` will never match any finding. This is safe (no false suppression) but confusing. The user thinks they've baselined a finding but it's not actually suppressed.

Conversely, if an attacker crafts a baseline entry with `content_hash: ""` and a finding has `current_value: ""` and `message: ""`, the SHA-256 of `""` is `e3b0c44298fc1c14...` truncated to 16 chars, so it still won't match `""`. This is safe.

However, the `--update-baseline` command always populates `content_hash`, so this is only an issue for manually edited baselines.

**Fix:**
1. When loading baseline entries, validate that `content_hash` is present and is a 16-char hex string. Reject entries that don't match this format with a warning.
2. Document the baseline file format so manual editors know `content_hash` is required.

---

## Finding 11: _create_fix_pr prefix match on branch name can match unrelated branches

**Severity:** LOW
**File:** `tekton_guard/cli.py`, line 28

**Description:**
The existing-PR check uses `--head "tekton-guard/"` which is a prefix match. If someone has a branch named `tekton-guard/something-unrelated`, the tool will skip creating the fix PR even though the existing PR is unrelated. This is a minor usability issue but could cause confusion in repos that use the `tekton-guard/` namespace for other purposes.

**Fix:**
Use `--head tekton-guard/auto-pin-` as the prefix to be more specific, or parse the returned JSON to check the branch name more precisely.

---

## Summary

| # | Severity | Rule/Area | Description |
|---|----------|-----------|-------------|
| 1 | HIGH | Baseline | content_hash collision allows cross-finding suppression |
| 2 | MEDIUM | Baseline | Malformed/naive expiry dates silently treated as non-expired |
| 3 | MEDIUM | OCI resolution | Missing manifest list Accept types causes silent failure on multi-arch |
| 4 | MEDIUM | --create-pr | Crashes on non-git dir, detached HEAD; stages unrelated files |
| 5 | LOW | TKN-LIMIT-001 | Fires on every step in every fixture; no test coverage |
| 6 | HIGH | Test coverage | Four functions with zero test coverage (verify_pins, resolve_image_digest, create_fix_pr, calculate_risk_scores) |
| 7 | CRITICAL | Konflux task | Placeholder digest sha256:abc123 will fail in production |
| 8 | MEDIUM | OCI resolution | Registry port numbers misparsed when tag is absent |
| 9 | LOW | verify_pins | Always compares against default branch HEAD, not original branch |
| 10 | MEDIUM | Baseline | Missing content_hash silently fails to match |
| 11 | LOW | --create-pr | Prefix match on branch name too broad |
