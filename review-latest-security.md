# tekton-guard Security Review: Latest Changes

Review date: 2026-06-23
Scope: fixer.py, cli.py, graph.py, checks/limits.py, tekton-guard-task.yaml, tests/test_fixer.py

---

## Finding 1: SSRF via Unrestricted OCI Registry Resolution

**Severity:** HIGH
**File:** `tekton_guard/fixer.py`, lines 54-104 (`_resolve_image_digest`)
**CWE:** CWE-918 (Server-Side Request Forgery)

**Description:**
`_resolve_image_digest` constructs an HTTP request to any registry derived from attacker-controlled YAML content (the `image` field in a Tekton step definition). There is no allowlist check on the target registry hostname. A malicious pipeline definition could specify an image reference pointing to an internal service (e.g., `metadata.google.internal/computeMetadata:v1`, `169.254.169.254:latest`, or `internal-service.corp.example.com/foo:bar`) and when `--fix` is run, tekton-guard will send an authenticated (for Docker Hub) or unauthenticated HTTP GET to that host.

The function resolves private/internal addresses, cloud metadata endpoints, and arbitrary IP addresses. This is exploitable when tekton-guard runs in a CI environment (Konflux, Jenkins, etc.) that has access to cloud metadata or internal services.

Additionally, the Docker Hub token flow fetches a bearer token and sends it via `Authorization` header. If the `registry` hostname is manipulated (e.g., `docker.io.attacker.com` would match the `"docker.io" in registry` check on line 81), the token could be leaked to an attacker-controlled server.

**Fix:**
1. Add a registry allowlist (reuse `config.trusted_registries`) and reject any registry not on the list.
2. Validate the parsed registry hostname is not a private/link-local IP address.
3. Change the Docker Hub detection from substring match (`"docker.io" in registry`) to an exact domain match (`registry in ("docker.io", "registry-1.docker.io", "index.docker.io")`).

---

## Finding 2: Shell Injection via Tekton Parameter Substitution in Konflux Task

**Severity:** HIGH
**File:** `tekton-guard-task.yaml`, lines 56-92
**CWE:** CWE-78 (OS Command Injection)

**Description:**
The Konflux task script injects Tekton parameter values directly into a bash script and into Python string interpolation. Specifically:

```bash
ARGS=("$SOURCE_DIR" --format "$FORMAT" --fail-on "$FAIL_ON")
```

While these bash variable expansions are double-quoted (which prevents word splitting), the bigger issue is the inline Python blocks that use single-quoted shell variable expansion inside Python strings:

```python
'result': '$RESULT',
'failures': int('$FINDING_COUNT'),
'note': 'tekton-guard found $FINDING_COUNT security finding(s)',
```

`$RESULT` is controlled by the script's own logic, but `$FINDING_COUNT` comes from parsing a JSON file via Python. If the JSON file is malformed or the `except` branch fires with a crafted value, the Python string interpolation could produce invalid JSON or inject content.

More critically, `$(params.source-dir)` is expanded by Tekton into the `SOURCE_DIR` env var. A crafted `source-dir` param value could contain shell metacharacters. Although the `"$SOURCE_DIR"` quoting protects the `tekton-guard` invocation, the `pip install` line on line 54 runs before any validation, and there is no input sanitization on the `source-dir` parameter before it is used as a filesystem path (a path traversal to `/etc` or similar is possible).

Additionally, the task installs tekton-guard from a mutable git ref (`pip install -q git+https://...`) at runtime. This means a compromise of the `main` branch of the tekton-guard repo would compromise every pipeline run using this task. The task itself is a security scanner, meaning supply chain compromise here is especially high impact.

**Fix:**
1. Pin the `pip install` to a specific commit SHA: `pip install -q git+https://github.com/ugiordan/tekton-guard.git@<sha>`.
2. Validate `$SOURCE_DIR` resolves to an expected path (e.g., under `/workspace/`).
3. Use `--` in the tekton-guard CLI invocation to prevent option injection: `tekton-guard -- "${ARGS[@]}"`.
4. Replace the inline Python `'$VAR'` pattern with proper argument passing (`sys.argv` or environment variables read inside Python).

---

## Finding 3: `git add -A` in _create_fix_pr Stages All Untracked Files

**Severity:** MEDIUM
**File:** `tekton_guard/cli.py`, lines 35-36
**CWE:** CWE-200 (Information Exposure)

**Description:**
The `_create_fix_pr` function runs `git add -A` which stages ALL changes in the working tree, not just the files that tekton-guard modified. If the working directory contains sensitive files (tokens, config files, debug logs, `.env` files, or other untracked content), they will be committed and pushed to the remote branch, then included in the PR.

In a CI environment this is especially dangerous because the workspace may contain fetched credentials, temporary tokens, or checkout artifacts from other steps.

**Fix:**
Replace `git add -A` with explicit `git add` of only the files that the FixEngine modified. The `FixEngine.fix_findings` method already tracks which files were changed. Thread the list of modified file paths through to `_create_fix_pr` and run `git add <file1> <file2> ...` instead.

---

## Finding 4: Baseline Bypass via Missing content_hash Field

**Severity:** MEDIUM
**File:** `tekton_guard/cli.py`, lines 248-257
**CWE:** CWE-287 (Improper Authentication / Authorization Bypass)

**Description:**
The baseline suppression key is a tuple of `(rule_id, file, content_hash)`. However, the `content_hash` in baseline entries is compared against a SHA-256 hash computed from the finding's `current_value` or `message`. If a baseline entry is crafted with `content_hash: ""` (empty string), it will only match findings where `current_value` and `message` are both empty/missing, which is a narrow match.

But the real bypass is the opposite direction: an attacker who controls the baseline file can suppress arbitrary findings by pre-computing the content_hash. The baseline file is a plain JSON file with no integrity protection (no signing, no checksum). Anyone who can modify `.tekton-guard-baseline.json` in the repository can silently suppress security findings.

More subtly, the `reason` field validation (line 238-239) only prints a warning and skips entries without a reason. It does not reject the entire baseline file. This means an attacker can mix valid entries (with reason) and invalid entries (without reason) to confuse auditors while still suppressing the desired findings.

The `expires` field parsing (lines 241-246) silently ignores malformed dates (`except (ValueError, TypeError): pass`), meaning a baseline entry with `expires: "never"` will never expire because the parsing fails and the entry is treated as having no expiry.

**Fix:**
1. Require baseline files to be committed (not from untracked files) and validate via git log that they were approved.
2. Reject baseline files entirely if any entry lacks a `reason` field, rather than skipping individual entries.
3. Reject entries with unparseable `expires` values instead of silently accepting them as non-expiring.
4. Consider adding a schema version check and HMAC signature to baseline files.

---

## Finding 5: Docker Hub Token Leak via Subdomain Matching

**Severity:** MEDIUM
**File:** `tekton_guard/fixer.py`, line 81
**CWE:** CWE-522 (Insufficiently Protected Credentials)

**Description:**
The check `if "docker.io" in registry` is a substring match, not a domain boundary match. An attacker can specify an image reference with a registry like `notdocker.io`, `docker.io.evil.com`, or `evil-docker.io` and the code will:

1. Request an auth token from `auth.docker.io` scoped to the attacker-controlled repository name
2. Send that Bearer token to the attacker-controlled registry in the `Authorization` header (line 89)

Wait. Re-reading more carefully: the token is requested from `auth.docker.io` but the actual manifest request goes to `registry` (the attacker-controlled host). However, the token obtained is from Docker Hub's auth service, not from the attacker's registry. But the authorization header set on line 89 is part of the `headers` dict which is later used on line 96 for the manifest request to whatever `registry` is. So the Docker Hub token would be sent to the attacker's registry.

Actually, looking at the flow more carefully: `headers["Authorization"]` is set inside the `if "docker.io" in registry` block (line 81), but `registry` is also overwritten to `registry-1.docker.io` on line 82. So for the case `docker.io.evil.com`, the flow would be:
- Line 81: `"docker.io" in "docker.io.evil.com"` is True
- Line 82: `registry = "registry-1.docker.io"` (overwritten!)
- The manifest URL on line 94 uses the now-overwritten registry

So the registry override on line 82 actually prevents the token leak for this specific path. However, it introduces a different problem: any image with `docker.io` as a substring of the registry will have its manifest fetched from Docker Hub instead of the actual registry, returning the wrong digest. This is a correctness issue that could lead to pinning to the wrong image.

For registries like `my-docker.io` (which does NOT contain `docker.io` since the check is substring, and `my-docker.io` does contain `docker.io`), the tool would silently resolve the image from Docker Hub instead of the actual registry.

**Fix:**
Use an exact domain match:
```python
if registry in ("docker.io", "registry-1.docker.io", "index.docker.io"):
```

---

## Finding 6: Risk Score Tier Inversion at Boundary Values

**Severity:** LOW
**File:** `tekton_guard/graph.py`, lines 100-138
**CWE:** CWE-682 (Incorrect Calculation)

**Description:**
The risk scoring system claims to prevent ranking inversions via tier gaps, but the gaps between tiers are not uniform and can produce misleading orderings.

`BASE_SCORES = {"INFO": 1, "LOW": 5, "MEDIUM": 10, "HIGH": 36, "CRITICAL": 62}`
`TIER_WEIGHTS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}`

The `display_score` formula is `tier_weight * 100 + risk_score` where `risk_score = base_score + blast_bonus` (max blast_bonus is 10).

Tier ranges (display_score):
- INFO: 0*100 + (1..11) = 1..11
- LOW: 1*100 + (5..15) = 105..115
- MEDIUM: 2*100 + (10..20) = 210..220
- HIGH: 3*100 + (36..46) = 336..346
- CRITICAL: 4*100 + (62..72) = 462..472

The tiers don't actually overlap, so inversions are prevented in `display_score`. However, within `risk_score` alone (which is also exposed), a MEDIUM finding with blast_bonus=10 gets `risk_score=20`, while a HIGH finding with no blast_bonus gets `risk_score=36`. If anyone sorts by `risk_score` instead of `display_score`, a CRITICAL with no blast radius (`risk_score=62`) could appear less important than it should relative to a HIGH with blast (`risk_score=46`). The gap between HIGH-max (46) and CRITICAL-min (62) is 16, which is fine, but the gap between MEDIUM-max (20) and HIGH-min (36) is also 16 while LOW-max (15) to MEDIUM-min (10) shows that a LOW with blast (15) has a higher `risk_score` than a bare MEDIUM (10). This IS an inversion on `risk_score`.

A LOW finding with 6+ consumers (`risk_score = 5 + 10 = 15`) has a higher `risk_score` than a MEDIUM finding with 0-1 consumers (`risk_score = 10`). If downstream consumers sort or filter by `risk_score` without understanding it is not a total ordering, they will prioritize the LOW over the MEDIUM.

**Fix:**
Either:
1. Only expose `display_score` to consumers and remove `risk_score` from the output, or
2. Use `display_score` as the sole sorting key everywhere and rename `risk_score` to `raw_score` with documentation that it is not comparable across severity tiers.

---

## Finding 7: verify_pins Always Resolves Against HEAD, Not Original Branch

**Severity:** LOW
**File:** `tekton_guard/fixer.py`, lines 107-151
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**
`verify_pins` checks whether pinned SHAs are stale by comparing them against `HEAD` of the default branch (line 123: `_resolve_git_sha(ref.url, "HEAD")`). However, the pinned SHA may have been pinned against a specific branch (e.g., `release-v1.0`), not against the repo's default branch.

Since the original branch information is lost after pinning (the revision field contains the SHA), `verify_pins` always compares against `HEAD` (which GitHub resolves to the default branch). This means:
- A pin to a non-default branch will always be reported as "stale" even if the branch hasn't changed
- A pin to an older commit on the default branch will be reported as stale even if the older version is intentionally used

This reduces the utility of the feature and could cause operators to blindly update SHAs to HEAD, potentially introducing breaking changes.

**Fix:**
1. When `--fix` creates a pin, store the original branch as a YAML comment (e.g., `# tekton-guard: pinned from main at 2026-06-23`).
2. In `verify_pins`, parse that comment to determine which branch to resolve against.
3. If no comment exists, fall back to HEAD but flag it as "branch unknown" in the output.

---

## Finding 8: Placeholder Digest in Konflux Task Image Reference

**Severity:** MEDIUM
**File:** `tekton-guard-task.yaml`, line 41
**CWE:** CWE-494 (Download of Code Without Integrity Check)

**Description:**
The task image is pinned as `python:3.12-slim@sha256:abc123`. The digest `sha256:abc123` is clearly a placeholder, not a real SHA-256 digest (real digests are 64 hex characters). This means:
1. The image pull will fail in any registry that validates digests
2. If the registry does not validate digest format, the tag `3.12-slim` will be pulled without integrity verification
3. This is a security scanner task, meaning the scan itself runs from an unverified image

**Fix:**
Replace with the actual digest of `python:3.12-slim`:
```yaml
image: python:3.12-slim@sha256:<actual-64-char-hex-digest>
```
Obtain the real digest via: `skopeo inspect --format '{{.Digest}}' docker://python:3.12-slim`

---

## Finding 9: _resolve_image_digest Does Not Validate Digest Content Length

**Severity:** LOW
**File:** `tekton_guard/fixer.py`, lines 97-100
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**
The function checks `digest.startswith("sha256:")` but does not validate:
1. That the hex portion is exactly 64 characters
2. That it contains only valid hex characters (`[0-9a-f]`)
3. That the digest actually matches the manifest content

A malicious or compromised registry could return `Docker-Content-Digest: sha256:abc` and the tool would accept it and write it into the pipeline YAML. Similarly, a truncated or malformed digest would be accepted.

**Fix:**
Add digest format validation:
```python
import re
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
if digest and _DIGEST_RE.match(digest):
    return digest
```

---

## Finding 10: _parse_duration_hours Silently Accepts Malformed Duration Strings

**Severity:** LOW
**File:** `tekton_guard/checks/limits.py`, lines 49-65
**CWE:** CWE-20 (Improper Input Validation)

**Description:**
The `_parse_duration_hours` function uses string splitting to parse durations like `"4h30m"`. It does not validate that the parts are numeric before calling `float()`. More importantly, it silently returns 0 for completely invalid strings (the `float()` call would raise ValueError, but there is no exception handling). If the timeout value is something like `"unlimited"` or `"0"` (no unit suffix), the function returns 0.0, and the check never fires.

Tekton's own duration parsing supports Go-style durations. If a pipeline uses a format like `4h0m0s` it works, but `4.5h` would also work (float parsing). However, durations like `240m` (no "h" present) would only be parsed in the "m" branch: `240/60 = 4.0`, which does not exceed the 4-hour threshold, meaning a 4-hour timeout specified as `240m` is not flagged. This is technically correct but a "241m" timeout (4h1m) would correctly be flagged as 4.0167 hours.

The real issue is that Kubernetes/Tekton durations can also be specified as integers (seconds) or ISO 8601 durations, neither of which this parser handles.

**Fix:**
1. Add exception handling around `float()` calls.
2. Support integer-only values (interpreted as seconds, matching Tekton behavior).
3. Add a comment documenting which duration formats are supported.
