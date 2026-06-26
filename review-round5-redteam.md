# Round 5: Red Team Audit

Auditor: Red Team (adversarial review of 4 prior review rounds)
Date: 2026-06-25
Scope: Full codebase + all prior review findings (phase1, phase2, final, latest-security, latest-architecture, latest-completeness)

---

## 1. WEAK EVIDENCE IN PRIOR FIXES / COSMETIC FIXES

### FLAG: PHASE1-F1 (TOCTOU double-close) - Fixed, but replacement has a new edge case

The original double-close bug in `_apply_changes` was fixed. The current code at `fixer.py:432` sets `fd = -1` after closing and checks `if fd >= 0` in the except block. This is correct. However, the prior review never verified the fix and just moved on. Confirmed the fix is real.

### FLAG: PHASE1-F4 (workspace readOnly line array corruption) - STILL PRESENT

Phase 1 flagged that `_fix_workspace_readonly` embeds `\n` inside a single `lines[]` element (fixer.py:378: `lines[i] + "\n" + new_line`). The current `_apply_changes` at lines 417-420 now has a splice path for multi-line replacements (`"\n" in new_line` branch). This partially fixes the index-shift problem by doing `lines[line_idx:line_idx + 1] = new_lines`. But the underlying approach is still fragile: if a file has BOTH a workspace readOnly fix and a git ref fix, and the workspace fix is at a lower line number than the git ref fix, the reverse-sort at line 414 processes the git ref first (higher index), then the workspace fix (lower index). The workspace splice at a lower index inserts a new line, which shifts everything after it. Since the git ref fix was already applied at the old higher index, this is fine. But if two workspace fixes exist in the same file, both at lower indices than each other's splice point, the second splice will see a shifted array. No test covers this interaction. The "fix" relied on the reverse-sort being sufficient, which is only true if each splice adds exactly one line and no two splices interact within 1 line of each other. This was marked HIGH and is still a latent bug.

### FLAG: FINAL-F3 (rstrip(".git") vs removesuffix(".git")) - FIXED

The `config.py:37` now correctly uses `removesuffix(".git")`. Prior reviews flagged this and it was fixed. Confirmed.

### FLAG: FINAL-F2 (dedup drops legitimate LIMIT-002 findings) - PARTIALLY FIXED, RESIDUAL ISSUE

The dedup key was expanded from `(rule_id, file, line_start)` to `(rule_id, file, line_start, title)` at `checks/__init__.py:55`. Since the pipeline timeout finding has title "Excessive pipeline timeout" and the task timeout finding has title "Excessive task timeout", they now survive dedup. The test at `test_phase2_checks.py:138` confirms both raw findings are produced. However, the test at line 126 only asserts `len(limit002) >= 1`, not `== 2`. This means if the dedup regresses, the test still passes. The test is weak evidence of the fix.

### FLAG: LATEST-SECURITY-F1 (SSRF via OCI registry) - CLAIMED FIXED BUT NOT ACTUALLY FIXED

The prior review flagged that `_resolve_image_digest` sends requests to arbitrary registries from attacker-controlled YAML content. The current code at `fixer.py:106` still constructs `manifest_url = f"https://{registry}/v2/{repository}/manifests/{tag}"` where `registry` comes from parsing an image reference that originates from untrusted YAML. There is no allowlist, no IP validation, no private-range rejection. The claim was that trusted_registries from config could be used, but no code actually calls `config.is_trusted_registry()` before making the HTTP request. The SSRF is still exploitable when `--fix` is used on attacker-controlled pipeline definitions in CI. This is a HIGH that was reported but never actually patched.

### FLAG: LATEST-SECURITY-F2 (shell injection in Konflux task) - STILL PRESENT, SEVERITY UNDERSTATED

The `tekton-guard-task.yaml` lines 81-92 still use shell variable interpolation inside Python string literals passed to `python3 -c`. The `$RESULT` variable at line 84 is set by the script's own logic (`RESULT="SUCCESS"` or `RESULT="WARNING"`), so it's safe. But `$FINDING_COUNT` at line 88 comes from a Python one-liner that does `json.load(open(...)).get(...)` with a bare `except: print(0)`. If the JSON file is malformed in a specific way that produces a string like `0'); import os; os.system('id`, the Python3 -c invocation would execute it. The likelihood is low because the json.load either succeeds (returning an int or dict) or the except branch returns literal `0`. But the defense-in-depth concern is valid and was not addressed. The remediation ("use os.environ") was never applied.

### FLAG: LATEST-SECURITY-F3 (git add -A stages all files) - FIXED

The current `cli.py:35` uses `git add .tekton/` instead of `git add -A`. This scopes the add to only `.tekton/` files. Better than `-A`, but still not precise (it would pick up untracked files in `.tekton/` that weren't modified by the fixer). The original HIGH concern is mostly addressed.

### FLAG: LATEST-COMPLETENESS-F7 (placeholder digest sha256:abc123) - FIXED (sort of)

The `tekton-guard-task.yaml:42` now shows `image: python:3.12-slim` without any `@sha256:` digest at all. The TODO comment on line 41 says "pin to a real digest in production". So the placeholder crash was fixed by removing the placeholder entirely, but the underlying issue (unpinned image for a security scanner task) remains. The tool would flag its own task definition with TKN-PIN-004. This is ironic but not a crash bug anymore.

---

## 2. SEVERITY INFLATION / NOISE ANALYSIS

### FLAG: TKN-LIMIT-001 - SEVERE NOISE PROBLEM, SHOULD BE OFF-BY-DEFAULT OR INFO

TKN-LIMIT-001 fires on EVERY step and sidecar that lacks `resources.requests` or `resources.limits`. In real-world Konflux/RHOAI pipelines, almost no Task definition sets resource limits directly because LimitRange objects handle this at the namespace level. This check will generate 3-10+ LOW findings per PipelineRun/Task, burying actual security issues.

The check also has a logical inconsistency already flagged but never fixed: `if has_requests or has_limits: continue` means a step with ONLY requests (no limits) passes, even though that's the exact unbounded-burst DoS risk the check claims to detect (CWE-400).

Real-world impact: a Konflux repo with 5 PipelineRuns, each referencing 5-8 tasks with 2-3 steps each, would generate 50-120 TKN-LIMIT-001 findings. This is not actionable.

### FLAG: TKN-EXFIL-002 - LOW VALUE, NEAR-UNIVERSAL FALSE POSITIVES

TKN-EXFIL-002 fires on any step that uses `curl` or `wget` in its script, regardless of context. In Konflux pipelines, `curl` is used routinely for downloading build dependencies, checking readiness endpoints, or interacting with internal APIs. This check fires on almost every non-trivial Task. The dedup between EXFIL-001 and EXFIL-002 was never implemented (they have different rule_ids), so when a task has secret access AND curl, the user sees both findings for the same step.

### FLAG: TKN-RES-003 - MODERATE NOISE FOR LEGITIMATE PAC USAGE

TKN-RES-003 flags every PipelineRun parameter that uses PaC template variables like `{{ source_url }}` or `{{ revision }}`. In Konflux, this is the standard pattern for ALL PipelineRuns. Every single Konflux PipelineRun will trigger multiple TKN-RES-003 findings because PaC parameter passing IS the design pattern. The check should differentiate between params that reach script interpolation points (dangerous) and params that are used as git-clone arguments (the intended usage pattern, safe). Currently it has no data-flow analysis, so it flags everything.

### FLAG: TKN-TRIG-001 SEVERITY CRITICAL - MISLABELED

TKN-TRIG-001 flags CEL expressions that reference user-controlled body fields (e.g., `body.pull_request.head.ref`). It reports CRITICAL severity. But as Phase 2 Finding 4 correctly identified, CEL expressions that reference these fields in filter conditions (like `.startsWith("feature/")`) are SAFE. They are boolean checks, not value interpolations. The injection happens downstream when the value reaches a script via params. The check cannot distinguish filtering from value extraction, so it over-reports. CRITICAL severity for a filter condition is severity inflation.

### FLAG: TKN-SA-001 SEVERITY HIGH - QUESTIONABLE FOR PAC PIPELINES

TKN-SA-001 flags `serviceAccountName: default` as HIGH. In Konflux with PaC, the service account is typically managed by the PaC controller and may legitimately be "default" during template definition, with the actual SA set at runtime by PaC. Flagging this as HIGH without understanding the deployment context creates noise.

---

## 3. BLIND SPOTS: WHAT IS NOT CHECKED AT ALL

### BLIND_SPOT: No detection of Tekton Results poisoning (workspace-based)

Tekton pipelines pass data between tasks via Results and workspaces. A malicious task can write arbitrary content to `$(results.IMAGE_URL.path)` or `$(results.IMAGE_DIGEST.path)`, poisoning downstream tasks that trust those values. None of the 28 checks analyze whether results produced by untrusted tasks flow into security-critical consumers (like Chains attestation or Enterprise Contract). This is the most dangerous Tekton-specific attack vector, described in multiple Tekton security advisories.

### BLIND_SPOT: No detection of workspace data poisoning between tasks

TKN-WS-002 checks whether untrusted tasks SHARE a workspace, but it does not check what happens with the data. A compromised task writing to a shared workspace can modify source code, inject build artifacts, or alter configuration files that downstream tasks consume. The check flags the sharing but provides no analysis of whether the sharing is read-only from the untrusted side or whether the consuming task validates what it reads.

### BLIND_SPOT: No detection of stepAction ref substitution attacks

StepActions referenced via git resolver can be substituted at the PR level in PaC. An attacker submitting a PR can modify the `.tekton/` directory to point StepAction refs to their own fork. TKN-PIN-005 checks for mutable refs but does not check whether the PR modified the ref URL itself (which is the actual attack vector in PaC pull_request events).

### BLIND_SPOT: No analysis of `runAfter` ordering for security-critical tasks

A pipeline can define `runAfter` dependencies that determine execution order. If a security task (e.g., SAST scan) runs AFTER the deploy task, it's useless. No check validates that security tasks run BEFORE or at least concurrent with deployment/release tasks.

### BLIND_SPOT: No detection of `finally` task abuse for credential cleanup bypass

If a pipeline's `finally` block contains the only task that cleans up credentials or rotates tokens, and that task has a `when` condition, the cleanup can be skipped. TKN-TRIG-003 checks `when` on security tasks but doesn't specifically analyze `finally` tasks for cleanup-bypass patterns.

### BLIND_SPOT: No analysis of PipelineRun with `pipelineSpec` (inline pipeline)

The parser extracts `pipeline_tasks` only for `Pipeline` kind resources (parser.py:341). A `PipelineRun` with an inline `pipelineSpec` (instead of `pipelineRef`) would have its tasks entirely ignored. All checks that iterate `resource.pipeline_tasks` would produce zero findings for inline pipelines. This is a complete bypass of trust, pinning, and workspace checks for inline PipelineRuns.

### BLIND_SPOT: No detection of `env` value injection from task results

TKN-RES-001 checks for `$(params.*)` and `$(tasks.*)` in script blocks. But it does not check for the same interpolation patterns in `env` value fields. While using env vars is the recommended remediation for script injection, the env value itself can still be interpolated: `value: $(tasks.fetch.results.url)`. If that result is attacker-controlled, the env var contains the malicious payload. The check's own remediation creates a false sense of security.

### BLIND_SPOT: No detection of OCI bundle content vs. what was audited

When a pipeline uses a bundle resolver, the bundle contains a Task definition. But tekton-guard only checks the bundle reference (is it pinned? is the digest present?). It never fetches and inspects the bundle's contents. A pinned bundle could contain a privileged step, root execution, or script injection. The `--resolve` flag only works for git resolvers, not bundle resolvers.

### BLIND_SPOT: TaskRun with taskRef is never checked for pinning

The parser extracts `taskRef` for TaskRun resources (parser.py:329-330), but `check_pin_001` only checks `PipelineRun` (pinning.py:15), and `check_pin_002` only iterates `pipeline_tasks` and `finally_tasks` (which are empty for TaskRun). There is no check for a standalone TaskRun with an unpinned git resolver taskRef.

---

## 4. GROUPTHINK / CHALLENGED ASSUMPTIONS

### GROUPTHINK: "SHA pinning solves supply chain security"

All 4 review rounds and the entire tool assume that pinning git refs to SHAs and images to digests is the primary defense against supply chain attacks. This is necessary but not sufficient. A compromised commit that was already pinned (the SHA points to malicious code) is undetectable by pinning checks. The tool has no mechanism to verify that the pinned SHA was reviewed, approved, or signed. It also has no mechanism to detect that a pinned SHA was force-pushed over (possible with repo admin access). The reviews reinforced this assumption without questioning it.

### GROUPTHINK: "The tool should scan `.tekton/` directories"

The `find_tekton_files` function (parser.py:381) only scans `.tekton/` subdirectories. But Tekton resources can live anywhere in a repo (e.g., `deploy/`, `ci/`, `config/`, or root-level `pipeline.yaml`). In non-Konflux setups, `.tekton/` is not the standard location. The tool silently produces zero findings for repos that store pipeline definitions elsewhere. None of the 4 reviews questioned this assumption.

### GROUPTHINK: "GitHub is the only git hosting platform"

The resolver only supports GitHub URLs (resolver.py:18, fixer.py:29-30). The `_git_url_to_raw_url` function returns None for non-GitHub URLs. `_resolve_git_sha` only works with the GitHub API. GitLab, Bitbucket, and Gitea instances are completely unsupported for SHA resolution, remote resolution, and graph building. For RHOAI's internal GitLab-hosted repos, the tool is non-functional for `--fix`, `--resolve`, and `--verify-pins`. This limitation was noted in passing but never treated as a design issue.

### GROUPTHINK: "CEL expression analysis via string matching is sufficient"

TKN-TRIG-001 and TKN-TRIG-002 analyze CEL expressions via substring and regex matching. After 4 rounds, no reviewer challenged this approach. CEL is a Turing-incomplete but expressive language. Real CEL expressions in Konflux use functions like `.matches()`, `.contains()`, ternary operators, and variable binding. String matching will produce both false positives (flagging safe filter conditions) and false negatives (missing obfuscated references like `body["pull_request"]["head"]["ref"]` bracket notation). A proper approach would use a CEL parser library.

### GROUPTHINK: "All PaC variables are equally dangerous"

TKN-RES-003 treats all 8 hardcoded PaC variables as equally tainted. But `pull_request_number` (an integer) has very different risk characteristics than `source_branch` (a string that reaches git-clone arguments and potentially script interpolation). The flat "MEDIUM" severity for all PaC variable usage ignores actual exploitability differences.

### GROUPTHINK: Reviewers converged on a "fix the fixer" narrative

Across 4 rounds, approximately 40% of all findings target the fixer module (fixer.py, the `--fix` flag, the `--create-pr` flow). This is disproportionate. The core value of the tool is the detection engine (checks/*.py and parser.py), but those modules received much less scrutiny. The parser's PaC template preprocessing (parser.py:138-153) does a regex-based replacement that could produce invalid YAML for certain edge cases (e.g., a `{{ }}` inside a YAML anchor definition), but no review examined parser correctness in depth. The checks modules were reviewed in Phase 2 but not revisited in rounds 3-4 despite the code being extended.

---

## 5. ADDITIONAL FINDINGS NOT IN ANY PRIOR REVIEW

### NEW-F1: Baseline content_hash does not include line_start, creating cross-suppression risk (HIGH)

Looking at `cli.py:258`, the finding-side hash input is `f"{f.get('current_value', f.get('message', ''))}:{f.get('line_start', 0)}"`. This includes `line_start`. Good. But the `--update-baseline` at line 273 uses the same format. So a baseline entry generated for one finding cannot suppress a different finding with the same rule_id and file but different line and content. This is correct.

However, the baseline-side key at line 251 uses `entry.get("content_hash", "")`. If the content_hash in the baseline file was generated with the old format (without line_start), it won't match the new format (with line_start). There's no versioning or migration. Any baseline generated before the line_start addition is silently broken. No review noticed this migration gap.

### NEW-F2: _parse_duration_hours will crash on empty string after split (MEDIUM)

In `limits.py:55-56`, if `val` is `"h"` (just the letter h with no numeric prefix), `parts = val.split("h")` produces `["", ""]`, and `float("")` raises ValueError. There is no try/except around the float() calls. Same for `"m"` or `"s"` alone. While unlikely in real Tekton specs, a fuzzer or malformed YAML would crash the check and potentially abort the entire scan for that resource.

### NEW-F3: PipelineRun with inline pipelineSpec is completely unscanned (HIGH)

As noted in blind spots above, `parser.py:340-342` only extracts `pipeline_tasks` when `kind == "Pipeline"`. A PipelineRun with `spec.pipelineSpec.tasks` (an inline pipeline definition, which is valid Tekton API) would have `pipeline_tasks = []`. Every check that iterates `resource.pipeline_tasks` (pin_002, pin_003, pin_005, trust_002, trust_003, ws_002, trig_003) produces zero findings. This is a complete bypass. An attacker could embed an inline pipeline with unpinned refs, untrusted sources, and privilege escalation, and the tool would report nothing except maybe SA-002.

### NEW-F4: _extract_repo_id path extraction is brittle and platform-dependent (LOW)

`graph.py:148-150` splits file paths on `/` and looks for `.tekton` by index. On Windows (if the tool ever runs there), paths use `\`. More practically, if the file path doesn't have at least 2 components before `.tekton` (e.g., `.tekton/pipeline.yaml` as a relative path), the index `i-2` goes negative and extracts wrong components. This produces garbage node IDs in the dependency graph.

### NEW-F5: resolver.py _fetch_via_api path traversal check is insufficient (MEDIUM)

The path traversal check at `resolver.py:83` only checks `".." in path`. This misses URL-encoded traversal (`%2e%2e`), null bytes (`%00`), and symlink-based traversal. For the clone-based resolver, the `target.resolve().relative_to()` check at line 57 is correct. But the API-based resolver constructs a raw URL (`url/raw/revision/path`) and fetches whatever is at that URL. The `..` check prevents the most obvious traversal but the URL is sent to GitHub's servers which handle the resolution. The real risk is that a crafted `pathInRepo` like `../../../.github/workflows/deploy.yml` would be fetched by GitHub's raw endpoint even with the `..` check if the `..` appears URL-encoded. However, GitHub's raw endpoint does handle `..` resolution server-side, so this is more of a defense-in-depth gap than an active exploit.

---

## Summary

| Category | Count | Details |
|----------|-------|---------|
| Prior fixes that are cosmetic or incomplete | 3 | SSRF unfixed, workspace splice still buggy, shell injection unaddressed |
| Severity inflation / noise generators | 5 | TKN-LIMIT-001, TKN-EXFIL-002, TKN-RES-003, TKN-TRIG-001, TKN-SA-001 |
| Blind spots (entire attack classes missed) | 9 | Results poisoning, inline pipelineSpec, TaskRun refs, bundle contents, env injection, runAfter ordering, finally cleanup bypass, stepAction PR substitution, non-.tekton locations |
| Groupthink assumptions challenged | 6 | SHA pinning sufficiency, .tekton-only scanning, GitHub-only, CEL string matching, flat PaC severity, fixer-focused reviews |
| New findings not in any prior round | 5 | Baseline migration gap, duration parser crash, inline pipelineSpec bypass, repo ID extraction, API path traversal |
