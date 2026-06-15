# Detection Rules

## Pinning (TKN-PIN)

### TKN-PIN-001: Mutable pipeline revision
- **Severity**: HIGH
- **CWE**: CWE-829
- **Detect**: `pipelineRef.resolver: git` with `revision` param that is not a 40-character hex SHA
- **Risk**: A push to the referenced branch can alter the build pipeline without any commit to this repository, breaking SLSA Build L3
- **Fix**: Pin revision to a 40-character commit SHA. Use Renovate or Mintmaker to keep SHA-pinned refs up to date.

### TKN-PIN-002: Mutable task reference (git resolver)
- **Severity**: HIGH
- **CWE**: CWE-829
- **Detect**: `taskRef.resolver: git` with non-SHA revision in Pipeline definitions
- **Fix**: Pin the task's git revision to a 40-character commit SHA.

### TKN-PIN-003: Unpinned task bundle
- **Severity**: HIGH
- **CWE**: CWE-829
- **Detect**: `taskRef.resolver: bundles` where bundle param lacks `@sha256:` digest
- **Fix**: Pin the bundle reference to include `@sha256:<digest>`.

### TKN-PIN-004: Mutable step image
- **Severity**: MEDIUM
- **CWE**: CWE-829
- **Detect**: `steps[].image` without `@sha256:` digest in Task/StepAction definitions
- **Fix**: Pin the image to a digest.

### TKN-PIN-005: Mutable StepAction reference
- **Severity**: HIGH
- **CWE**: CWE-829
- **Detect**: Step-level `ref.resolver: git` with mutable revision
- **Fix**: Pin the StepAction's git revision to a 40-character commit SHA.

## Trust (TKN-TRUST)

### TKN-TRUST-001: Pipeline from untrusted source
- **Severity**: HIGH
- **CWE**: CWE-829
- **Detect**: `pipelineRef.resolver: git` with URL not in `trusted_git_sources`
- **Fix**: Use a pipeline from a trusted source or add the source to config.

### TKN-TRUST-002: Task from untrusted source
- **Severity**: HIGH
- **CWE**: CWE-829
- **Detect**: `taskRef.resolver: git|hub` from untrusted source
- **Fix**: Use tasks from trusted sources.

### TKN-TRUST-003: Unverified cluster task reference
- **Severity**: MEDIUM
- **CWE**: CWE-829
- **Detect**: `taskRef.name` without resolver (cluster-local, mutable, unversioned)
- **Fix**: Use a bundle or git resolver with a pinned reference.

## ServiceAccount (TKN-SA)

### TKN-SA-001: Default ServiceAccount
- **Severity**: HIGH
- **CWE**: CWE-269
- **Detect**: `serviceAccountName: default` on PipelineRun/TaskRun
- **Fix**: Create and use a dedicated ServiceAccount with minimal RBAC.

### TKN-SA-002: Missing ServiceAccount
- **Severity**: MEDIUM
- **CWE**: CWE-269
- **Detect**: PipelineRun/TaskRun with no `serviceAccountName` set
- **Fix**: Explicitly set serviceAccountName.

## Workspace (TKN-WS)

### TKN-WS-001: Secret workspace without readOnly
- **Severity**: LOW
- **CWE**: CWE-732
- **Detect**: Workspace backed by secret without `readOnly: true`
- **Fix**: Add `readOnly: true` to the workspace binding.

### TKN-WS-002: Shared workspace with untrusted tasks
- **Severity**: MEDIUM
- **CWE**: CWE-732
- **Detect**: Multiple tasks sharing a workspace where at least one task is from an untrusted source
- **Fix**: Isolate untrusted tasks with separate workspaces.

## Result Injection (TKN-RES)

### TKN-RES-001: Parameter/result interpolation in script block
- **Severity**: MEDIUM
- **CWE**: CWE-94
- **Detect**: `$(params.*)` or `$(tasks.*.results.*)` used inside `script:` blocks
- **Risk**: The Tekton equivalent of GitHub Actions `${{ }}` injection. Untrusted input interpolated into scripts enables arbitrary code execution.
- **Fix**: Pass values as environment variables instead of interpolating in scripts.

### TKN-RES-002: Parameter interpolation in command args
- **Severity**: LOW
- **CWE**: CWE-78
- **Detect**: `$(params.*)` used in `args:` or `command:` arrays
- **Fix**: Validate parameter values before use.

## Chains Readiness (TKN-CHAIN)

### TKN-CHAIN-001: Build pipeline without Chains annotations
- **Severity**: LOW
- **CWE**: CWE-345
- **Detect**: Build-type PipelineRun without Chains or AppStudio annotations
- **Fix**: Ensure the pipeline produces IMAGE_URL and IMAGE_DIGEST results for Tekton Chains.

### TKN-CHAIN-002: Missing provenance annotations
- **Severity**: INFO
- **CWE**: CWE-345
- **Detect**: Build PipelineRun lacking `build.appstudio.redhat.com/commit_sha` annotation
- **Fix**: Add provenance annotations for SLSA compliance.
