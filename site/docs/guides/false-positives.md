# False Positive Tuning

tekton-guard includes built-in suppression for common Konflux/PipelinesAsCode patterns, plus baseline management for per-repo suppression.

## Built-in suppressions

### PaC template variables

PipelinesAsCode template variables like `{{ revision }}` and `{{ source_url }}` resolve to actual values (commit SHA, repo URL) at runtime. tekton-guard recognizes these as runtime-pinned and does not flag them.

```yaml
# NOT flagged: {{ revision }} resolves to commit SHA at runtime
pipelineRef:
  resolver: git
  params:
    - name: revision
      value: "{{ revision }}"

# FLAGGED: literal 'main' is mutable
pipelineRef:
  resolver: git
  params:
    - name: revision
      value: main
```

### Konflux/AppStudio Chains

PipelineRuns with `appstudio.openshift.io/application` or `appstudio.openshift.io/component` labels are recognized as Konflux-managed. Tekton Chains is configured at the cluster level for these pipelines, so TKN-CHAIN-001 is suppressed.

### Known-safe workspaces

The `git-auth` workspace is a standard PaC pattern for git authentication. It is suppressed by default for TKN-WS-001. Add other known-safe workspace names via config:

```yaml
known_safe_secret_workspaces:
  - "git-auth"
  - "my-custom-auth"
```

## Custom suppressions

### Skip checks entirely

Use `skip_checks` in your config to disable checks entirely:

```yaml
skip_checks:
  - "TKN-TRUST-003"  # We use cluster tasks intentionally
  - "TKN-EXFIL-002"  # Network tools are expected
```

### Filter by severity

Use `--min-severity` to filter out low-severity findings:

```bash
tekton-guard /path/to/repo --min-severity MEDIUM
```

### Baseline suppression

For repos with existing findings that can't be fixed immediately, use baseline files. Generate a baseline from current findings, then use it to suppress known issues in CI:

```bash
# Generate baseline
tekton-guard /path/to/repo --update-baseline .tekton-guard-baseline.json

# Use baseline (only new findings are reported)
tekton-guard /path/to/repo --baseline .tekton-guard-baseline.json --fail-on HIGH
```

This is the recommended approach for incremental adoption: start with a baseline of existing findings, then fix them over time while preventing new findings from being introduced.

### Diff-only scanning

In PR workflows, use `--diff-base` to scan only files changed since a given ref:

```bash
tekton-guard /path/to/repo --diff-base main --format text
```

This avoids flagging pre-existing issues in unchanged files.
