# False Positive Tuning

tekton-guard includes built-in suppression for common Konflux/PipelinesAsCode patterns.

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

Use `skip_checks` in your config to disable checks entirely:

```yaml
skip_checks:
  - "TKN-TRUST-003"  # We use cluster tasks intentionally
```

Use `--min-severity` to filter out low-severity findings:

```bash
tekton-guard /path/to/repo --min-severity MEDIUM
```
