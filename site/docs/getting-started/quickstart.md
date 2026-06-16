# Quick Start

Get scanning in under a minute. tekton-guard looks for `.tekton/` directories and scans all YAML files inside.

!!! tip "Prerequisites"
    - Python 3.10+
    - A repository with Tekton pipeline definitions (`.tekton/` directory)
    - Optional: `GITHUB_TOKEN` for auto-fix and cross-repo resolution

## Scan a Repository

```bash
tekton-guard /path/to/your/repo
```

## Scan a Single File

```bash
tekton-guard .tekton/my-pipeline-push.yaml
```

## Output Formats

tekton-guard supports three output formats for different workflows.

```bash
# JSON (default, for automation)
tekton-guard /path/to/repo --format json

# Human-readable text
tekton-guard /path/to/repo --format text

# SARIF (for GitHub Code Scanning)
tekton-guard /path/to/repo --format sarif
```

!!! example "Text output"
    ```
    Tekton Security Scan: /path/to/repo
    Found 3 issue(s)

    [HIGH] TKN-PIN-001: Mutable pipeline revision
      File: .tekton/push.yaml:49
      PipelineRun references pipeline via git resolver with mutable
      revision 'main' instead of a pinned commit SHA.
      Fix: Pin revision to a 40-character commit SHA.

    [LOW] TKN-WS-001: Secret workspace without readOnly
      File: .tekton/push.yaml:55
      Workspace backed by secret is not mounted as readOnly.
      Fix: Add 'readOnly: true' to the workspace binding.
    ```

## Filter by Severity

```bash
# Only report HIGH and CRITICAL
tekton-guard /path/to/repo --min-severity HIGH

# Fail CI only on HIGH+
tekton-guard /path/to/repo --fail-on HIGH
```

## Auto-Fix Mutable Refs

tekton-guard can automatically pin mutable git revisions to commit SHAs and add readOnly to secret workspaces.

!!! warning "GITHUB_TOKEN required for auto-fix"
    The `--fix` flag resolves mutable git references to pinned commit SHAs via the GitHub API. Set `GITHUB_TOKEN` with read access to the referenced repositories before running.

```bash
# Preview what would be fixed
tekton-guard /path/to/repo --fix-dry-run --format text

# Apply fixes (modifies YAML files in place)
GITHUB_TOKEN=ghp_... tekton-guard /path/to/repo --fix --format text
```

Currently fixable checks:

- **TKN-PIN-001, TKN-PIN-002, TKN-PIN-005** - pins mutable git revisions to SHAs
- **TKN-WS-001** - adds `readOnly: true` to secret-backed workspaces

!!! example "Auto-fix output"
    ```
    Fixed 3 finding(s): pinned mutable revisions to commit SHAs.
    ```

## Scan Only Changed Files (PR Workflow)

In a PR context, scan only files that changed relative to the base branch:

```bash
tekton-guard /path/to/repo --diff-base main --format text
```

## Use a Baseline to Suppress Known Findings

```bash
# Generate a baseline from current findings
tekton-guard /path/to/repo --update-baseline .tekton-guard-baseline.json

# Scan using the baseline (only new findings are reported)
tekton-guard /path/to/repo --baseline .tekton-guard-baseline.json
```

## Generate a Dependency Graph

Visualize cross-repo pipeline dependencies:

```bash
tekton-guard /path/to/repo --resolve --graph deps.json
cat deps.json | python -m json.tool
```

The graph shows repos as nodes and git resolver references as edges, useful for understanding blast radius when a shared pipeline is compromised.

## Use a Config File

```bash
tekton-guard /path/to/repo --config .tekton-guard.yaml
```

See [Configuration](../guides/configuration.md) for config file format.

!!! info "What's next?"
    - **[CI Integration](../guides/ci-integration.md)** - Set up automated scanning in GitHub Actions
    - **[Configuration](../guides/configuration.md)** - Customize trust lists and check behavior
    - **[Detection Rules](../reference/rules.md)** - Understand all 27 security checks
    - **[False Positive Tuning](../guides/false-positives.md)** - Handle PaC templates and baselines
