# Quick Start

## Scan a repository

tekton-guard looks for `.tekton/` directories and scans all YAML files inside:

```bash
tekton-guard /path/to/your/repo
```

## Scan a single file

```bash
tekton-guard .tekton/my-pipeline-push.yaml
```

## Output formats

```bash
# JSON (default, for automation)
tekton-guard /path/to/repo --format json

# Human-readable text
tekton-guard /path/to/repo --format text

# SARIF (for GitHub Code Scanning)
tekton-guard /path/to/repo --format sarif
```

## Filter by severity

```bash
# Only report HIGH and CRITICAL
tekton-guard /path/to/repo --min-severity HIGH

# Fail CI only on HIGH+
tekton-guard /path/to/repo --fail-on HIGH
```

## Auto-fix mutable refs

tekton-guard can automatically pin mutable git revisions to commit SHAs. This requires a `GITHUB_TOKEN` with read access to the referenced repositories.

```bash
# Preview what would be fixed
tekton-guard /path/to/repo --fix-dry-run --format text

# Apply fixes (modifies YAML files in place)
GITHUB_TOKEN=ghp_... tekton-guard /path/to/repo --fix --format text
```

Currently fixable checks:
- TKN-PIN-001, TKN-PIN-002, TKN-PIN-005 (pins mutable git revisions to SHAs)
- TKN-WS-001 (adds `readOnly: true` to secret-backed workspaces)

## Scan only changed files (PR workflow)

In a PR context, scan only files that changed relative to the base branch:

```bash
tekton-guard /path/to/repo --diff-base main --format text
```

## Use a baseline to suppress known findings

```bash
# Generate a baseline from current findings
tekton-guard /path/to/repo --update-baseline .tekton-guard-baseline.json

# Scan using the baseline (only new findings are reported)
tekton-guard /path/to/repo --baseline .tekton-guard-baseline.json
```

## Generate a dependency graph

Visualize cross-repo pipeline dependencies:

```bash
tekton-guard /path/to/repo --resolve --graph deps.json
cat deps.json | python -m json.tool
```

The graph shows repos as nodes and git resolver references as edges, useful for understanding blast radius when a shared pipeline is compromised.

## Use a config file

```bash
tekton-guard /path/to/repo --config .tekton-guard.yaml
```

See [Configuration](../guides/configuration.md) for config file format.
