# CLI Reference

## Synopsis

```
tekton-guard [OPTIONS] TARGET
```

`TARGET` is a path to a repository directory (scans `.tekton/`) or a single YAML file.

## Options

### Output

| Flag | Description | Default |
|------|-------------|---------|
| **`--format`**, `-f` | Output format: `json`, `sarif`, `text` | `json` |
| **`--output`**, `-o` | Write output to file | stdout |

### Filtering

| Flag | Description | Default |
|------|-------------|---------|
| **`--config`**, `-c` | Config file path (trust lists, skip_checks) | none |
| **`--min-severity`** | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | any |
| **`--fail-on`** | Exit 1 only if findings at or above this severity | any finding |
| **`--exit-zero`** | Always exit 0 regardless of findings (informational runs) | false |

### Auto-Fix

| Flag | Description | Default |
|------|-------------|---------|
| **`--fix`** | Apply safe fixes (SHA pinning, readOnly). Requires `GITHUB_TOKEN` for git ref resolution. | false |
| **`--fix-dry-run`** | Preview fixes without applying them | false |

!!! warning "Destructive operation"
    The `--fix` flag modifies YAML files in place. Always run `--fix-dry-run` first to preview changes. Back up your `.tekton/` directory or ensure files are committed before applying fixes.

`--fix` and `--fix-dry-run` are mutually exclusive. Currently supported fixes:

- **TKN-PIN-001, TKN-PIN-002, TKN-PIN-005** - resolves mutable git revisions to commit SHAs via the GitHub API
- **TKN-WS-001** - adds `readOnly: true` to secret-backed workspace bindings

### CI/CD Gate

| Flag | Description | Default |
|------|-------------|---------|
| **`--diff-base`** | Only report findings in files changed since this git ref (e.g., `main`). Requires git. | none |
| **`--baseline`** | Baseline file to suppress known findings (`.tekton-guard-baseline.json`) | none |
| **`--update-baseline`** | Write current findings as a new baseline file to this path | none |

`--diff-base` is useful in PR workflows to scan only changed `.tekton/` files. `--baseline` suppresses findings that were already present before a PR, so CI only fails on newly introduced issues.

### Cross-Repo Resolution

| Flag | Description | Default |
|------|-------------|---------|
| **`--resolve`** | Follow git resolver URLs to fetch and scan remote Pipeline/Task definitions | false |
| **`--resolve-method`** | Resolution method: `api` (HTTP, fast, public repos) or `clone` (git, works with tokens) | `api` |

### Dependency Graph

| Flag | Description | Default |
|------|-------------|---------|
| **`--graph`** | Generate dependency graph JSON to this file path | none |

The graph output shows repos as nodes and git resolver references as edges, useful for visualizing blast radius when a shared pipeline is compromised.

## Exit Codes

| Code | Meaning |
|------|---------|
| **`0`** | No findings above threshold |
| **`1`** | Findings above threshold |
| **`2`** | Scanner error (bad path, parse failure) |

## Examples

!!! example "Basic scanning"
    ```bash
    # Scan a repo, output JSON
    tekton-guard /path/to/repo

    # Scan with text output
    tekton-guard /path/to/repo -f text

    # SARIF for GitHub Code Scanning
    tekton-guard /path/to/repo -f sarif -o results.sarif

    # Scan with custom config
    tekton-guard /path/to/repo -c .tekton-guard.yaml
    ```

!!! example "Filtering and CI gating"
    ```bash
    # Only HIGH+ findings fail CI
    tekton-guard /path/to/repo --fail-on HIGH

    # Informational run (never fail)
    tekton-guard /path/to/repo --exit-zero -f text

    # PR-only scan: only files changed since main
    tekton-guard /path/to/repo --diff-base main --fail-on HIGH

    # Baseline suppression: suppress known findings
    tekton-guard /path/to/repo --baseline .tekton-guard-baseline.json

    # Create a baseline from current findings
    tekton-guard /path/to/repo --update-baseline .tekton-guard-baseline.json
    ```

!!! example "Auto-fix and resolution"
    ```bash
    # Preview fixes without applying
    tekton-guard /path/to/repo --fix-dry-run -f text

    # Auto-fix: pin mutable refs to SHAs
    GITHUB_TOKEN=ghp_... tekton-guard /path/to/repo --fix

    # Follow remote references
    tekton-guard /path/to/repo --resolve

    # Generate dependency graph
    tekton-guard /path/to/repo --graph deps.json --resolve
    ```
