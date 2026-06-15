# CLI Reference

## Synopsis

```
tekton-guard [OPTIONS] TARGET
```

`TARGET` is a path to a repository directory (scans `.tekton/`) or a single YAML file.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--format`, `-f` | Output format: `json`, `sarif`, `text` | `json` |
| `--output`, `-o` | Write output to file | stdout |
| `--config`, `-c` | Config file path | none |
| `--min-severity` | Minimum severity to report | any |
| `--fail-on` | Exit 1 only if findings at or above this severity | any |
| `--exit-zero` | Always exit 0 regardless of findings | false |
| `--resolve` | Follow git resolver URLs to fetch remote resources | false |
| `--resolve-method` | Resolution method: `api` or `clone` | `api` |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings above threshold |
| `1` | Findings above threshold |
| `2` | Scanner error |

## Examples

```bash
# Scan a repo, output JSON
tekton-guard /path/to/repo

# Scan with text output
tekton-guard /path/to/repo -f text

# SARIF for GitHub Code Scanning
tekton-guard /path/to/repo -f sarif -o results.sarif

# Only HIGH+ findings fail CI
tekton-guard /path/to/repo --fail-on HIGH

# Scan with custom config
tekton-guard /path/to/repo -c .tekton-guard.yaml

# Follow remote references
tekton-guard /path/to/repo --resolve

# Informational run
tekton-guard /path/to/repo --exit-zero -f text
```
