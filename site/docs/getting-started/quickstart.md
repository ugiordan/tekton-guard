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

## Use a config file

```bash
tekton-guard /path/to/repo --config .tekton-guard.yaml
```

See [Configuration](../guides/configuration.md) for config file format.
