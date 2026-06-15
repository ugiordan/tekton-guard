# Configuration

tekton-guard uses a YAML configuration file to customize trust lists and check behavior.

## Config file

Create `.tekton-guard.yaml` in your project root:

```yaml
# Git sources considered trusted (URL prefix match)
trusted_git_sources:
  - "https://github.com/opendatahub-io/"
  - "https://github.com/konflux-ci/"
  - "https://github.com/redhat-appstudio/"

# Container registries considered trusted (image prefix match)
trusted_registries:
  - "quay.io/konflux-ci/"
  - "quay.io/redhat-appstudio/"

# Checks to skip entirely
skip_checks: []

# Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL)
min_severity: "LOW"

# Secret workspace names that are known-safe (suppress TKN-WS-001)
known_safe_secret_workspaces:
  - "git-auth"
```

## Trust lists

### trusted_git_sources

URL prefixes for git resolver sources considered trusted. PipelineRuns and tasks that reference pipelines from these sources will not trigger TKN-TRUST-001 or TKN-TRUST-002.

```yaml
trusted_git_sources:
  - "https://github.com/my-org/"
  - "https://github.com/another-org/specific-repo"
```

### trusted_registries

Image registry prefixes considered trusted. Used by TKN-TRUST-002 for bundle resolver trust checks.

```yaml
trusted_registries:
  - "quay.io/my-org/"
  - "registry.example.com/"
```

## Skipping checks

Disable specific checks by rule ID:

```yaml
skip_checks:
  - "TKN-CHAIN-001"
  - "TKN-CHAIN-002"
```

## Using the config

```bash
tekton-guard /path/to/repo --config .tekton-guard.yaml
```
