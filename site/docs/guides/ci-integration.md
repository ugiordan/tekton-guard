# CI Integration

## GitHub Actions

Add tekton-guard to your CI pipeline to catch Tekton security issues before merge.

### Basic workflow

```yaml
name: Tekton Security Scan
on:
  pull_request:
    paths:
      - '.tekton/**'

jobs:
  tekton-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install tekton-guard
        run: pip install git+https://github.com/ugiordan/tekton-guard.git

      - name: Run scan
        run: tekton-guard . --format sarif --output results.sarif --fail-on HIGH

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### With custom trust configuration

```yaml
      - name: Run scan with config
        run: tekton-guard . --config .tekton-guard.yaml --format sarif --output results.sarif
```

### Informational mode (no failure)

```yaml
      - name: Run scan (informational)
        run: tekton-guard . --exit-zero --format text
```

## Konflux / Pipelines as Code

tekton-guard can run as a Tekton Task in your Konflux pipeline:

```yaml
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: tekton-guard-scan
spec:
  params:
    - name: source-dir
      type: string
      default: /workspace/source
  steps:
    - name: scan
      image: python:3.12-slim
      script: |
        pip install git+https://github.com/ugiordan/tekton-guard.git
        tekton-guard $(params.source-dir) --format json --fail-on HIGH
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings above threshold |
| `1` | Findings above threshold |
| `2` | Scanner error (bad path, parse failure) |

Use `--fail-on` to control the threshold and `--exit-zero` to suppress failures entirely.
