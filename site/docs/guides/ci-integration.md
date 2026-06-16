# CI Integration

## CI Workflow

```mermaid
graph LR
    PR["PR Opened"] --> CHECKOUT["Checkout"]
    CHECKOUT --> SCAN["tekton-guard<br/>--diff-base main<br/>--format sarif"]
    SCAN --> SARIF["Upload SARIF"]
    SARIF --> GH["GitHub Code Scanning"]
    
    SCAN -->|findings?| FAIL["Exit 1<br/>PR Blocked"]
    SCAN -->|clean| PASS["Exit 0<br/>PR Passes"]
    
    SCAN -.->|--baseline| SUPPRESS["Suppress Known"]
    SCAN -.->|--fix --create-pr| FIXPR["Auto-Fix PR"]
    
    style PR fill:#e3f2fd,stroke:#1565c0
    style FAIL fill:#ffcdd2,stroke:#c62828
    style PASS fill:#c8e6c9,stroke:#2e7d32
    style FIXPR fill:#f3e5f5,stroke:#7b1fa2
```

## GitHub Actions

### Using the reusable action

tekton-guard ships a composite GitHub Action at `.github/actions/tekton-guard/action.yml`. This is the recommended way to integrate.

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
        with:
          fetch-depth: 0  # needed for --diff-base

      - uses: ./.github/actions/tekton-guard
        with:
          fail-on: HIGH
          diff-base: ${{ github.event.pull_request.base.sha }}
```

#### Action inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target` | Path to scan | `.` |
| `config` | Path to config file | none |
| `fail-on` | Minimum severity to fail on | `HIGH` |
| `format` | Output format (`json`, `sarif`, `text`) | `sarif` |
| `diff-base` | Only scan files changed since this ref | none |
| `baseline` | Path to baseline file for suppression | none |

When `format` is `sarif`, the action automatically uploads results to GitHub Code Scanning via `github/codeql-action/upload-sarif`.

### Manual workflow (without reusable action)

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
        with:
          fetch-depth: 0

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

### PR-only scanning with --diff-base

Scan only files changed in the PR, so you don't fail on pre-existing findings in unchanged files:

```yaml
      - name: Scan changed files only
        run: |
          tekton-guard . \
            --diff-base ${{ github.event.pull_request.base.sha }} \
            --format sarif --output results.sarif \
            --fail-on HIGH
```

### Baseline suppression

For repos with existing findings that can't be fixed immediately, use a baseline to suppress known issues. Only newly introduced findings will fail CI.

#### Step 1: Generate the baseline

```bash
tekton-guard . --update-baseline .tekton-guard-baseline.json
git add .tekton-guard-baseline.json
git commit -m "chore: add tekton-guard baseline"
```

#### Step 2: Use the baseline in CI

```yaml
      - name: Scan with baseline suppression
        run: |
          tekton-guard . \
            --baseline .tekton-guard-baseline.json \
            --format sarif --output results.sarif \
            --fail-on HIGH
```

New findings not in the baseline will still fail CI. As you fix existing findings, regenerate the baseline to keep it current.

### Combining diff-base and baseline

For maximum precision, combine both flags. `--diff-base` limits scanning to changed files, and `--baseline` suppresses known findings:

```yaml
      - name: Scan PR changes with baseline
        run: |
          tekton-guard . \
            --diff-base ${{ github.event.pull_request.base.sha }} \
            --baseline .tekton-guard-baseline.json \
            --format sarif --output results.sarif \
            --fail-on HIGH
```

### Auto-fix in CI

Run `--fix-dry-run` in CI to show what would be fixed, or use `--fix` in a dedicated workflow to auto-remediate:

```yaml
  tekton-guard-fix:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install tekton-guard
        run: pip install git+https://github.com/ugiordan/tekton-guard.git

      - name: Auto-fix mutable refs
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          tekton-guard . --fix --format text
          if [ -n "$(git diff)" ]; then
            git config user.name "github-actions[bot]"
            git config user.email "github-actions[bot]@users.noreply.github.com"
            git add .tekton/
            git commit -m "fix: pin mutable Tekton refs to commit SHAs"
            git push
          fi
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
