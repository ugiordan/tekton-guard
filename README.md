# tekton-guard

Security scanner for Tekton pipeline definitions. Catches supply chain risks that pattern-matching tools (semgrep, kube-linter) can't: transitive reference chains, resolver trust classification, cross-resource data flow analysis.

No dedicated Tekton security scanner existed before this tool. The industry invested in GitHub Actions security (Zizmor, StepSecurity, Scorecard) but nothing equivalent for Tekton, despite it being the CNCF-standard pipeline engine and the foundation of Red Hat's build infrastructure (Konflux, OpenShift Pipelines).

## What it checks

16 checks across 6 categories:

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Pinning** | TKN-PIN-001..005 | Mutable pipeline/task/StepAction refs, unpinned bundles, mutable step images |
| **Trust** | TKN-TRUST-001..003 | Untrusted git/hub sources, unverified cluster tasks |
| **ServiceAccount** | TKN-SA-001..002 | Default or missing SA on PipelineRuns |
| **Workspace** | TKN-WS-001..002 | Secret workspaces without readOnly, shared workspaces with untrusted tasks |
| **Result Injection** | TKN-RES-001..002 | Param/result interpolation in scripts and args (CWE-94) |
| **Chains Readiness** | TKN-CHAIN-001..002 | Missing provenance annotations on build pipelines |

## Install

```bash
pip install .
```

Requires Python 3.10+ and `ruamel.yaml`.

## Usage

```bash
# Scan a repo's .tekton/ directory
tekton-guard /path/to/repo

# Text output
tekton-guard /path/to/repo --format text

# SARIF output (for GitHub Code Scanning)
tekton-guard /path/to/repo --format sarif

# Scan a single file
tekton-guard .tekton/push.yaml

# Use a config file with custom trust lists
tekton-guard /path/to/repo --config .tekton-guard.yaml

# Follow git resolver URLs to scan remote Pipeline/Task definitions
tekton-guard /path/to/repo --resolve

# Only fail on HIGH+ severity
tekton-guard /path/to/repo --fail-on HIGH

# Informational run (never fail)
tekton-guard /path/to/repo --exit-zero
```

## Exit codes

- `0`: no findings above threshold
- `1`: findings above threshold
- `2`: scanner error (bad path, parse failure)

## Configuration

Create a `.tekton-guard.yaml`:

```yaml
trusted_git_sources:
  - "https://github.com/opendatahub-io/"
  - "https://github.com/konflux-ci/"

trusted_registries:
  - "quay.io/konflux-ci/"
  - "quay.io/redhat-appstudio/"

skip_checks: []
min_severity: "LOW"

known_safe_secret_workspaces:
  - "git-auth"
```

## False positive suppression

Built-in suppression for PipelinesAsCode/Konflux patterns:
- PaC template variables (`{{revision}}`, `{{source_url}}`) are recognized as runtime-pinned
- AppStudio/Konflux pipelines with cluster-level Chains are not flagged for missing annotations
- `git-auth` workspace is suppressed by default (standard PaC pattern)

## Cross-repo resolution

With `--resolve`, the scanner follows git resolver URLs to fetch and scan remote Pipeline/Task definitions:

```bash
$ tekton-guard /path/to/repo --resolve --format text
Resolved 2 remote resource(s)
[HIGH] TKN-PIN-002: remote:org/pipeline-repo@main/pipeline/build.yaml:161
  Pipeline task 'init' references task via git resolver with mutable revision 'main'
```

## License

Apache 2.0
