<p align="center">
  <img src="site/docs/images/logo.svg" alt="tekton-guard logo" width="120">
</p>

# tekton-guard

Static security analysis for Tekton pipeline definitions.

tekton-guard parses Tekton CRDs (PipelineRun, Pipeline, Task, StepAction, TriggerTemplate, EventListener) and runs 50 security checks covering supply chain integrity, trust classification, and pipeline logic manipulation. It catches what pattern-matching tools can't: transitive reference chains, resolver trust, cross-resource data flow, CEL injection, and pipeline execution bypass.

**[Documentation](https://ugiordan.github.io/tekton-guard/)** | **[Detection Rules Reference](https://ugiordan.github.io/tekton-guard/reference/rules/)**

## Install

```bash
pip install git+https://github.com/ugiordan/tekton-guard.git
```

Requires Python 3.10+ and `ruamel.yaml`.

### GitHub Action
```yaml
- uses: ugiordan/kube-security-action@v1
```

### Pre-commit
```yaml
repos:
  - repo: https://github.com/ugiordan/tekton-guard
    rev: v1.0.0
    hooks:
      - id: tekton-guard
```

## Quick Start

```bash
tekton-guard /path/to/repo --format text
```

Example output:
```
Tekton Security Scan: opendatahub-operator
Found 4 issue(s)

[HIGH] TKN-PIN-001: Mutable pipeline revision
  File: .tekton/push.yaml:48
  PipelineRun references pipeline with mutable revision 'main'
  Fix: Pin revision to a 40-character commit SHA

[MEDIUM] TKN-RES-003: PaC-sourced parameter taint
  File: .tekton/push.yaml:2
  PipelineRun passes PaC template variables via param 'git-url'
  Fix: Pass through environment variables instead of direct interpolation

Summary: 2 HIGH, 2 MEDIUM
```

## What It Detects

50 checks across 12 categories:

- **Pinning** (5): mutable pipeline/task/StepAction refs, unpinned bundles, mutable step images
- **Trust** (7): untrusted sources, HTTP resolver without digest, cluster resolver in shared namespace, unknown resolver types
- **Trigger Security** (9): CEL injection (CRITICAL), TriggerTemplate injection, EventListener security, PaC Repository scope
- **Pipeline Logic** (7): security task not in finally, onError:continue bypass, parameterized images, TOCTOU, retries on security tasks
- **Chains Readiness** (6): VerificationPolicy regex, result poisoning, SBOM
- **Result Injection** (3): script injection, args interpolation, PaC parameter taint
- **Security Context** (2): privileged containers, root user
- **Volume Mounts** (2): host path, container runtime socket
- **ServiceAccount** (2): default or missing SA
- **Workspace** (2): secret without readOnly, shared with untrusted tasks
- **Exfiltration** (2): secret access + network tools
- **Resource Limits** (3): missing resources, excessive timeouts, timeout mismatch

## Why tekton-guard?

| Tool | Tekton Semantic | Cross-Resource | Auto-Fix | Supply Chain |
|------|:-:|:-:|:-:|:-:|
| **tekton-guard** | Yes | Yes | Yes | Yes |
| Semgrep | No | No | No | No |
| kube-linter | No | No | No | No |
| Enterprise Contract | No | No | No | Yes |
| IBM/tekton-lint | Yes | No | No | No |

tekton-guard is the only tool that performs semantic security analysis of Tekton pipeline definitions with cross-resource correlation, auto-fix, and supply chain integrity checks. No dedicated Tekton security scanner existed before this tool.

## Key Features

- **Auto-fix** (`--fix`): resolves mutable git refs to SHA via GitHub API, pins container images to digests
- **Cross-repo resolution** (`--resolve`): follows git resolver URLs to scan remote Pipeline/Task definitions
- **Dependency graph** (`--graph`): maps pipeline reference chains with blast radius analysis
- **CI gate**: `--diff-base`, `--baseline` with content fingerprinting, `--fail-on` severity threshold
- **SARIF output**: integrates with GitHub Code Scanning
- **PaC-aware**: suppresses false positives from PipelinesAsCode template variables and Konflux patterns

## Output Formats

- **Text**: human-readable with severity summary
- **JSON**: machine-parseable findings with docs_url per finding
- **SARIF**: integrates with GitHub Code Scanning, GitLab SAST

```bash
tekton-guard /path/to/repo --format sarif --output results.sarif
```

## Ecosystem Tested

- 21 RHOAI repos: 369 findings
- tektoncd catalog: 1,076 files, zero crashes, 2,192 findings
- konflux-ci/build-definitions: 442 files, 913 findings
- odh-konflux-central: 331 files, 925 findings

## License

Apache 2.0
