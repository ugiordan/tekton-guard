# tekton-guard

Security scanner for Tekton pipeline definitions. Catches supply chain risks that pattern-matching tools (semgrep, kube-linter) can't detect: transitive reference chains, resolver trust classification, cross-resource data flow analysis, trigger injection, pipeline logic manipulation.

No dedicated Tekton security scanner existed before this tool.

## Demo

![tekton-guard Demo](site/docs/images/demo.gif)

## Documentation

Full documentation at [ugiordan.github.io/tekton-guard](https://ugiordan.github.io/tekton-guard/)

## What it checks

48 checks across 12 categories:

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Pinning** | TKN-PIN-001..005 | Mutable pipeline/task/StepAction refs, unpinned bundles, mutable step images |
| **Trust** | TKN-TRUST-001..006 | Untrusted git/hub sources, cluster resolver in shared namespace, HTTP resolver without digest, bundle without VerificationPolicy |
| **ServiceAccount** | TKN-SA-001..002 | Default or missing SA on PipelineRuns |
| **Workspace** | TKN-WS-001..002 | Secret workspaces without readOnly, shared workspaces with untrusted tasks |
| **Result Injection** | TKN-RES-001..003 | Script/args interpolation injection, PaC parameter taint |
| **Security Context** | TKN-SEC-001..002 | Privileged containers, root user |
| **Volume Mounts** | TKN-VOL-001..002 | Host path mounts, container runtime socket access |
| **Trigger Security** | TKN-TRIG-001..009 | CEL injection, permissive triggers, TriggerTemplate injection, EventListener security, PaC Repository scope |
| **Exfiltration** | TKN-EXFIL-001..002 | Secret access + network tools, network tool detection |
| **Resource Limits** | TKN-LIMIT-001..002 | Missing resource requests, excessive timeouts |
| **Chains Readiness** | TKN-CHAIN-001..006 | Provenance annotations, VerificationPolicy regex, result poisoning, SBOM |
| **Pipeline Logic** | TKN-LOGIC-001..007 | Security task not in finally, onError:continue, parameterized images, TOCTOU, retries on security tasks |

## Install

```bash
pip install git+https://github.com/ugiordan/tekton-guard.git
```

Requires Python 3.10+ and `ruamel.yaml`.

## Usage

```bash
# Scan a repo's .tekton/ directory
tekton-guard /path/to/repo

# Text output
tekton-guard /path/to/repo --format text

# SARIF output (for GitHub Code Scanning)
tekton-guard /path/to/repo --format sarif --output results.sarif

# Use a config file with custom trust lists
tekton-guard /path/to/repo --config .tekton-guard.yaml

# Follow git resolver URLs to scan remote Pipeline/Task definitions
tekton-guard /path/to/repo --resolve

# Auto-fix mutable refs (requires GITHUB_TOKEN)
tekton-guard /path/to/repo --fix

# Only fail on HIGH+ severity
tekton-guard /path/to/repo --fail-on HIGH

# CI mode: diff-only scanning with baseline
tekton-guard /path/to/repo --diff-base main --baseline .tekton-guard-baseline.json

# Dependency graph with blast radius
tekton-guard /path/to/repo --graph graph.json

# Check if pinned SHAs are stale
tekton-guard /path/to/repo --verify-pins

# Include VerificationPolicy files for TRUST-006
tekton-guard /path/to/repo --policy-dir /path/to/policies/
```

## Exit codes

- `0`: no findings above threshold
- `1`: findings above threshold
- `2`: scanner error

## License

Apache 2.0
