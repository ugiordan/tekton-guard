# tekton-guard

**Security scanner for Tekton pipeline definitions.**

tekton-guard catches supply chain risks in Tekton pipelines that pattern-matching tools (semgrep, kube-linter) can't detect: transitive reference chains, resolver trust classification, cross-resource data flow analysis.

## Why tekton-guard?

No dedicated Tekton security scanner existed before this tool. The industry invested heavily in GitHub Actions security (Zizmor, StepSecurity, Scorecard) but nothing equivalent for Tekton, despite it being the CNCF-standard pipeline engine and the foundation of Red Hat's build infrastructure (Konflux, OpenShift Pipelines).

Existing tools fall short:

| Tool | Limitation |
|------|-----------|
| **Semgrep** | Single-file pattern matching, can't follow Pipeline->Task->StepAction chains |
| **kube-linter** | Generic K8s checks, no Tekton semantic understanding |
| **Enterprise Contract** | Validates build outputs/attestations, not pipeline definitions |
| **Tekton Chains** | Signs pipeline results, doesn't validate pipeline definitions |
| **IBM/tekton-lint** | Correctness linter, zero security checks |

tekton-guard fills this gap with 16 security checks across 6 categories, purpose-built for Tekton CRDs.

## Quick example

```bash
$ tekton-guard /path/to/repo --format text

Tekton Security Scan: /path/to/repo
Found 3 issue(s)

[HIGH] TKN-PIN-001: Mutable pipeline revision
  File: .tekton/push.yaml:49
  PipelineRun references pipeline via git resolver with mutable
  revision 'main' instead of a pinned commit SHA.
  Fix: Pin revision to a 40-character commit SHA.

[HIGH] TKN-TRUST-001: Pipeline from untrusted source
  File: .tekton/push.yaml:49
  PipelineRun references a pipeline from an untrusted git source.
  Fix: Use a pipeline from a trusted source or update config.

[LOW] TKN-WS-001: Secret workspace without readOnly
  File: .tekton/push.yaml:55
  Workspace backed by secret is not mounted as readOnly.
  Fix: Add 'readOnly: true' to the workspace binding.
```

## What it checks

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Pinning** | TKN-PIN-001..005 | Mutable pipeline/task/StepAction refs, unpinned bundles, mutable step images |
| **Trust** | TKN-TRUST-001..003 | Untrusted git/hub sources, unverified cluster tasks |
| **ServiceAccount** | TKN-SA-001..002 | Default or missing SA on PipelineRuns |
| **Workspace** | TKN-WS-001..002 | Secret workspaces without readOnly, shared workspaces with untrusted tasks |
| **Result Injection** | TKN-RES-001..002 | Param/result interpolation in scripts and args (CWE-94) |
| **Chains Readiness** | TKN-CHAIN-001..002 | Missing provenance annotations on build pipelines |

## Get started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Detection Rules Reference](reference/rules.md)
