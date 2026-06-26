# kube-shield: Rename and Scope Expansion

**Date**: 2026-06-26
**Status**: Draft
**Author**: Ugo Giordano

## Problem

tekton-guard scans Tekton pipeline definitions for supply chain security issues (28 checks, 136 tests). But RHOAI's deployment surface includes Helm charts (odh-gitops), Kustomize overlays, and ArgoCD applications. The tool's architecture (parser, checks/ package, auto-fix, CI gate) is generic: only the parser and checks are Tekton-specific. Extending to other K8s definition sources is natural, but the name "tekton-guard" no longer fits.

## Solution

Rename `tekton-guard` to `kube-shield`. Expand to scan Tekton pipelines, Helm charts, Kustomize overlays, ArgoCD applications, and generic K8s manifests for supply chain integrity violations.

## Identity and Scope

**kube-shield**: static security analysis for Kubernetes supply chain definitions.

Scope boundary (what kube-shield checks vs what other tools check):

| Concern | kube-shield | kube-linter | kube-chainsaw |
|---------|-------------|-------------|---------------|
| Reference pinning (SHA, digest, version) | Yes | No | No |
| Source trust (repos, registries, charts) | Yes | No | No |
| Template/script injection | Yes | No | No |
| Secrets in definitions | Yes | No | No |
| GitOps sync policy security | Yes | No | No |
| Resource best practices (probes, limits) | No | Yes | No |
| RBAC privilege chain analysis | No | No | Yes |
| Privileged containers, hostPath mounts | Yes (generic) | Yes (generic) | No |

kube-shield focuses on: "can this deployment definition be tampered with, and through what attack path?" It does not replicate kube-linter's resource hygiene checks or kube-chainsaw's RBAC graph analysis.

## Architecture

### Package rename

```
tekton_guard/ -> kube_shield/
```

CLI command: `kube-shield` (replaces `tekton-guard`)

### Source type auto-detection

kube-shield detects the source type from directory structure:

| Directory/File | Source Type |
|---------------|-------------|
| `.tekton/*.yaml` | Tekton |
| `Chart.yaml` | Helm |
| `kustomization.yaml` | Kustomize |
| ArgoCD `Application` kind | ArgoCD |
| Other K8s YAML | Generic K8s |

The `--type` flag overrides auto-detection.

### Parser modules

```
kube_shield/
├── parsers/
│   ├── __init__.py     # auto-detect, dispatch to correct parser
│   ├── tekton.py       # current parser.py (Tekton CRDs)
│   ├── helm.py         # helm template rendering + values analysis
│   ├── kustomize.py    # kustomize build + remote base tracking
│   ├── argocd.py       # ArgoCD Application CRD parsing
│   └── k8s.py          # generic K8s manifest parsing
```

Each parser produces a common `Resource` object (generalized from `TektonResource`) that checks operate on. Tekton-specific fields (pipeline_ref, task_ref, etc.) remain but are optional.

### Check prefix convention

| Prefix | Source | Example |
|--------|--------|---------|
| `TKN-` | Tekton | TKN-PIN-001 (mutable pipeline ref) |
| `HLM-` | Helm | HLM-PIN-001 (unpinned chart dependency) |
| `KST-` | Kustomize | KST-PIN-001 (remote base without SHA) |
| `AGO-` | ArgoCD | AGO-PIN-001 (unpinned targetRevision) |
| `K8S-` | Generic | K8S-SEC-001 (privileged container) |

### Existing checks migration

Current TKN-* checks remain unchanged (backward compatible). TKN-SEC-001/002 and TKN-VOL-001/002 become aliases for K8S-SEC-001/002 and K8S-VOL-001/002 (fire on any K8s manifest, not just Tekton).

## New Checks

### Helm (HLM-*)

| Check | Severity | What it detects |
|-------|----------|-----------------|
| HLM-PIN-001 | HIGH | Chart dependency in Chart.yaml without pinned version |
| HLM-PIN-002 | MEDIUM | Mutable image tag in values.yaml |
| HLM-PIN-003 | MEDIUM | Mutable image tag in rendered templates |
| HLM-TRUST-001 | HIGH | Chart dependency from untrusted Helm repo |
| HLM-INJ-001 | HIGH | Unsafe `.Values` interpolation in templates (e.g., `{{ .Values.name }}` in shell commands without `quote`) |
| HLM-SECRET-001 | HIGH | Plaintext secrets in values.yaml (passwords, tokens, API keys) |
| HLM-SECRET-002 | MEDIUM | Secret resource without encryption-at-rest annotation |

### Kustomize (KST-*)

| Check | Severity | What it detects |
|-------|----------|-----------------|
| KST-PIN-001 | HIGH | Remote base URL without commit SHA pin |
| KST-PIN-002 | MEDIUM | Image transformer with mutable tag (no digest) |
| KST-TRUST-001 | HIGH | Remote base from untrusted source |
| KST-PATCH-001 | MEDIUM | Strategic merge patch that adds privileged securityContext |

### ArgoCD (AGO-*)

| Check | Severity | What it detects |
|-------|----------|-----------------|
| AGO-PIN-001 | HIGH | Application targetRevision not SHA-pinned |
| AGO-TRUST-001 | HIGH | Application source from untrusted repo |
| AGO-SYNC-001 | MEDIUM | Auto-sync enabled without prune protection |
| AGO-SYNC-002 | LOW | Self-heal enabled (overrides manual hotfixes) |
| AGO-NS-001 | MEDIUM | Application destination namespace is kube-system or default |

### Generic K8s (K8S-*)

Promote from Tekton-specific:
| Check | Severity | What it detects |
|-------|----------|-----------------|
| K8S-SEC-001 | HIGH | Privileged container (from TKN-SEC-001) |
| K8S-SEC-002 | MEDIUM | Root user / privilege escalation (from TKN-SEC-002) |
| K8S-VOL-001 | HIGH | Host path volume mount (from TKN-VOL-001) |
| K8S-VOL-002 | CRITICAL | Container runtime socket mount (from TKN-VOL-002) |
| K8S-SECRET-001 | HIGH | Secret data in ConfigMap (base64-encoded values in ConfigMap) |
| K8S-IMG-001 | MEDIUM | Mutable image tag on any Pod/Deployment/Job/CronJob |

## Helm Parser Design

The Helm parser needs `helm` CLI available (or a Go library). Strategy:

1. Parse `Chart.yaml` for dependencies (check HLM-PIN-001, HLM-TRUST-001)
2. Parse `values.yaml` directly for secrets and image refs (HLM-SECRET-001, HLM-PIN-002)
3. Run `helm template` to render templates, then parse rendered manifests for K8S-* checks (HLM-PIN-003, HLM-INJ-001)
4. Optionally parse `.tpl` template files directly for injection patterns

Fallback: if `helm` CLI is not available, skip step 3 (template rendering) and scan only Chart.yaml and values.yaml.

## Kustomize Parser Design

1. Parse `kustomization.yaml` for `resources:` entries with remote URLs (KST-PIN-001, KST-TRUST-001)
2. Parse `images:` transformer for tag pinning (KST-PIN-002)
3. Parse `patchesStrategicMerge:` for privilege escalation (KST-PATCH-001)
4. Optionally run `kustomize build` for rendered manifest K8S-* checks

## ArgoCD Parser Design

Parse ArgoCD `Application` CRDs:
1. `spec.source.repoURL` for trust check (AGO-TRUST-001)
2. `spec.source.targetRevision` for pinning (AGO-PIN-001)
3. `spec.syncPolicy.automated` for sync policy checks (AGO-SYNC-001/002)
4. `spec.destination.namespace` for namespace checks (AGO-NS-001)

## CLI Changes

```bash
# Scan everything (auto-detect)
kube-shield /path/to/repo

# Scan specific source type
kube-shield /path/to/repo --type tekton
kube-shield /path/to/repo --type helm
kube-shield /path/to/repo --type kustomize

# All existing flags work unchanged
kube-shield /path/to/repo --fix --format sarif --fail-on HIGH
```

## Migration Path

### Phase 1: Rename (tekton-guard -> kube-shield)
- Rename package, CLI, repo
- All TKN-* checks keep working unchanged
- Promote SEC/VOL to K8S-* (keep TKN-* as aliases)
- Update docs, GitHub Action

### Phase 2: Helm support
- Helm parser (Chart.yaml, values.yaml, helm template)
- 7 HLM-* checks
- Test against odh-gitops charts/

### Phase 3: Kustomize support
- Kustomize parser (kustomization.yaml, remote bases)
- 4 KST-* checks

### Phase 4: ArgoCD support
- ArgoCD Application parser
- 5 AGO-* checks

### Phase 5: Generic K8s
- K8S-SECRET-001, K8S-IMG-001
- Full scan of any K8s YAML directory

## Compatibility

- `tekton-guard` CLI remains as a deprecated alias for `kube-shield`
- All TKN-* rule IDs are stable (no renaming)
- Baseline files from tekton-guard work in kube-shield
- Config files use the same format (new fields for Helm repos, Kustomize bases trust lists)
