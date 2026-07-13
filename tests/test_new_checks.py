"""Tests for Phase 2 checks: TKN-SEC, TKN-VOL, and the 10 new checks."""

from pathlib import Path

from tekton_guard.checks import run_checks
from tekton_guard.config import ScannerConfig
from tekton_guard.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def _run(fixture: str, **config_kwargs) -> list[dict]:
    config = ScannerConfig(**config_kwargs)
    resources = parse_file(FIXTURES / fixture)
    return run_checks(resources, config)


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


def _findings_for(findings: list[dict], rule_id: str, resource_name: str | None = None) -> list[dict]:
    result = [f for f in findings if f["rule_id"] == rule_id]
    if resource_name:
        result = [f for f in result if f["resource_name"] == resource_name]
    return result


class TestSecurityContext:
    def test_privileged_step_flagged(self):
        findings = _run("edge-security-context.yaml")
        sec001 = [f for f in findings if f["rule_id"] == "TKN-SEC-001"]
        names = [f["step_name"] for f in sec001]
        assert "privileged-step" in names

    def test_privileged_sidecar_flagged(self):
        findings = _run("edge-security-context.yaml")
        sec001 = [f for f in findings if f["rule_id"] == "TKN-SEC-001"]
        names = [f["step_name"] for f in sec001]
        assert "privileged-sidecar" in names

    def test_root_user_flagged(self):
        findings = _run("edge-security-context.yaml")
        sec002 = [f for f in findings if f["rule_id"] == "TKN-SEC-002"]
        names = [f["step_name"] for f in sec002]
        assert "root-step" in names

    def test_privilege_escalation_flagged(self):
        findings = _run("edge-security-context.yaml")
        sec002 = [f for f in findings if f["rule_id"] == "TKN-SEC-002"]
        names = [f["step_name"] for f in sec002]
        assert "escalation-step" in names

    def test_safe_step_not_flagged(self):
        findings = _run("edge-security-context.yaml")
        all_sec = [f for f in findings if f["rule_id"].startswith("TKN-SEC")]
        names = [f.get("step_name", "") for f in all_sec]
        assert "safe-step" not in names

    def test_sec001_severity_is_high(self):
        findings = _run("edge-security-context.yaml")
        sec001 = [f for f in findings if f["rule_id"] == "TKN-SEC-001"]
        for f in sec001:
            assert f["severity"] == "HIGH"

    def test_sec002_severity_is_medium(self):
        findings = _run("edge-security-context.yaml")
        sec002 = [f for f in findings if f["rule_id"] == "TKN-SEC-002"]
        for f in sec002:
            assert f["severity"] == "MEDIUM"


class TestVolumeMounts:
    def test_docker_socket_flagged_as_critical(self):
        findings = _run("edge-volumes-dangerous.yaml")
        vol002 = [f for f in findings if f["rule_id"] == "TKN-VOL-002"
                  and f["resource_name"] == "docker-socket-task"]
        assert len(vol002) == 1
        assert vol002[0]["severity"] == "CRITICAL"
        assert vol002[0]["host_path"] == "/var/run/docker.sock"

    def test_containerd_socket_flagged_as_critical(self):
        findings = _run("edge-volumes-dangerous.yaml")
        vol002 = [f for f in findings if f["rule_id"] == "TKN-VOL-002"
                  and f["resource_name"] == "containerd-socket-task"]
        assert len(vol002) == 1
        assert vol002[0]["host_path"] == "/run/containerd/containerd.sock"

    def test_etc_shadow_flagged_as_high(self):
        findings = _run("edge-volumes-dangerous.yaml")
        vol001 = [f for f in findings if f["rule_id"] == "TKN-VOL-001"
                  and f["resource_name"] == "etc-shadow-task"]
        assert len(vol001) == 1
        assert vol001[0]["severity"] == "HIGH"

    def test_docker_socket_not_double_flagged(self):
        """VOL-002 subsumes VOL-001 for runtime sockets."""
        findings = _run("edge-volumes-dangerous.yaml")
        vol001_docker = [f for f in findings if f["rule_id"] == "TKN-VOL-001"
                         and f["resource_name"] == "docker-socket-task"]
        assert len(vol001_docker) == 0

    def test_safe_volumes_not_flagged(self):
        findings = _run("edge-volumes-dangerous.yaml")
        safe_findings = [f for f in findings if f["resource_name"] == "safe-volumes-task"
                         and f["rule_id"].startswith("TKN-VOL")]
        assert len(safe_findings) == 0

    def test_emptydir_not_flagged(self):
        findings = _run("edge-volumes-dangerous.yaml")
        vol_findings = [f for f in findings if f["rule_id"].startswith("TKN-VOL")]
        for f in vol_findings:
            assert "emptyDir" not in f.get("host_path", "")


# -----------------------------------------------------------------------
# TKN-SEC-003: pathInRepo traversal (CVE-2026-33211)
# -----------------------------------------------------------------------

class TestSec003PathTraversal:

    def test_traversal_flagged(self):
        """pathInRepo with ../../ must be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec003 = _findings_for(findings, "TKN-SEC-003", "path-traversal-run")
        assert len(sec003) == 1
        assert sec003[0]["severity"] == "CRITICAL"
        assert sec003[0]["cwe"] == "CWE-22"

    def test_safe_path_not_flagged(self):
        """Normal pathInRepo without traversal must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec003 = _findings_for(findings, "TKN-SEC-003", "safe-path-run")
        assert len(sec003) == 0

    def test_dotdot_in_filename_not_flagged(self):
        """FP guard: v2..3/build.yaml has .. but not as a path component."""
        findings = _run("edge-new-checks.yaml")
        sec003 = _findings_for(findings, "TKN-SEC-003", "dotdot-in-filename-run")
        assert len(sec003) == 0

    def test_url_encoded_traversal_flagged(self):
        """URL-encoded %2e%2e traversal must be caught after decoding."""
        findings = _run("edge-new-checks.yaml")
        sec003 = _findings_for(findings, "TKN-SEC-003", "encoded-traversal-run")
        assert len(sec003) == 1


# -----------------------------------------------------------------------
# TKN-SEC-004: VolumeMount targeting /tekton/ paths (CVE-2026-40923)
# -----------------------------------------------------------------------

class TestSec004TektonMount:

    def test_tekton_results_mount_flagged(self):
        """VolumeMount to /tekton/results/ must be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec004 = _findings_for(findings, "TKN-SEC-004", "tekton-mount-task")
        assert len(sec004) >= 1
        mount_paths = [f["mount_path"] for f in sec004]
        assert any("/tekton/results" in mp for mp in mount_paths)

    def test_tekton_creds_mount_flagged(self):
        """VolumeMount to /tekton/creds/ must be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec004 = _findings_for(findings, "TKN-SEC-004", "tekton-mount-task")
        mount_paths = [f["mount_path"] for f in sec004]
        assert any("/tekton/creds" in mp for mp in mount_paths)

    def test_tekton_home_not_flagged(self):
        """FP guard: /tekton/home is legitimate, must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec004 = _findings_for(findings, "TKN-SEC-004", "tekton-home-mount-task")
        assert len(sec004) == 0


# -----------------------------------------------------------------------
# TKN-SEC-005: Resolver name too long (CVE-2026-33022)
# -----------------------------------------------------------------------

class TestSec005ResolverNameLength:

    def test_long_resolver_flagged(self):
        """Resolver name > 30 chars must be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec005 = _findings_for(findings, "TKN-SEC-005", "long-resolver-run")
        assert len(sec005) == 1
        assert sec005[0]["severity"] == "MEDIUM"
        assert sec005[0]["resolver_length"] > 30

    def test_normal_resolver_not_flagged(self):
        """Standard 'git' resolver must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec005 = _findings_for(findings, "TKN-SEC-005", "normal-resolver-run")
        assert len(sec005) == 0


# -----------------------------------------------------------------------
# TKN-SEC-006: Step without runAsNonRoot
# -----------------------------------------------------------------------

class TestSec006RunAsNonRoot:

    def test_step_without_nonroot_flagged(self):
        """Step without runAsNonRoot must be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec006 = _findings_for(findings, "TKN-SEC-006", "no-nonroot-task")
        assert len(sec006) == 1

    def test_step_with_nonroot_not_flagged(self):
        """Step with runAsNonRoot: true must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        sec006 = _findings_for(findings, "TKN-SEC-006", "nonroot-task")
        assert len(sec006) == 0

    def test_pod_level_nonroot_not_flagged(self):
        """FP guard: stepTemplate with runAsNonRoot must suppress finding."""
        findings = _run("edge-new-checks.yaml")
        sec006 = _findings_for(findings, "TKN-SEC-006", "pod-level-nonroot-task")
        assert len(sec006) == 0

    def test_nonzero_user_not_flagged(self):
        """FP guard: runAsUser: 1000 (non-root) must suppress finding."""
        findings = _run("edge-new-checks.yaml")
        sec006 = _findings_for(findings, "TKN-SEC-006", "nonzero-user-task")
        assert len(sec006) == 0


# -----------------------------------------------------------------------
# TKN-TRUST-008: Git resolver API mode token leak (CVE-2026-40161)
# -----------------------------------------------------------------------

class TestTrust008ApiModeLeak:

    def test_api_mode_untrusted_server_flagged(self):
        """serverURL to untrusted server without token must be flagged."""
        findings = _run("edge-new-checks.yaml")
        trust008 = _findings_for(findings, "TKN-TRUST-008", "api-mode-leak-run")
        assert len(trust008) == 1
        assert trust008[0]["severity"] == "HIGH"
        assert "evil-git-server" in trust008[0]["serverURL"]

    def test_api_mode_with_token_not_flagged(self):
        """serverURL with explicit token must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        trust008 = _findings_for(findings, "TKN-TRUST-008", "api-mode-with-token-run")
        assert len(trust008) == 0

    def test_api_mode_trusted_server_not_flagged(self):
        """FP guard: serverURL to trusted source must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        trust008 = _findings_for(findings, "TKN-TRUST-008", "api-mode-trusted-run")
        assert len(trust008) == 0


# -----------------------------------------------------------------------
# TKN-CHAIN-007: Build pipeline without provenance signing
# -----------------------------------------------------------------------

class TestChain007ProvenanceSigning:

    def test_build_without_signing_flagged(self):
        """Build PipelineRun without chains annotations must be flagged."""
        findings = _run("edge-new-checks.yaml")
        chain007 = _findings_for(findings, "TKN-CHAIN-007", "build-no-signing")
        assert len(chain007) == 1
        assert chain007[0]["severity"] == "MEDIUM"

    def test_build_with_signing_not_flagged(self):
        """Build PipelineRun with chains.tekton.dev annotation must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        chain007 = _findings_for(findings, "TKN-CHAIN-007", "build-with-signing")
        assert len(chain007) == 0

    def test_konflux_build_not_flagged(self):
        """FP guard: Konflux/AppStudio builds have cluster-level Chains."""
        findings = _run("edge-new-checks.yaml")
        chain007 = _findings_for(findings, "TKN-CHAIN-007", "konflux-build")
        assert len(chain007) == 0


# -----------------------------------------------------------------------
# TKN-RES-004: Untrusted task result consumed without validation
# -----------------------------------------------------------------------

class TestRes004UntrustedResult:

    def test_untrusted_result_to_trusted_consumer_flagged(self):
        """Trusted consumer reading untrusted producer result must be flagged."""
        findings = _run("edge-new-checks.yaml")
        res004 = _findings_for(findings, "TKN-RES-004", "result-flow-pipeline")
        consumer_findings = [f for f in res004 if f["consumer_task"] == "trusted-consumer"]
        assert len(consumer_findings) == 1
        assert consumer_findings[0]["producer_task"] == "untrusted-producer"
        assert consumer_findings[0]["result_name"] == "output"

    def test_untrusted_consumer_of_untrusted_not_flagged(self):
        """FP guard: both sides untrusted means nothing new to flag."""
        findings = _run("edge-new-checks.yaml")
        res004 = _findings_for(findings, "TKN-RES-004", "result-flow-pipeline")
        consumer_findings = [f for f in res004 if f["consumer_task"] == "also-untrusted-consumer"]
        assert len(consumer_findings) == 0

    def test_all_trusted_not_flagged(self):
        """Pipeline with only trusted tasks must not fire RES-004."""
        findings = _run("edge-new-checks.yaml")
        res004 = _findings_for(findings, "TKN-RES-004", "all-trusted-pipeline")
        assert len(res004) == 0


# -----------------------------------------------------------------------
# TKN-LOGIC-008: Untrusted task result in when expression
# -----------------------------------------------------------------------

class TestLogic008UntrustedWhen:

    def test_untrusted_result_in_when_flagged(self):
        """When expression referencing untrusted task result must be flagged."""
        findings = _run("edge-new-checks.yaml")
        logic008 = _findings_for(findings, "TKN-LOGIC-008", "result-flow-pipeline")
        assert len(logic008) == 1
        assert logic008[0]["producer_task"] == "untrusted-producer"

    def test_all_trusted_when_not_flagged(self):
        """When expression referencing trusted task result must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        logic008 = _findings_for(findings, "TKN-LOGIC-008", "all-trusted-pipeline")
        assert len(logic008) == 0


# -----------------------------------------------------------------------
# TKN-WS-003: Large workspace fan-out
# -----------------------------------------------------------------------

class TestWs003WorkspaceFanout:

    def test_large_fanout_flagged(self):
        """Workspace used by 5 tasks must be flagged (threshold 4)."""
        findings = _run("edge-new-checks.yaml")
        ws003 = _findings_for(findings, "TKN-WS-003", "wide-workspace-pipeline")
        mega = [f for f in ws003 if f["workspace_name"] == "mega-workspace"]
        assert len(mega) == 1
        assert mega[0]["task_count"] == 5

    def test_small_fanout_not_flagged(self):
        """Workspace used by 2 tasks must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        ws003 = _findings_for(findings, "TKN-WS-003", "wide-workspace-pipeline")
        small = [f for f in ws003 if f["workspace_name"] == "small-workspace"]
        assert len(small) == 0


# -----------------------------------------------------------------------
# TKN-VOL-003: Sidecar with write access to results directory
# -----------------------------------------------------------------------

class TestVol003SidecarResults:

    def test_writable_sidecar_results_flagged(self):
        """Sidecar with writable /tekton/results mount must be flagged."""
        findings = _run("edge-new-checks.yaml")
        vol003 = _findings_for(findings, "TKN-VOL-003", "sidecar-results-task")
        assert len(vol003) == 1
        assert vol003[0]["sidecar_name"] == "evil-sidecar"

    def test_readonly_sidecar_results_not_flagged(self):
        """FP guard: read-only sidecar mount must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        vol003 = _findings_for(findings, "TKN-VOL-003", "sidecar-readonly-results-task")
        assert len(vol003) == 0

    def test_step_results_not_flagged(self):
        """FP guard: step (not sidecar) with /tekton/results must not be flagged."""
        findings = _run("edge-new-checks.yaml")
        vol003 = _findings_for(findings, "TKN-VOL-003", "step-results-task")
        assert len(vol003) == 0
