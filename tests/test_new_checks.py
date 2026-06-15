"""Tests for Phase 2 checks: TKN-SEC, TKN-VOL."""

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
        names = [f["step_name"] for f in all_sec]
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
