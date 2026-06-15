"""Tests for Phase 2 checks: TKN-TRIG, TKN-LIMIT, TKN-EXFIL, TKN-RES-003."""

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


class TestTriggerSecurity:
    def test_cel_injection_detected(self):
        findings = _run("edge-triggers.yaml")
        trig001 = [f for f in findings if f["rule_id"] == "TKN-TRIG-001"]
        assert len(trig001) == 1
        assert trig001[0]["resource_name"] == "cel-injection-risk"
        assert trig001[0]["severity"] == "CRITICAL"

    def test_safe_cel_not_flagged(self):
        findings = _run("edge-triggers.yaml")
        trig001 = [f for f in findings if f["rule_id"] == "TKN-TRIG-001"
                    and f["resource_name"] == "safe-cel"]
        assert len(trig001) == 0

    def test_permissive_push_flagged(self):
        findings = _run("edge-triggers.yaml")
        trig002 = [f for f in findings if f["rule_id"] == "TKN-TRIG-002"
                    and f["resource_name"] == "permissive-push"]
        assert len(trig002) == 1

    def test_comment_without_branch_flagged(self):
        findings = _run("edge-triggers.yaml")
        trig002 = [f for f in findings if f["rule_id"] == "TKN-TRIG-002"
                    and f["resource_name"] == "comment-no-branch"]
        assert len(trig002) == 1

    def test_branch_restricted_push_not_flagged(self):
        findings = _run("edge-triggers.yaml")
        trig002 = [f for f in findings if f["rule_id"] == "TKN-TRIG-002"
                    and f["resource_name"] == "safe-cel"]
        assert len(trig002) == 0


class TestExfiltration:
    def test_secret_with_curl_flagged(self):
        findings = _run("edge-exfiltration.yaml")
        exfil001 = [f for f in findings if f["rule_id"] == "TKN-EXFIL-001"
                    and f["resource_name"] == "secret-with-curl"]
        assert len(exfil001) == 1

    def test_no_secret_with_curl_not_exfil001(self):
        """EXFIL-001 requires secret access. No secret = no finding."""
        findings = _run("edge-exfiltration.yaml")
        exfil001 = [f for f in findings if f["rule_id"] == "TKN-EXFIL-001"
                    and f["resource_name"] == "no-secret-with-curl"]
        assert len(exfil001) == 0

    def test_curl_always_flagged_by_exfil002(self):
        """EXFIL-002 flags network tools regardless of secret access."""
        findings = _run("edge-exfiltration.yaml")
        exfil002 = [f for f in findings if f["rule_id"] == "TKN-EXFIL-002"]
        names = [f["resource_name"] for f in exfil002]
        assert "secret-with-curl" in names
        assert "no-secret-with-curl" in names


class TestPaCTaint:
    def test_pac_tainted_params_flagged(self):
        findings = _run("edge-pac-taint.yaml")
        res003 = [f for f in findings if f["rule_id"] == "TKN-RES-003"]
        assert len(res003) >= 2  # git-url and revision
        param_names = [f["param_name"] for f in res003]
        assert "git-url" in param_names
        assert "revision" in param_names

    def test_hardcoded_param_not_flagged(self):
        findings = _run("edge-pac-taint.yaml")
        res003 = [f for f in findings if f["rule_id"] == "TKN-RES-003"]
        param_names = [f["param_name"] for f in res003]
        assert "safe-param" not in param_names


class TestWhenSkip:
    def test_security_task_with_when_flagged(self):
        findings = _run("edge-when-skip.yaml")
        trig003 = [f for f in findings if f["rule_id"] == "TKN-TRIG-003"]
        assert len(trig003) == 1
        assert trig003[0]["task_name"] == "sast-scan"

    def test_non_security_task_with_when_not_flagged(self):
        """Build task is not a security task, when expression should not trigger."""
        findings = _run("edge-when-skip.yaml")
        trig003 = [f for f in findings if f["rule_id"] == "TKN-TRIG-003"
                    and f.get("task_name") == "build"]
        assert len(trig003) == 0


class TestTimeout:
    def test_excessive_timeout_not_on_normal_pipelines(self):
        """Most test fixtures have no timeouts, should produce 0 LIMIT findings."""
        findings = _run("pipelinerun-mutable.yaml")
        limit = [f for f in findings if f["rule_id"].startswith("TKN-LIMIT")]
        assert len(limit) == 0
