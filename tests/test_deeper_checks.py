"""Tests for deeper Tekton checks (Phase A: triggers, Phase B: supply chain)."""

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


class TestVerificationPolicy:
    def test_unanchored_regex_flagged(self):
        findings = _run("edge-verification-policy.yaml")
        chain003 = [f for f in findings if f["rule_id"] == "TKN-CHAIN-003"]
        assert len(chain003) >= 1
        unanchored = [f for f in chain003 if "unanchored" in f["resource_name"]]
        assert len(unanchored) >= 1

    def test_anchored_regex_clean(self):
        findings = _run("edge-verification-policy.yaml")
        chain003 = [f for f in findings if f["rule_id"] == "TKN-CHAIN-003"
                    and f["resource_name"] == "anchored-policy"]
        assert len(chain003) == 0

    def test_partial_anchor_flagged(self):
        """Pattern with ^ but no $ should be flagged."""
        findings = _run("edge-verification-policy.yaml")
        chain003 = [f for f in findings if f["rule_id"] == "TKN-CHAIN-003"]
        partial = [f for f in chain003 if "quay.io" in f.get("pattern", "")]
        assert len(partial) == 1


class TestChainDeep:
    def test_untrusted_build_task_flagged(self):
        findings = _run("edge-chain-deep.yaml")
        chain004 = [f for f in findings if f["rule_id"] == "TKN-CHAIN-004"]
        assert len(chain004) >= 1
        names = [f.get("task_name") for f in chain004]
        assert "push-container" in names or "build-image" in names

    def test_build_without_sbom_flagged(self):
        findings = _run("edge-chain-deep.yaml")
        chain005 = [f for f in findings if f["rule_id"] == "TKN-CHAIN-005"
                    and f["resource_name"] == "build-pipeline"]
        assert len(chain005) == 1

    def test_build_with_sbom_clean(self):
        findings = _run("edge-chain-deep.yaml")
        chain005 = [f for f in findings if f["rule_id"] == "TKN-CHAIN-005"
                    and f["resource_name"] == "build-with-sbom"]
        assert len(chain005) == 0


class TestResolverDeep:
    def test_http_without_digest_flagged(self):
        findings = _run("edge-resolver-deep.yaml")
        trust004 = [f for f in findings if f["rule_id"] == "TKN-TRUST-004"]
        assert len(trust004) == 1
        assert trust004[0].get("task_name") or "fetch-task" in trust004[0].get("message", "")

    def test_http_with_digest_clean(self):
        findings = _run("edge-resolver-deep.yaml")
        trust004 = [f for f in findings if f["rule_id"] == "TKN-TRUST-004"
                    and "fetch-with-digest" in f.get("message", "")]
        assert len(trust004) == 0

    def test_cluster_shared_namespace_flagged(self):
        findings = _run("edge-resolver-deep.yaml")
        trust005 = [f for f in findings if f["rule_id"] == "TKN-TRUST-005"]
        assert len(trust005) == 1
        assert trust005[0].get("namespace") == "tekton-pipelines"

    def test_cluster_dedicated_namespace_clean(self):
        findings = _run("edge-resolver-deep.yaml")
        trust005 = [f for f in findings if f["rule_id"] == "TKN-TRUST-005"
                    and f.get("namespace") == "my-dedicated-ns"]
        assert len(trust005) == 0


class TestTriggerDeep:
    def test_trigger_template_injection_flagged(self):
        findings = _run("edge-triggers-deep.yaml")
        trig004 = [f for f in findings if f["rule_id"] == "TKN-TRIG-004"]
        assert len(trig004) == 1
        assert trig004[0]["resource_name"] == "template-with-injection"

    def test_clean_template_not_flagged(self):
        findings = _run("edge-triggers-deep.yaml")
        trig004 = [f for f in findings if f["rule_id"] == "TKN-TRIG-004"
                   and f["resource_name"] == "template-clean"]
        assert len(trig004) == 0

    def test_listener_no_interceptor_flagged(self):
        findings = _run("edge-triggers-deep.yaml")
        trig005 = [f for f in findings if f["rule_id"] == "TKN-TRIG-005"]
        assert len(trig005) == 1
        assert trig005[0]["resource_name"] == "listener-no-interceptor"

    def test_listener_with_interceptor_clean(self):
        findings = _run("edge-triggers-deep.yaml")
        trig005 = [f for f in findings if f["rule_id"] == "TKN-TRIG-005"
                   and f["resource_name"] == "listener-with-interceptor"]
        assert len(trig005) == 0

    def test_unrestricted_repo_flagged(self):
        findings = _run("edge-triggers-deep.yaml")
        trig006 = [f for f in findings if f["rule_id"] == "TKN-TRIG-006"]
        assert len(trig006) == 1
        assert trig006[0]["resource_name"] == "unrestricted-repo"

    def test_restricted_repo_clean(self):
        findings = _run("edge-triggers-deep.yaml")
        trig006 = [f for f in findings if f["rule_id"] == "TKN-TRIG-006"
                   and f["resource_name"] == "restricted-repo"]
        assert len(trig006) == 0

    def test_listener_default_sa_flagged(self):
        findings = _run("edge-triggers-deep.yaml")
        trig007 = [f for f in findings if f["rule_id"] == "TKN-TRIG-007"]
        assert len(trig007) == 1
        assert trig007[0]["resource_name"] == "listener-no-interceptor"

    def test_listener_dedicated_sa_clean(self):
        findings = _run("edge-triggers-deep.yaml")
        trig007 = [f for f in findings if f["rule_id"] == "TKN-TRIG-007"
                   and f["resource_name"] == "listener-with-interceptor"]
        assert len(trig007) == 0
