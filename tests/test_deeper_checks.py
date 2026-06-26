"""Tests for deeper Tekton checks (Phase B: supply chain)."""

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
