"""Tests for security checks."""

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


# --- Pinning checks ---


class TestPinning:
    def test_mutable_pipeline_ref_detected(self):
        findings = _run("pipelinerun-mutable.yaml")
        assert "TKN-PIN-001" in _rule_ids(findings)
        pin = [f for f in findings if f["rule_id"] == "TKN-PIN-001"][0]
        assert pin["severity"] == "HIGH"
        assert pin["current_value"] == "main"

    def test_pinned_pipeline_ref_clean(self):
        findings = _run("pipelinerun-pinned.yaml")
        assert "TKN-PIN-001" not in _rule_ids(findings)

    def test_unpinned_bundle_detected(self):
        findings = _run("pipeline-with-tasks.yaml")
        assert "TKN-PIN-003" in _rule_ids(findings)
        bundle_f = [f for f in findings if f["rule_id"] == "TKN-PIN-003"][0]
        assert "quay.io/example/build-task:v1.0" in bundle_f["current_value"]

    def test_mutable_task_git_ref_detected(self):
        findings = _run("pipeline-with-tasks.yaml")
        assert "TKN-PIN-002" in _rule_ids(findings)
        git_f = [f for f in findings if f["rule_id"] == "TKN-PIN-002"][0]
        assert git_f["current_value"] == "develop"

    def test_mutable_step_image_detected(self):
        findings = _run("task-with-injection.yaml")
        assert "TKN-PIN-004" in _rule_ids(findings)
        img_findings = [f for f in findings if f["rule_id"] == "TKN-PIN-004"]
        assert len(img_findings) == 1  # only alpine/git, others are pinned


# --- Trust checks ---


class TestTrust:
    def test_untrusted_pipeline_source(self):
        findings = _run("pipelinerun-mutable.yaml")
        assert "TKN-TRUST-001" in _rule_ids(findings)

    def test_trusted_pipeline_source(self):
        findings = _run("pipelinerun-pinned.yaml")
        assert "TKN-TRUST-001" not in _rule_ids(findings)

    def test_untrusted_task_source(self):
        findings = _run("pipeline-with-tasks.yaml")
        assert "TKN-TRUST-002" in _rule_ids(findings)
        trust_f = [f for f in findings if f["rule_id"] == "TKN-TRUST-002"][0]
        assert "untrusted-org" in trust_f["resolver_url"]

    def test_cluster_task_ref(self):
        findings = _run("pipeline-with-tasks.yaml")
        assert "TKN-TRUST-003" in _rule_ids(findings)
        cluster_f = [f for f in findings if f["rule_id"] == "TKN-TRUST-003"]
        names = [f["cluster_task"] for f in cluster_f]
        assert "git-clone" in names
        assert "cleanup-task" in names

    def test_custom_trust_list(self):
        findings = _run(
            "pipelinerun-mutable.yaml",
            trusted_git_sources=["https://github.com/example/"],
        )
        assert "TKN-TRUST-001" not in _rule_ids(findings)


# --- ServiceAccount checks ---


class TestServiceAccount:
    def test_default_sa_flagged(self):
        findings = _run("pipelinerun-default-sa.yaml")
        assert "TKN-SA-001" in _rule_ids(findings)

    def test_missing_sa_flagged(self):
        findings = _run("pipelinerun-no-sa.yaml")
        assert "TKN-SA-002" in _rule_ids(findings)

    def test_explicit_sa_clean(self):
        findings = _run("pipelinerun-pinned.yaml")
        assert "TKN-SA-001" not in _rule_ids(findings)
        assert "TKN-SA-002" not in _rule_ids(findings)


# --- Workspace checks ---


class TestWorkspace:
    def test_secret_without_readonly(self):
        # Use a fixture with a non-git-auth secret workspace
        findings = _run(
            "pipelinerun-mutable.yaml",
            known_safe_secret_workspaces=[],  # disable suppression
        )
        assert "TKN-WS-001" in _rule_ids(findings)

    def test_secret_with_readonly_clean(self):
        findings = _run("pipelinerun-pinned.yaml")
        assert "TKN-WS-001" not in _rule_ids(findings)

    def test_shared_workspace_untrusted(self):
        findings = _run("pipeline-with-tasks.yaml")
        assert "TKN-WS-002" in _rule_ids(findings)
        ws_f = [f for f in findings if f["rule_id"] == "TKN-WS-002"][0]
        assert "external-scan" in ws_f["untrusted_tasks"]


# --- Result injection checks ---


class TestResultInjection:
    def test_script_injection_detected(self):
        findings = _run("task-with-injection.yaml")
        assert "TKN-RES-001" in _rule_ids(findings)
        inj = [f for f in findings if f["rule_id"] == "TKN-RES-001"][0]
        assert "$(params.revision)" in str(inj["interpolations"])

    def test_args_interpolation_detected(self):
        findings = _run("task-with-injection.yaml")
        assert "TKN-RES-002" in _rule_ids(findings)


# --- Chains readiness checks ---


class TestChainsReadiness:
    def test_build_without_chains_annotations(self):
        config = ScannerConfig()
        from tekton_guard.parser import parse_file
        resources = parse_file(FIXTURES / "pipelinerun-mutable.yaml")
        # Simulate a non-Konflux build pipeline: keep the build type label
        # but remove application/component labels that indicate Konflux
        for r in resources:
            r.labels = {"pipelines.appstudio.openshift.io/type": "build"}
            r.annotations = {}
        findings = run_checks(resources, config)
        assert "TKN-CHAIN-001" in _rule_ids(findings)

    def test_build_with_chains_annotations(self):
        findings = _run("pipelinerun-pinned.yaml")
        assert "TKN-CHAIN-001" not in _rule_ids(findings)

    def test_non_build_pipeline_skipped(self):
        findings = _run("pipelinerun-default-sa.yaml")
        assert "TKN-CHAIN-001" not in _rule_ids(findings)
        assert "TKN-CHAIN-002" not in _rule_ids(findings)


# --- False positive suppression ---


class TestFalsePositiveSuppression:
    def test_pac_revision_template_not_flagged(self):
        """PaC {{revision}} resolves to commit SHA at runtime, not a FP."""
        findings = _run("pipelinerun-pac-self-ref.yaml")
        assert "TKN-PIN-001" not in _rule_ids(findings)

    def test_pac_source_url_template_not_flagged(self):
        """PaC {{source_url}} is the triggering repo itself, not untrusted."""
        findings = _run("pipelinerun-pac-self-ref.yaml")
        assert "TKN-TRUST-001" not in _rule_ids(findings)

    def test_appstudio_build_chains_not_flagged(self):
        """Konflux/AppStudio pipelines have Chains configured cluster-wide."""
        findings = _run("pipelinerun-pac-self-ref.yaml")
        assert "TKN-CHAIN-001" not in _rule_ids(findings)

    def test_git_auth_workspace_not_flagged(self):
        """git-auth is a known-safe PaC workspace pattern."""
        findings = _run("pipelinerun-pac-self-ref.yaml")
        assert "TKN-WS-001" not in _rule_ids(findings)

    def test_pac_self_ref_produces_zero_findings(self):
        """A well-formed PaC self-referencing PipelineRun should be clean."""
        findings = _run("pipelinerun-pac-self-ref.yaml")
        assert len(findings) == 0

    def test_mutable_main_still_flagged(self):
        """Ensure literal 'main' is still caught after PaC suppression."""
        findings = _run("pipelinerun-mutable.yaml")
        assert "TKN-PIN-001" in _rule_ids(findings)


# --- Config: skip_checks ---


class TestSkipChecks:
    def test_skip_pinning(self):
        findings = _run("pipelinerun-mutable.yaml", skip_checks=["TKN-PIN-001"])
        assert "TKN-PIN-001" not in _rule_ids(findings)

    def test_min_severity(self):
        # Use task fixture which produces both MEDIUM and LOW findings
        all_findings = _run("task-with-injection.yaml")
        high_only = _run("task-with-injection.yaml", min_severity="HIGH")
        assert len(high_only) < len(all_findings)
        for f in high_only:
            assert f["severity"] in ("HIGH", "CRITICAL")
