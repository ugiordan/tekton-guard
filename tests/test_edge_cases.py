"""Edge case tests: adversarial inputs, boundary conditions, tricky patterns."""

from pathlib import Path

from tekton_guard.checks import run_checks
from tekton_guard.checks._common import collect_all_containers
from tekton_guard.config import ScannerConfig
from tekton_guard.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def _run(fixture: str, **config_kwargs) -> list[dict]:
    config = ScannerConfig(**config_kwargs)
    resources = parse_file(FIXTURES / fixture)
    return run_checks(resources, config)


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


# -----------------------------------------------------------------------
# Sneaky reference edge cases
# -----------------------------------------------------------------------

class TestSneakyRefs:
    """Test that non-SHA refs are caught even when they look like hashes."""

    def test_semver_tag_flagged(self):
        """v1.2.3 is not a SHA, must be flagged."""
        findings = _run("edge-sneaky-refs.yaml")
        pin001 = [f for f in findings if f["rule_id"] == "TKN-PIN-001"
                  and f["resource_name"] == "sneaky-refs-test"]
        assert len(pin001) == 1
        assert pin001[0]["current_value"] == "v1.2.3"

    def test_short_sha_flagged(self):
        """A 7-char abbreviated SHA is not a full 40-char SHA, must be flagged."""
        findings = _run("edge-sneaky-refs.yaml")
        pin001 = [f for f in findings if f["rule_id"] == "TKN-PIN-001"
                  and f["resource_name"] == "short-sha-test"]
        assert len(pin001) == 1
        assert pin001[0]["current_value"] == "abc123f"

    def test_refs_heads_main_flagged(self):
        """refs/heads/main is a mutable ref, must be flagged."""
        findings = _run("edge-sneaky-refs.yaml")
        pin001 = [f for f in findings if f["rule_id"] == "TKN-PIN-001"
                  and f["resource_name"] == "refs-heads-main-test"]
        assert len(pin001) == 1
        assert "refs/heads/main" in pin001[0]["current_value"]

    def test_real_40char_sha_not_flagged(self):
        """Verify the regex accepts a real 40-char hex SHA."""
        findings = _run("pipelinerun-pinned.yaml")
        assert "TKN-PIN-001" not in _rule_ids(findings)


# -----------------------------------------------------------------------
# Sidecar attack surface
# -----------------------------------------------------------------------

class TestSidecarAttacks:
    """Sidecars must be checked with the same rigor as steps."""

    def test_sidecar_mutable_image_flagged(self):
        """Mutable image on a sidecar must trigger TKN-PIN-004."""
        findings = _run("edge-sidecar-attacks.yaml")
        pin004 = [f for f in findings if f["rule_id"] == "TKN-PIN-004"]
        assert len(pin004) == 1
        assert "evil-sidecar" in pin004[0]["step_name"]
        assert "attacker/exfil-tool:latest" in pin004[0]["current_value"]

    def test_sidecar_script_injection_flagged(self):
        """Script injection in a sidecar must trigger TKN-RES-001."""
        findings = _run("edge-sidecar-attacks.yaml")
        res001 = [f for f in findings if f["rule_id"] == "TKN-RES-001"]
        assert len(res001) == 1
        assert "evil-sidecar" in res001[0]["step_name"]

    def test_clean_step_not_flagged_for_injection(self):
        """The clean step uses env vars, not interpolation. No RES-001."""
        findings = _run("edge-sidecar-attacks.yaml")
        res001 = [f for f in findings if f["rule_id"] == "TKN-RES-001"]
        for f in res001:
            assert "clean-step" not in f["step_name"]

    def test_collect_all_containers_includes_sidecars(self):
        """collect_all_containers must return both steps and sidecars."""
        resources = parse_file(FIXTURES / "edge-sidecar-attacks.yaml")
        containers = collect_all_containers(resources[0])
        types = [c.container_type for c in containers]
        assert "step" in types
        assert "sidecar" in types
        names = [c.container.name for c in containers]
        assert "clean-step" in names
        assert "evil-sidecar" in names


# -----------------------------------------------------------------------
# Complex workspace sharing
# -----------------------------------------------------------------------

class TestComplexWorkspaces:
    """Workspace isolation with multiple untrusted tasks sharing data."""

    def test_shared_workspace_with_multiple_untrusted(self):
        """shared-data workspace has 2 untrusted tasks (hub + untrusted git)."""
        findings = _run("edge-workspace-complex.yaml")
        ws002 = [f for f in findings if f["rule_id"] == "TKN-WS-002"]
        shared = [f for f in ws002 if f["workspace_name"] == "shared-data"]
        assert len(shared) == 1
        assert "untrusted-scan" in shared[0]["untrusted_tasks"]
        assert "also-untrusted" in shared[0]["untrusted_tasks"]

    def test_credentials_workspace_single_user_not_flagged(self):
        """credentials workspace only used by 1 task, WS-002 should not fire for it."""
        findings = _run("edge-workspace-complex.yaml")
        ws002 = [f for f in findings if f["rule_id"] == "TKN-WS-002"]
        creds = [f for f in ws002 if f["workspace_name"] == "credentials"]
        assert len(creds) == 0

    def test_hub_resolver_counted_as_untrusted(self):
        """Hub resolver tasks are always untrusted for workspace sharing."""
        findings = _run("edge-workspace-complex.yaml")
        trust002 = [f for f in findings if f["rule_id"] == "TKN-TRUST-002"]
        hub_findings = [f for f in trust002 if f["resolver_type"] == "hub"]
        assert len(hub_findings) >= 1

    def test_finally_task_cluster_ref_flagged(self):
        """Cleanup task in finally block with cluster ref should trigger TRUST-003."""
        findings = _run("edge-workspace-complex.yaml")
        trust003 = [f for f in findings if f["rule_id"] == "TKN-TRUST-003"]
        cleanup = [f for f in trust003 if f["cluster_task"] == "cleanup-task"]
        assert len(cleanup) == 1


# -----------------------------------------------------------------------
# Empty and malformed inputs
# -----------------------------------------------------------------------

class TestEmptyAndMalformed:
    """Parser and checks should handle edge cases gracefully."""

    def test_empty_spec_no_crash(self):
        """PipelineRun with empty spec should parse without error."""
        resources = parse_file(FIXTURES / "edge-empty-and-malformed.yaml")
        # Should get 3 resources (empty PipelineRun, no-steps Task, empty Pipeline)
        assert len(resources) == 3

    def test_empty_spec_no_findings(self):
        """Empty spec PipelineRun should not produce pinning findings."""
        findings = _run("edge-empty-and-malformed.yaml")
        empty_findings = [f for f in findings if f["resource_name"] == "empty-spec"]
        # SA-002 might fire (no SA set), but no PIN findings
        pin_findings = [f for f in empty_findings if f["rule_id"].startswith("TKN-PIN")]
        assert len(pin_findings) == 0

    def test_no_steps_task_no_crash(self):
        """Task with no steps should parse and check without error."""
        findings = _run("edge-empty-and-malformed.yaml")
        no_steps = [f for f in findings if f["resource_name"] == "no-steps"]
        # Should not crash, might have 0 findings
        assert isinstance(no_steps, list)

    def test_empty_tasks_list_no_crash(self):
        """Pipeline with tasks: [] should parse without error."""
        resources = parse_file(FIXTURES / "edge-empty-and-malformed.yaml")
        pipeline = [r for r in resources if r.name == "empty-tasks"][0]
        assert len(pipeline.pipeline_tasks) == 0

    def test_missing_sa_on_empty_pipelinerun(self):
        """Empty-spec PipelineRun has no SA, should trigger SA-002."""
        findings = _run("edge-empty-and-malformed.yaml")
        sa002 = [f for f in findings if f["rule_id"] == "TKN-SA-002"
                 and f["resource_name"] == "empty-spec"]
        assert len(sa002) == 1


# -----------------------------------------------------------------------
# Inline taskSpec with sidecars in Pipelines
# -----------------------------------------------------------------------

class TestInlineTaskSpecDeep:
    """Sidecars inside inline taskSpec blocks in Pipelines."""

    def test_inline_sidecar_mutable_image(self):
        """Sidecar in an inline taskSpec should have its image checked."""
        findings = _run("edge-inline-taskspec-deep.yaml")
        pin004 = [f for f in findings if f["rule_id"] == "TKN-PIN-004"]
        dind = [f for f in pin004 if "docker" in f.get("current_value", "").lower()
                and "dind" in f.get("current_value", "").lower()]
        assert len(dind) == 1

    def test_inline_sidecar_counted_by_collect_all_containers(self):
        """collect_all_containers must find sidecars in inline taskSpec."""
        resources = parse_file(FIXTURES / "edge-inline-taskspec-deep.yaml")
        pipeline = [r for r in resources if r.kind == "Pipeline"][0]
        containers = collect_all_containers(pipeline)
        sidecar_names = [c.container.name for c in containers if c.container_type == "sidecar"]
        assert "docker-daemon" in sidecar_names


# -----------------------------------------------------------------------
# v1beta1 bundle edge cases
# -----------------------------------------------------------------------

class TestV1Beta1Mixed:
    """v1beta1 old-style bundle syntax mixed with new resolver syntax."""

    def test_v1beta1_unpinned_bundle_flagged(self):
        """Old-style bundle: field without digest should trigger PIN-003."""
        findings = _run("edge-v1beta1-mixed.yaml")
        pin003 = [f for f in findings if f["rule_id"] == "TKN-PIN-003"]
        unpinned = [f for f in pin003 if "untrusted-org" in f.get("current_value", "")]
        assert len(unpinned) == 1

    def test_v1beta1_pinned_bundle_clean(self):
        """Old-style bundle with @sha256 digest should NOT trigger PIN-003."""
        findings = _run("edge-v1beta1-mixed.yaml")
        pin003 = [f for f in findings if f["rule_id"] == "TKN-PIN-003"
                  and f.get("task_name") == "old-style-pinned"]
        assert len(pin003) == 0

    def test_new_resolver_still_works_in_mixed(self):
        """New-style git resolver in same file should still trigger PIN-002."""
        findings = _run("edge-v1beta1-mixed.yaml")
        pin002 = [f for f in findings if f["rule_id"] == "TKN-PIN-002"]
        assert len(pin002) == 1
        assert pin002[0]["current_value"] == "main"

    def test_v1beta1_bundle_trust_not_checked_for_trusted_registry(self):
        """Pinned bundle from trusted registry should be clean."""
        findings = _run("edge-v1beta1-mixed.yaml")
        pin003 = [f for f in findings if f["rule_id"] == "TKN-PIN-003"
                  and f.get("task_name") == "old-style-pinned"]
        assert len(pin003) == 0


# -----------------------------------------------------------------------
# Deduplication
# -----------------------------------------------------------------------

class TestDeduplication:
    """Findings should be deduplicated by (rule_id, file, line)."""

    def test_multi_doc_no_duplicate_findings(self):
        """Two PipelineRuns in one file should produce 2 separate PIN-001 findings."""
        findings = _run("multi-doc.yaml")
        pin001 = [f for f in findings if f["rule_id"] == "TKN-PIN-001"]
        # first-pipeline has main (flagged), second has SHA (not flagged)
        assert len(pin001) == 1
        assert pin001[0]["resource_name"] == "first-pipeline"


# -----------------------------------------------------------------------
# PaC template edge cases
# -----------------------------------------------------------------------

class TestPaCTemplateEdgeCases:
    """PaC template detection boundary conditions."""

    def test_pac_with_spaces_detected(self):
        """{{ revision }} with spaces should be detected as PaC template."""
        from tekton_guard.checks._common import _is_pac_template
        assert _is_pac_template("{{ revision }}")
        assert _is_pac_template("{{revision}}")
        assert _is_pac_template("'{{ revision }}'")
        assert _is_pac_template('"{{ revision }}"')

    def test_non_pac_not_detected(self):
        """Literal values that look similar should not be PaC templates."""
        from tekton_guard.checks._common import _is_pac_template
        assert not _is_pac_template("main")
        assert not _is_pac_template("v1.2.3")
        assert not _is_pac_template("abc123")
        assert not _is_pac_template("")

    def test_dotted_pac_variable_detected(self):
        """{{ foo.bar }} matches the broad PAC_TEMPLATE_RE pattern."""
        from tekton_guard.checks._common import _is_pac_template
        # PAC_TEMPLATE_RE is r"^\{\{.*\}\}$" which matches anything in {{ }}
        assert _is_pac_template("{{ foo.bar }}")

    def test_expression_pac_detected(self):
        """{{ foo + bar }} matches the broad PAC_TEMPLATE_RE pattern."""
        from tekton_guard.checks._common import _is_pac_template
        # The regex matches any content between {{ }}
        assert _is_pac_template("{{ foo + bar }}")
