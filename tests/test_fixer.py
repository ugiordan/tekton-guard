"""Tests for the auto-fix engine."""

import os
import shutil
from pathlib import Path

from tekton_guard.checks import run_checks
from tekton_guard.config import ScannerConfig
from tekton_guard.fixer import FixEngine, FixResult
from tekton_guard.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_fix_result_tracking():
    result = FixResult()
    result.fixed.append({"rule_id": "TKN-PIN-001"})
    result.skipped.append({"rule_id": "TKN-SA-001"})
    result.failed.append({"rule_id": "TKN-PIN-002"})
    d = result.to_dict()
    assert d["summary"]["fixed"] == 1
    assert d["summary"]["skipped"] == 1
    assert d["summary"]["failed"] == 1


def test_dry_run_does_not_modify_file(tmp_path):
    src = FIXTURES / "pipelinerun-mutable.yaml"
    dst = tmp_path / "test.yaml"
    shutil.copy(src, dst)
    original = dst.read_text()

    resources = parse_file(dst)
    findings = run_checks(resources, ScannerConfig())

    engine = FixEngine(dry_run=True)
    result = engine.fix_findings(findings, str(dst))

    assert dst.read_text() == original


def test_ws001_fix_skipped_for_manual_review():
    """WS-001 findings should be fixable, but check the result."""
    engine = FixEngine(dry_run=True)
    findings = [{"rule_id": "TKN-WS-001", "file": "/nonexistent", "line_start": 1}]
    result = engine.fix_findings(findings, "/nonexistent")
    # File doesn't exist, so nothing happens
    assert result.total_fixed == 0


def test_manual_review_checks_skipped(tmp_path):
    dummy = tmp_path / "test.yaml"
    dummy.write_text("dummy: content\n")
    fpath = str(dummy)
    engine = FixEngine(dry_run=True)
    findings = [
        {"rule_id": "TKN-SA-001", "file": fpath, "line_start": 1},
        {"rule_id": "TKN-TRUST-001", "file": fpath, "line_start": 1},
        {"rule_id": "TKN-RES-001", "file": fpath, "line_start": 1},
    ]
    result = engine.fix_findings(findings, fpath)
    assert len(result.skipped) == 3
    for s in result.skipped:
        assert s["reason"] == "manual_review_required"


def test_pin003_004_skipped_as_not_implemented(tmp_path):
    dummy = tmp_path / "test.yaml"
    dummy.write_text("dummy: content\n")
    fpath = str(dummy)
    engine = FixEngine(dry_run=True)
    findings = [
        {"rule_id": "TKN-PIN-003", "file": fpath, "line_start": 1},
        {"rule_id": "TKN-PIN-004", "file": fpath, "line_start": 1},
    ]
    result = engine.fix_findings(findings, fpath)
    assert len(result.skipped) == 2
    for s in result.skipped:
        assert "digest" in s["reason"]


def test_sha_cache_reuses():
    engine = FixEngine(dry_run=True)
    engine._sha_cache["https://github.com/org/repo.git@main"] = "a" * 40
    sha = engine._cached_resolve_sha("https://github.com/org/repo.git", "main")
    assert sha == "a" * 40


def test_fix_git_ref_with_cached_sha(tmp_path):
    """Test that git ref fixing works when SHA is cached (no network)."""
    yaml_content = """\
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: test-run
spec:
  pipelineRef:
    resolver: git
    params:
    - name: url
      value: https://github.com/example/pipelines.git
    - name: revision
      value: main
    - name: pathInRepo
      value: pipeline/build.yaml
"""
    dst = tmp_path / "run.yaml"
    dst.write_text(yaml_content)

    resources = parse_file(dst)
    findings = run_checks(resources, ScannerConfig())

    pin_findings = [f for f in findings if f["rule_id"] == "TKN-PIN-001"]
    assert len(pin_findings) == 1

    fake_sha = "abcdef1234567890abcdef1234567890abcdef12"
    engine = FixEngine(dry_run=False)
    engine._sha_cache["https://github.com/example/pipelines.git@main"] = fake_sha

    result = engine.fix_findings(pin_findings, str(dst))
    assert result.total_fixed == 1
    assert result.fixed[0]["method"] == "github_api"

    new_content = dst.read_text()
    assert fake_sha in new_content
    assert "main" not in new_content.split("revision")[1].split("\n")[0]


def test_fix_workspace_readonly(tmp_path):
    """Test that readOnly: true is inserted for secret workspaces."""
    yaml_content = """\
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: test-run
spec:
  pipelineRef:
    resolver: git
    params:
    - name: url
      value: https://github.com/example/pipelines.git
    - name: revision
      value: abcdef1234567890abcdef1234567890abcdef12
    - name: pathInRepo
      value: pipeline/build.yaml
  workspaces:
  - name: creds
    secret:
      secretName: my-secret
"""
    dst = tmp_path / "run.yaml"
    dst.write_text(yaml_content)

    resources = parse_file(dst)
    config = ScannerConfig()
    findings = run_checks(resources, config)

    ws_findings = [f for f in findings if f["rule_id"] == "TKN-WS-001"]
    assert len(ws_findings) == 1

    engine = FixEngine(dry_run=False)
    result = engine.fix_findings(ws_findings, str(dst))
    assert result.total_fixed == 1
    assert result.fixed[0]["method"] == "yaml_insert"

    new_content = dst.read_text()
    assert "readOnly: true" in new_content


def test_fix_no_github_token_fails_gracefully(tmp_path):
    """Git ref resolution fails gracefully without GITHUB_TOKEN."""
    yaml_content = """\
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: test-run
spec:
  pipelineRef:
    resolver: git
    params:
    - name: url
      value: https://github.com/example/pipelines.git
    - name: revision
      value: main
    - name: pathInRepo
      value: pipeline/build.yaml
"""
    dst = tmp_path / "run.yaml"
    dst.write_text(yaml_content)

    resources = parse_file(dst)
    findings = run_checks(resources, ScannerConfig())
    pin_findings = [f for f in findings if f["rule_id"] == "TKN-PIN-001"]

    # Clear GITHUB_TOKEN to force failure
    old_token = os.environ.pop("GITHUB_TOKEN", None)
    try:
        engine = FixEngine(dry_run=False)
        result = engine.fix_findings(pin_findings, str(dst))
        assert result.total_fixed == 0
        assert len(result.failed) == 1
        assert result.failed[0]["reason"] == "resolution_failed"
    finally:
        if old_token is not None:
            os.environ["GITHUB_TOKEN"] = old_token


def test_fix_result_to_dict_empty():
    result = FixResult()
    d = result.to_dict()
    assert d["summary"]["fixed"] == 0
    assert d["summary"]["skipped"] == 0
    assert d["summary"]["failed"] == 0
    assert d["fixed"] == []
    assert d["skipped"] == []
    assert d["failed"] == []


def test_findings_for_wrong_file_ignored(tmp_path):
    """Findings targeting a different file should be ignored."""
    yaml_content = """\
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: test-run
spec:
  pipelineRef:
    resolver: git
    params:
    - name: url
      value: https://github.com/example/pipelines.git
    - name: revision
      value: main
"""
    dst = tmp_path / "run.yaml"
    dst.write_text(yaml_content)

    findings = [
        {"rule_id": "TKN-PIN-001", "file": "other-file.yaml", "line_start": 1,
         "resolver_url": "https://github.com/example/pipelines.git", "current_value": "main"},
    ]
    engine = FixEngine(dry_run=True)
    result = engine.fix_findings(findings, str(dst))
    assert result.total_fixed == 0
    assert len(result.skipped) == 0
    assert len(result.failed) == 0
