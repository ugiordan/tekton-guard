"""Tests for CLI exit codes and flags."""

from pathlib import Path
from tekton_guard.cli import main

FIXTURES = str(Path(__file__).parent / "fixtures")


def test_exit_0_no_findings():
    code = main([FIXTURES + "/pipelinerun-pac-self-ref.yaml", "--format", "text"])
    assert code == 0


def test_exit_1_findings():
    code = main([FIXTURES + "/pipelinerun-mutable.yaml", "--format", "text"])
    assert code == 1


def test_exit_2_bad_path():
    code = main(["/nonexistent/path", "--format", "text"])
    assert code == 2


def test_fail_on_high_skips_low():
    code = main([FIXTURES + "/task-with-injection.yaml", "--fail-on", "HIGH", "--format", "text"])
    assert code == 0


def test_fail_on_high_catches_high():
    code = main([FIXTURES + "/pipelinerun-mutable.yaml", "--fail-on", "HIGH", "--format", "text"])
    assert code == 1


def test_exit_zero_flag():
    code = main([FIXTURES + "/pipelinerun-mutable.yaml", "--exit-zero", "--format", "text"])
    assert code == 0


def test_update_baseline_creates_file(tmp_path):
    baseline_file = str(tmp_path / "baseline.json")
    code = main([FIXTURES + "/pipelinerun-mutable.yaml", "--format", "text",
                 "--update-baseline", baseline_file])
    import json
    baseline = json.loads(Path(baseline_file).read_text())
    assert baseline["version"] == "1.0"
    assert len(baseline["findings"]) > 0
    assert all(f["rule_id"] for f in baseline["findings"])


def test_baseline_suppresses_findings(tmp_path):
    import json
    # First generate baseline
    baseline_file = str(tmp_path / "baseline.json")
    main([FIXTURES + "/pipelinerun-mutable.yaml", "--format", "text",
          "--update-baseline", baseline_file])
    # Then scan with baseline
    code = main([FIXTURES + "/pipelinerun-mutable.yaml", "--format", "text",
                 "--baseline", baseline_file])
    assert code == 0  # all findings suppressed
