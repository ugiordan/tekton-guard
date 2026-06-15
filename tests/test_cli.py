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
