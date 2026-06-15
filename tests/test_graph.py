"""Tests for cross-repo dependency graph."""

from tekton_guard.graph import (
    build_dependency_graph,
    calculate_blast_radius,
    detect_cycles,
    _url_to_repo_id,
    _extract_repo_id,
)
from tekton_guard.parser import TektonResource, ResolverRef


def _make_pipelinerun(name: str, file_path: str, url: str, revision: str, path_in_repo: str = "") -> TektonResource:
    from tekton_guard.parser import SHA_RE
    is_pinned = bool(SHA_RE.match(revision))
    return TektonResource(
        kind="PipelineRun",
        api_version="tekton.dev/v1",
        name=name,
        namespace="test",
        file_path=file_path,
        line_offset=1,
        pipeline_ref=ResolverRef(
            resolver_type="git",
            params={"url": url, "revision": revision, "pathInRepo": path_in_repo},
        ),
    )


def test_build_graph_basic():
    resources = [
        _make_pipelinerun("pr1", "/repos/org/repo-a/.tekton/push.yaml",
                         "https://github.com/org/pipeline-repo.git", "main",
                         "pipeline/build.yaml"),
        _make_pipelinerun("pr2", "/repos/org/repo-b/.tekton/push.yaml",
                         "https://github.com/org/pipeline-repo.git", "main",
                         "pipeline/build.yaml"),
    ]
    graph = build_dependency_graph(resources)
    assert len(graph["nodes"]) == 3  # repo-a, repo-b, pipeline-repo
    assert len(graph["edges"]) == 2


def test_blast_radius():
    resources = [
        _make_pipelinerun("pr1", "/repos/org/repo-a/.tekton/push.yaml",
                         "https://github.com/org/shared.git", "main", "p.yaml"),
        _make_pipelinerun("pr2", "/repos/org/repo-b/.tekton/push.yaml",
                         "https://github.com/org/shared.git", "main", "p.yaml"),
        _make_pipelinerun("pr3", "/repos/org/repo-c/.tekton/push.yaml",
                         "https://github.com/org/shared.git", "main", "p.yaml"),
    ]
    graph = build_dependency_graph(resources)
    blast = calculate_blast_radius(graph)
    assert blast["org/shared"] == 3


def test_no_cycles():
    resources = [
        _make_pipelinerun("pr1", "/repos/org/a/.tekton/push.yaml",
                         "https://github.com/org/b.git", "main", "p.yaml"),
    ]
    graph = build_dependency_graph(resources)
    cycles = detect_cycles(graph)
    assert len(cycles) == 0


def test_cycle_detection():
    graph = {
        "edges": [
            {"from": "org/a", "to": "org/b"},
            {"from": "org/b", "to": "org/c"},
            {"from": "org/c", "to": "org/a"},
        ]
    }
    cycles = detect_cycles(graph)
    assert len(cycles) >= 1


def test_url_to_repo_id():
    assert _url_to_repo_id("https://github.com/org/repo.git") == "org/repo"
    assert _url_to_repo_id("https://github.com/org/repo") == "org/repo"
    assert _url_to_repo_id("https://gitlab.com/org/repo") == ""


def test_extract_repo_id():
    assert _extract_repo_id("/repos/org/my-repo/.tekton/push.yaml") == "org/my-repo"
    assert _extract_repo_id("remote:org/pipeline-repo@main/p.yaml") == "org/pipeline-repo"


def test_pinned_edge():
    resources = [
        _make_pipelinerun("pr1", "/repos/org/repo/.tekton/push.yaml",
                         "https://github.com/org/pipelines.git",
                         "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                         "pipeline/build.yaml"),
    ]
    graph = build_dependency_graph(resources)
    assert graph["edges"][0]["pinned"] is True


def test_unpinned_edge():
    resources = [
        _make_pipelinerun("pr1", "/repos/org/repo/.tekton/push.yaml",
                         "https://github.com/org/pipelines.git", "main",
                         "pipeline/build.yaml"),
    ]
    graph = build_dependency_graph(resources)
    assert graph["edges"][0]["pinned"] is False


def test_dedup_edges():
    """Same consumer -> source -> path should produce only one edge."""
    resources = [
        _make_pipelinerun("pr1", "/repos/org/repo/.tekton/push.yaml",
                         "https://github.com/org/pipelines.git", "main", "p.yaml"),
        _make_pipelinerun("pr2", "/repos/org/repo/.tekton/pr.yaml",
                         "https://github.com/org/pipelines.git", "main", "p.yaml"),
    ]
    graph = build_dependency_graph(resources)
    assert len(graph["edges"]) == 1
