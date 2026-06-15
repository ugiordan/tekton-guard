"""Tests for Tekton YAML parser."""

from pathlib import Path

from tekton_guard.parser import parse_file, find_tekton_files

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_pipelinerun():
    resources = parse_file(FIXTURES / "pipelinerun-mutable.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert r.kind == "PipelineRun"
    assert r.name == "test-pipeline-on-push"
    assert r.namespace == "test-tenant"
    assert r.pipeline_ref is not None
    assert r.pipeline_ref.resolver_type == "git"
    assert r.pipeline_ref.url == "https://github.com/example/pipelines.git"
    assert r.pipeline_ref.revision == "main"
    assert not r.pipeline_ref.is_sha_pinned()
    assert r.service_account == "build-pipeline-sa"
    assert len(r.workspaces) == 1
    assert r.workspaces[0].secret_name == "{{ git_auth_secret }}"


def test_parse_pinned_pipelinerun():
    resources = parse_file(FIXTURES / "pipelinerun-pinned.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert r.pipeline_ref.is_sha_pinned()
    assert r.workspaces[0].is_read_only is True


def test_parse_pipeline():
    resources = parse_file(FIXTURES / "pipeline-with-tasks.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert r.kind == "Pipeline"
    assert len(r.pipeline_tasks) == 3
    assert len(r.finally_tasks) == 1

    # git-clone: cluster task ref
    assert r.pipeline_tasks[0].task_ref.name == "git-clone"
    assert r.pipeline_tasks[0].task_ref.resolver is None

    # build: bundles resolver
    build_ref = r.pipeline_tasks[1].task_ref.resolver
    assert build_ref.resolver_type == "bundles"
    assert "quay.io/example/build-task:v1.0" in build_ref.bundle

    # external-scan: git resolver
    scan_ref = r.pipeline_tasks[2].task_ref.resolver
    assert scan_ref.resolver_type == "git"
    assert scan_ref.revision == "develop"


def test_parse_task():
    resources = parse_file(FIXTURES / "task-with-injection.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert r.kind == "Task"
    assert len(r.steps) == 3
    assert r.steps[0].name == "clone"
    assert "$(params.revision)" in r.steps[0].script
    assert len(r.results) == 2


def test_parse_non_tekton():
    resources = parse_file(FIXTURES / "non-tekton.yaml")
    assert len(resources) == 0


def test_parse_nonexistent():
    resources = parse_file("/nonexistent/path.yaml")
    assert len(resources) == 0


def test_find_tekton_files_single():
    files = find_tekton_files(FIXTURES / "pipelinerun-mutable.yaml")
    assert len(files) == 1


def test_labels_and_annotations():
    resources = parse_file(FIXTURES / "pipelinerun-mutable.yaml")
    r = resources[0]
    assert r.labels["pipelines.appstudio.openshift.io/type"] == "build"
    assert "build.appstudio.redhat.com/commit_sha" in r.annotations


def test_parse_multi_document():
    resources = parse_file(FIXTURES / "multi-doc.yaml")
    assert len(resources) == 2  # ConfigMap skipped
    assert resources[0].name == "first-pipeline"
    assert resources[1].name == "second-pipeline"
    assert resources[0].pipeline_ref.revision == "main"
    assert resources[1].pipeline_ref.is_sha_pinned()


def test_multi_doc_line_offsets():
    resources = parse_file(FIXTURES / "multi-doc.yaml")
    assert resources[0].line_offset < resources[1].line_offset


def test_parse_sidecars():
    resources = parse_file(FIXTURES / "task-with-sidecars.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert len(r.steps) == 1
    assert len(r.sidecars) == 1
    sc = r.sidecars[0]
    assert sc.name == "logging-sidecar"
    assert "fluentd" in sc.image
    assert "curl" in sc.script


def test_parse_volumes():
    resources = parse_file(FIXTURES / "task-with-volumes.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert len(r.volumes) >= 2
    docker_vol = [v for v in r.volumes if v.get("name") == "docker-socket"]
    assert len(docker_vol) == 1
    assert "hostPath" in docker_vol[0]
    assert r.steps[0].volume_mounts is not None
    assert len(r.steps[0].volume_mounts) == 2


def test_parse_v1beta1_bundle():
    resources = parse_file(FIXTURES / "pipeline-v1beta1-bundle.yaml")
    assert len(resources) == 1
    r = resources[0]
    assert len(r.pipeline_tasks) == 2

    build_ref = r.pipeline_tasks[0].task_ref
    assert build_ref.resolver is not None
    assert build_ref.resolver.resolver_type == "bundles"
    assert "quay.io/example/tekton-bundles:latest" in build_ref.resolver.bundle
    assert not build_ref.resolver.is_sha_pinned()

    test_ref = r.pipeline_tasks[1].task_ref
    assert test_ref.resolver is not None
    assert test_ref.resolver.is_sha_pinned()
