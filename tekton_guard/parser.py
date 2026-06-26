"""Parse Tekton CRDs from YAML files with line number tracking."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


TEKTON_KINDS = {"PipelineRun", "Pipeline", "Task", "TaskRun", "StepAction",
                "TriggerTemplate", "TriggerBinding", "EventListener",
                "Repository", "VerificationPolicy"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}")

_PAC_VAR_RE = re.compile(r"\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}")


@dataclass
class ResolverRef:
    resolver_type: str
    params: dict[str, Any] = field(default_factory=dict)
    line: int = 0

    @property
    def url(self) -> str:
        return str(self.params.get("url", ""))

    @property
    def revision(self) -> str:
        return str(self.params.get("revision", ""))

    @property
    def bundle(self) -> str:
        return str(self.params.get("bundle", ""))

    def is_sha_pinned(self) -> bool:
        if self.resolver_type == "git":
            return bool(SHA_RE.match(self.revision))
        if self.resolver_type == "bundles":
            return bool(DIGEST_RE.search(self.bundle))
        return False


@dataclass
class StepDef:
    name: str = ""
    image: str = ""
    image_line: int = 0
    script: str = ""
    script_line: int = 0
    command: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    args_line: int = 0
    security_context: dict[str, Any] = field(default_factory=dict)
    env: list[dict[str, Any]] = field(default_factory=list)
    ref: ResolverRef | None = None
    volume_mounts: list[dict[str, Any]] = field(default_factory=list)
    resources: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskRefDef:
    name: str = ""
    resolver: ResolverRef | None = None
    line: int = 0


@dataclass
class WorkspaceBinding:
    name: str = ""
    workspace: str = ""
    secret_name: str = ""
    is_read_only: bool | None = None
    line: int = 0


@dataclass
class PipelineTaskDef:
    name: str = ""
    task_ref: TaskRefDef | None = None
    workspaces: list[WorkspaceBinding] = field(default_factory=list)
    params: list[dict[str, Any]] = field(default_factory=list)
    steps: list[StepDef] = field(default_factory=list)
    sidecars: list[StepDef] = field(default_factory=list)
    line: int = 0


@dataclass
class TektonResource:
    kind: str
    api_version: str
    name: str
    namespace: str
    file_path: str
    line_offset: int

    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    pipeline_ref: ResolverRef | None = None
    task_ref: TaskRefDef | None = None
    service_account: str = ""
    service_account_line: int = 0
    workspaces: list[WorkspaceBinding] = field(default_factory=list)
    params: list[dict[str, Any]] = field(default_factory=list)

    pipeline_tasks: list[PipelineTaskDef] = field(default_factory=list)
    finally_tasks: list[PipelineTaskDef] = field(default_factory=list)

    steps: list[StepDef] = field(default_factory=list)
    sidecars: list[StepDef] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    volumes: list[dict[str, Any]] = field(default_factory=list)

    raw: dict[str, Any] = field(default_factory=dict)


def _get_line(data: Any, default: int = 0) -> int:
    """Get 1-based line number from a ruamel.yaml node."""
    if hasattr(data, "lc"):
        return data.lc.line + 1
    return default


def _to_plain(data: Any) -> Any:
    """Convert ruamel CommentedMap/Seq to plain dict/list for storage."""
    if isinstance(data, dict):
        return {str(k): _to_plain(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_to_plain(item) for item in data]
    return data


def _preprocess_pac_templates(content: str) -> tuple[str, dict[str, str]]:
    """Replace {{ var }} patterns with safe placeholders. Returns (processed, mapping)."""
    uid = uuid.uuid4().hex[:8]
    mapping: dict[str, str] = {}
    counter = 0

    def _replace(match: re.Match) -> str:
        nonlocal counter
        original = match.group(0)
        placeholder = f"__PAC_{uid}_{counter}__"
        mapping[placeholder] = original
        counter += 1
        return placeholder

    processed = _PAC_VAR_RE.sub(_replace, content)
    return processed, mapping


def _restore_pac_templates(content: str, mapping: dict[str, str]) -> str:
    """Restore PaC template placeholders to original values."""
    for placeholder, original in mapping.items():
        content = content.replace(placeholder, original)
    return content


def _yaml_load_all(content: str) -> list[Any]:
    """Load multi-document YAML with PaC template handling (parse-then-fallback)."""
    yaml = YAML()
    yaml.preserve_quotes = True

    try:
        return list(yaml.load_all(StringIO(content)))
    except Exception:
        pass

    processed, mapping = _preprocess_pac_templates(content)
    try:
        docs = list(yaml.load_all(StringIO(processed)))
    except Exception:
        return []

    def _restore_values(data: Any) -> Any:
        if isinstance(data, str):
            return _restore_pac_templates(data, mapping)
        if isinstance(data, dict):
            for k in list(data.keys()):
                data[k] = _restore_values(data[k])
            return data
        if isinstance(data, list):
            return [_restore_values(item) for item in data]
        return data

    return [_restore_values(doc) for doc in docs]


def _extract_resolver_ref(ref_data: dict, base_line: int) -> ResolverRef | None:
    resolver_type = ref_data.get("resolver")
    if not resolver_type:
        return None
    params = {}
    for p in ref_data.get("params", []):
        pname = p.get("name", "")
        pval = p.get("value", "")
        if pname:
            params[pname] = pval
    return ResolverRef(
        resolver_type=str(resolver_type),
        params=params,
        line=_get_line(ref_data, base_line),
    )


def _extract_task_ref(ref_data: dict, base_line: int) -> TaskRefDef:
    name = ref_data.get("name", "")
    resolver = _extract_resolver_ref(ref_data, base_line)
    if not resolver and "bundle" in ref_data:
        bundle_val = str(ref_data["bundle"])
        resolver = ResolverRef(
            resolver_type="bundles",
            params={"bundle": bundle_val},
            line=_get_line(ref_data, base_line),
        )
    return TaskRefDef(name=str(name) if name else "", resolver=resolver, line=_get_line(ref_data, base_line))


def _extract_steps(steps_data: list) -> list[StepDef]:
    result = []
    for s in steps_data or []:
        if not isinstance(s, dict):
            continue
        step_ref = None
        if "ref" in s and isinstance(s["ref"], dict):
            step_ref = _extract_resolver_ref(s["ref"], _get_line(s))
        step = StepDef(
            name=str(s.get("name", "")),
            image=str(s.get("image", "")),
            image_line=_get_line(s),
            script=str(s.get("script", "")),
            script_line=_get_line(s),
            command=list(s.get("command", [])),
            args=[str(a) for a in (s.get("args", []) or [])],
            args_line=_get_line(s),
            security_context=_to_plain(s.get("securityContext", {})) or {},
            env=_to_plain(s.get("env", [])) or [],
            ref=step_ref,
            volume_mounts=_to_plain(s.get("volumeMounts", [])) or [],
            resources=_to_plain(s.get("resources", {})) or {},
        )
        result.append(step)
    return result


def _extract_workspace_bindings(ws_data: list, base_line: int) -> list[WorkspaceBinding]:
    result = []
    for ws in ws_data or []:
        if not isinstance(ws, dict):
            continue
        secret = ws.get("secret", {})
        secret_name = ""
        if isinstance(secret, dict):
            secret_name = str(secret.get("secretName", ""))
        binding = WorkspaceBinding(
            name=str(ws.get("name", "")),
            workspace=str(ws.get("workspace", "")),
            secret_name=secret_name,
            is_read_only=ws.get("readOnly") if "readOnly" in ws else None,
            line=_get_line(ws, base_line),
        )
        result.append(binding)
    return result


def _extract_pipeline_tasks(tasks_data: list, base_line: int) -> list[PipelineTaskDef]:
    result = []
    for t in tasks_data or []:
        if not isinstance(t, dict):
            continue
        task_ref = None
        if "taskRef" in t:
            task_ref = _extract_task_ref(t["taskRef"], _get_line(t, base_line))
        inline_steps = []
        inline_sidecars = []
        if "taskSpec" in t and isinstance(t["taskSpec"], dict):
            inline_steps = _extract_steps(t["taskSpec"].get("steps", []))
            inline_sidecars = _extract_steps(t["taskSpec"].get("sidecars", []))
        pt = PipelineTaskDef(
            name=str(t.get("name", "")),
            task_ref=task_ref,
            workspaces=_extract_workspace_bindings(t.get("workspaces", []), _get_line(t, base_line)),
            params=_to_plain(t.get("params", [])) or [],
            steps=inline_steps,
            sidecars=inline_sidecars,
            line=_get_line(t, base_line),
        )
        result.append(pt)
    return result


def _parse_document(doc: dict, file_path: str, doc_line: int) -> TektonResource | None:
    kind = doc.get("kind", "")
    if kind not in TEKTON_KINDS:
        return None

    metadata = doc.get("metadata", {}) or {}
    spec = doc.get("spec", {}) or {}

    name = str(metadata.get("name", ""))
    namespace = str(metadata.get("namespace", ""))
    labels = _to_plain(metadata.get("labels", {})) or {}
    annotations = _to_plain(metadata.get("annotations", {})) or {}

    resource = TektonResource(
        kind=kind,
        api_version=str(doc.get("apiVersion", "")),
        name=name,
        namespace=namespace,
        file_path=file_path,
        line_offset=doc_line,
        labels=labels,
        annotations=annotations,
        raw=_to_plain(doc),
    )

    if kind in ("PipelineRun", "TaskRun"):
        if "pipelineRef" in spec:
            resource.pipeline_ref = _extract_resolver_ref(spec["pipelineRef"], _get_line(spec))
            if resource.pipeline_ref:
                for p in spec["pipelineRef"].get("params", []):
                    pname = p.get("name", "")
                    if pname == "revision":
                        resource.pipeline_ref.line = _get_line(p, resource.pipeline_ref.line)
        if "taskRef" in spec:
            resource.task_ref = _extract_task_ref(spec["taskRef"], _get_line(spec))

        trt = spec.get("taskRunTemplate", {}) or {}
        sa = trt.get("serviceAccountName", "") or spec.get("serviceAccountName", "")
        resource.service_account = str(sa)
        resource.service_account_line = _get_line(trt, _get_line(spec))

        resource.workspaces = _extract_workspace_bindings(spec.get("workspaces", []), _get_line(spec))
        resource.params = _to_plain(spec.get("params", [])) or []

        # Inline pipelineSpec: PipelineRun can embed pipeline definition directly
        if "pipelineSpec" in spec:
            ps = spec["pipelineSpec"]
            if isinstance(ps, dict):
                resource.pipeline_tasks = _extract_pipeline_tasks(ps.get("tasks", []), _get_line(ps))
                resource.finally_tasks = _extract_pipeline_tasks(ps.get("finally", []), _get_line(ps))

        # Inline taskSpec: TaskRun can embed task definition directly
        if "taskSpec" in spec and isinstance(spec["taskSpec"], dict):
            task_spec = spec["taskSpec"]
            resource.steps = _extract_steps(task_spec.get("steps", []))
            resource.sidecars = _extract_steps(task_spec.get("sidecars", []))
            resource.volumes = _to_plain(task_spec.get("volumes", [])) or []
            resource.results = _to_plain(task_spec.get("results", [])) or []

    if kind == "Pipeline":
        resource.pipeline_tasks = _extract_pipeline_tasks(spec.get("tasks", []), _get_line(spec))
        resource.finally_tasks = _extract_pipeline_tasks(spec.get("finally", []), _get_line(spec))

    if kind in ("Task", "StepAction"):
        resource.steps = _extract_steps(spec.get("steps", []))
        resource.results = _to_plain(spec.get("results", [])) or []
        resource.sidecars = _extract_steps(spec.get("sidecars", []))
        resource.volumes = _to_plain(spec.get("volumes", [])) or []

    return resource


def parse_file(file_path: str | Path) -> list[TektonResource]:
    """Parse a YAML file and return all Tekton resources found."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    resources = []

    for doc in _yaml_load_all(content):
        if not isinstance(doc, dict):
            continue
        doc_line = _get_line(doc, 1)
        resource = _parse_document(doc, str(file_path), doc_line)
        if resource:
            resources.append(resource)

    return resources


def find_tekton_files(root: str | Path) -> list[Path]:
    """Find all Tekton YAML files in a directory tree."""
    root_path = Path(root)
    if not root_path.is_dir():
        if root_path.is_file() and root_path.suffix in (".yaml", ".yml"):
            return [root_path]
        return []

    tekton_dir = root_path / ".tekton"
    if tekton_dir.is_dir():
        return sorted(
            p for p in tekton_dir.rglob("*.yaml")
        ) + sorted(
            p for p in tekton_dir.rglob("*.yml")
        )

    return sorted(
        p for p in root_path.rglob("*.yaml")
        if ".tekton" in p.parts
    ) + sorted(
        p for p in root_path.rglob("*.yml")
        if ".tekton" in p.parts
    )


def parse_directory(root: str | Path) -> list[TektonResource]:
    """Parse all Tekton files in a directory tree."""
    resources = []
    for path in find_tekton_files(root):
        resources.extend(parse_file(path))
    return resources
