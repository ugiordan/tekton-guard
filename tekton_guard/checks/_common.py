"""Shared helpers for tekton-guard checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import (
    StepDef,
    TektonResource,
)

PARAM_INTERP_RE = re.compile(r"\$\((?:params|tasks)\.[^)]+\)")
PAC_TEMPLATE_RE = re.compile(r"^\{\{.*\}\}$")

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CheckFn = Callable[[TektonResource, ScannerConfig], list[dict]]

_REGISTRY: list[CheckFn] = []


def register_check(func: CheckFn) -> CheckFn:
    """Decorator that registers a check function."""
    _REGISTRY.append(func)
    return func


def get_all_checks() -> list[CheckFn]:
    return list(_REGISTRY)


def _is_pac_template(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    return bool(PAC_TEMPLATE_RE.match(stripped))


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    resource: TektonResource,
    line: int,
    message: str,
    *,
    cwe: str = "",
    remediation: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file": resource.file_path,
        "line_start": line,
        "line_end": line,
        "message": message,
        "resource_kind": resource.kind,
        "resource_name": resource.name,
        "cwe": cwe,
        "remediation": remediation,
    }
    if extra:
        result.update(extra)
    return result


@dataclass
class ContainerInfo:
    container: StepDef
    container_type: str  # "step" | "sidecar"
    context: str         # e.g., "Task 'build-task'" or "pipeline task 'audit'"


def collect_all_containers(resource: TektonResource) -> list[ContainerInfo]:
    """Return all step-like containers (steps + sidecars) from a resource."""
    result: list[ContainerInfo] = []

    if resource.kind in ("Task", "StepAction", "TaskRun"):
        for step in resource.steps:
            ctx = f"Task '{resource.name}'" if resource.kind != "TaskRun" else f"TaskRun '{resource.name}'"
            result.append(ContainerInfo(step, "step", ctx))
        for sc in resource.sidecars:
            ctx = f"Task '{resource.name}'" if resource.kind != "TaskRun" else f"TaskRun '{resource.name}'"
            result.append(ContainerInfo(sc, "sidecar", ctx))

    if resource.kind in ("Pipeline", "PipelineRun"):
        for pt in resource.pipeline_tasks + resource.finally_tasks:
            for step in pt.steps:
                result.append(ContainerInfo(step, "step", f"pipeline task '{pt.name}'"))
            for sc in pt.sidecars:
                result.append(ContainerInfo(sc, "sidecar", f"pipeline task '{pt.name}'"))

    return result
