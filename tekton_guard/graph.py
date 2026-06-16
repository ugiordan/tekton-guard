"""Cross-repo dependency graph for Tekton pipeline references."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from tekton_guard.parser import TektonResource


def build_dependency_graph(resources: list[TektonResource]) -> dict[str, Any]:
    """Build a dependency graph from parsed resources.

    Nodes are repos (consumers or pipeline sources).
    Edges represent git resolver references between repos.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple[str, str, str]] = set()

    for resource in resources:
        consumer = _extract_repo_id(resource.file_path)
        if not consumer:
            continue
        if consumer not in nodes:
            nodes[consumer] = {"id": consumer, "type": "consumer"}

        refs = _collect_git_refs(resource)
        for ref_url, ref_path, is_pinned in refs:
            source = _url_to_repo_id(ref_url)
            if not source:
                continue
            if source not in nodes:
                nodes[source] = {"id": source, "type": "pipeline_source"}

            edge_key = (consumer, source, ref_path)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            edges.append({
                "from": consumer,
                "to": source,
                "ref": ref_path,
                "pinned": is_pinned,
                "observed_at": datetime.now(timezone.utc).isoformat(),
            })

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def calculate_blast_radius(graph: dict[str, Any]) -> dict[str, int]:
    """Calculate how many consumers depend on each pipeline source."""
    source_consumers: dict[str, set[str]] = {}
    for edge in graph.get("edges", []):
        source = edge["to"]
        consumer = edge["from"]
        source_consumers.setdefault(source, set()).add(consumer)
    return {source: len(consumers) for source, consumers in source_consumers.items()}


def detect_cycles(graph: dict[str, Any]) -> list[list[str]]:
    """Detect cycles in the dependency graph using DFS."""
    adjacency: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        adjacency.setdefault(edge["from"], []).append(edge["to"])

    visited: set[str] = set()
    path: list[str] = []
    path_set: set[str] = set()
    cycles: list[list[str]] = []

    def _dfs(node: str) -> None:
        if node in path_set:
            cycle_start = path.index(node)
            cycles.append(path[cycle_start:] + [node])
            return
        if node in visited:
            return
        visited.add(node)
        path.append(node)
        path_set.add(node)
        for neighbor in adjacency.get(node, []):
            _dfs(neighbor)
        path.pop()
        path_set.remove(node)

    for node in adjacency:
        if node not in visited:
            _dfs(node)

    return cycles


def _extract_repo_id(file_path: str) -> str:
    """Extract a repo identifier from a file path."""
    if file_path.startswith("remote:"):
        parts = file_path.split("@")[0].replace("remote:", "")
        return parts
    # Local file path: try to extract org/repo from path
    parts = file_path.split("/")
    for i, part in enumerate(parts):
        if part == ".tekton" and i >= 2:
            return f"{parts[i-2]}/{parts[i-1]}"
    return ""


def _url_to_repo_id(url: str) -> str:
    """Convert a git URL to a repo identifier."""
    clean = url.rstrip("/").removesuffix(".git")
    match = re.search(r"github\.com/([^/]+/[^/]+)", clean)
    return match.group(1) if match else ""


def _collect_git_refs(resource: TektonResource) -> list[tuple[str, str, bool]]:
    """Collect (url, pathInRepo, is_pinned) tuples from git resolver refs."""
    refs = []
    if resource.pipeline_ref and resource.pipeline_ref.resolver_type == "git":
        ref = resource.pipeline_ref
        path_in_repo = ref.params.get("pathInRepo", "")
        refs.append((ref.url, path_in_repo, ref.is_sha_pinned()))

    for pt in resource.pipeline_tasks + resource.finally_tasks:
        if pt.task_ref and pt.task_ref.resolver:
            ref = pt.task_ref.resolver
            if ref.resolver_type == "git":
                path_in_repo = ref.params.get("pathInRepo", "")
                refs.append((ref.url, path_in_repo, ref.is_sha_pinned()))

    return refs
