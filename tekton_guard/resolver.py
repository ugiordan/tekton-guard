"""Resolve remote Tekton resources via git resolver URLs."""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tekton_guard.parser import ResolverRef, TektonResource, parse_file

logger = logging.getLogger(__name__)

_cache: dict[str, list[TektonResource]] = {}


def _git_url_to_raw_url(url: str, revision: str, path: str) -> str | None:
    """Convert a git clone URL to a raw file URL for GitHub repos."""
    url = url.rstrip("/").removesuffix(".git")
    if "github.com" not in url:
        return None
    return f"{url}/raw/{revision}/{path}"


def _fetch_via_clone(url: str, revision: str, path: str, cache_dir: Path | None = None) -> list[TektonResource]:
    """Fetch a remote Tekton file by shallow-cloning the repo."""
    cache_key = f"{url}@{revision}:{path}"
    if cache_key in _cache:
        return _cache[cache_key]

    clone_url = url.rstrip("/")
    if not clone_url.endswith(".git"):
        clone_url += ".git"

    with tempfile.TemporaryDirectory(prefix="tekton-resolve-") as tmpdir:
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", revision,
                 "--single-branch", "--no-tags", clone_url, tmpdir],
                capture_output=True, timeout=30, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            # Branch clone failed, try fetching specific commit (if SHA)
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--no-tags", clone_url, tmpdir],
                    capture_output=True, timeout=30, check=True,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("Failed to clone %s", clone_url)
                _cache[cache_key] = []
                return []

        target = Path(tmpdir) / path
        # Validate resolved path stays within tmpdir
        try:
            target.resolve().relative_to(Path(tmpdir).resolve())
        except ValueError:
            logger.debug("Path traversal detected: %s", path)
            _cache[cache_key] = []
            return []
        if not target.exists():
            logger.debug("Path %s not found in %s", path, clone_url)
            _cache[cache_key] = []
            return []

        resources = parse_file(target)
        # Rewrite file_path to show the remote origin
        short_url = url.rstrip("/").removesuffix(".git").split("github.com/")[-1]
        for r in resources:
            r.file_path = f"remote:{short_url}@{revision[:12]}/{path}"

        _cache[cache_key] = resources
        return resources


def _fetch_via_api(url: str, revision: str, path: str) -> list[TektonResource]:
    """Fetch a remote Tekton file via GitHub raw content URL (no git clone needed)."""
    import urllib.request

    # Validate path has no traversal
    if ".." in path:
        logger.debug("Rejecting path with traversal: %s", path)
        return []

    cache_key = f"{url}@{revision}:{path}"
    if cache_key in _cache:
        return _cache[cache_key]

    raw_url = _git_url_to_raw_url(url, revision, path)
    if not raw_url:
        return []

    try:
        req = urllib.request.Request(raw_url, headers={"User-Agent": "tekton-guard/1.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8")
    except Exception:
        logger.debug("Failed to fetch %s", raw_url)
        _cache[cache_key] = []
        return []

    # Parse the fetched YAML using our parser
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(content)
        tmp_path = f.name

    try:
        resources = parse_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    short_url = url.rstrip("/").removesuffix(".git").split("github.com/")[-1]
    for r in resources:
        r.file_path = f"remote:{short_url}@{revision[:12]}/{path}"

    _cache[cache_key] = resources
    return resources


def resolve_remote_refs(
    resources: list[TektonResource],
    *,
    use_network: bool = True,
    method: str = "api",
) -> list[TektonResource]:
    """Resolve remote pipeline/task references and return additional resources to scan.

    Args:
        resources: Already-parsed local resources
        use_network: Whether to actually fetch remote content
        method: "api" (HTTP fetch, fast) or "clone" (git clone, works offline with token)

    Returns:
        Additional TektonResource objects fetched from remote sources
    """
    if not use_network:
        return []

    additional: list[TektonResource] = []
    fetch = _fetch_via_api if method == "api" else _fetch_via_clone

    for resource in resources:
        # Resolve pipelineRef on PipelineRuns
        if resource.pipeline_ref and resource.pipeline_ref.resolver_type == "git":
            ref = resource.pipeline_ref
            path_in_repo = ref.params.get("pathInRepo", "")
            if ref.url and ref.revision and path_in_repo:
                remote = fetch(ref.url, ref.revision, path_in_repo)
                additional.extend(remote)

        # Resolve taskRef on Pipeline tasks
        for pt in resource.pipeline_tasks + resource.finally_tasks:
            if pt.task_ref and pt.task_ref.resolver:
                ref = pt.task_ref.resolver
                if ref.resolver_type == "git":
                    path_in_repo = ref.params.get("pathInRepo", "")
                    if ref.url and ref.revision and path_in_repo:
                        remote = fetch(ref.url, ref.revision, path_in_repo)
                        additional.extend(remote)

    return additional
