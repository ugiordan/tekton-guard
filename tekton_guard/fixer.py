"""Auto-fix engine for tekton-guard findings."""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _resolve_git_sha(url: str, ref: str) -> str | None:
    """Resolve a git ref to SHA via GitHub API. Requires GITHUB_TOKEN."""
    import urllib.request

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        logger.warning("GITHUB_TOKEN not set, cannot resolve SHA for %s@%s", url, ref)
        return None

    # Extract owner/repo from URL
    clean = url.rstrip("/").removesuffix(".git")
    match = re.search(r"github\.com/([^/]+/[^/]+)", clean)
    if not match:
        logger.debug("Not a GitHub URL: %s", url)
        return None

    owner_repo = match.group(1)
    api_url = f"https://api.github.com/repos/{owner_repo}/commits/{ref}"

    try:
        req = urllib.request.Request(api_url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "tekton-guard/1.1",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            sha = data.get("sha", "")
            if sha and _SHA_RE.match(sha):
                return sha
    except Exception as e:
        logger.debug("Failed to resolve %s@%s: %s", url, ref, e)

    return None


class FixResult:
    def __init__(self):
        self.fixed: list[dict[str, Any]] = []
        self.skipped: list[dict[str, Any]] = []
        self.failed: list[dict[str, Any]] = []

    @property
    def total_fixed(self) -> int:
        return len(self.fixed)

    def to_dict(self) -> dict:
        return {
            "fixed": self.fixed,
            "skipped": self.skipped,
            "failed": self.failed,
            "summary": {
                "fixed": len(self.fixed),
                "skipped": len(self.skipped),
                "failed": len(self.failed),
            },
        }


class FixEngine:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._sha_cache: dict[str, str | None] = {}

    def _cached_resolve_sha(self, url: str, ref: str) -> str | None:
        key = f"{url}@{ref}"
        if key not in self._sha_cache:
            self._sha_cache[key] = _resolve_git_sha(url, ref)
        return self._sha_cache[key]

    def fix_findings(self, findings: list[dict], file_path: str) -> FixResult:
        """Apply fixes to findings in a single file."""
        result = FixResult()
        path = Path(file_path)
        if not path.exists():
            return result

        content = path.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")
        changes: list[tuple[int, str, str]] = []  # (line_idx, old, new)

        for finding in findings:
            if finding.get("file") != file_path:
                continue

            rule = finding["rule_id"]
            line_num = finding.get("line_start", 0)

            if rule in ("TKN-PIN-001", "TKN-PIN-002", "TKN-PIN-005"):
                fix = self._fix_git_ref(finding, lines)
                if fix:
                    changes.append(fix)
                    result.fixed.append({
                        "rule_id": rule,
                        "file": file_path,
                        "line": line_num,
                        "original": finding.get("current_value", ""),
                        "resolved": fix[2].strip(),
                        "method": "github_api",
                    })
                else:
                    result.failed.append({
                        "rule_id": rule,
                        "file": file_path,
                        "line": line_num,
                        "reason": "resolution_failed",
                    })

            elif rule == "TKN-WS-001":
                fix = self._fix_workspace_readonly(finding, lines)
                if fix:
                    changes.append(fix)
                    result.fixed.append({
                        "rule_id": rule,
                        "file": file_path,
                        "line": line_num,
                        "original": "readOnly not set",
                        "resolved": "readOnly: true",
                        "method": "yaml_insert",
                    })

            elif rule in ("TKN-PIN-003", "TKN-PIN-004"):
                result.skipped.append({
                    "rule_id": rule,
                    "file": file_path,
                    "line": line_num,
                    "reason": "digest_resolution_not_implemented",
                })

            else:
                result.skipped.append({
                    "rule_id": rule,
                    "file": file_path,
                    "line": line_num,
                    "reason": "manual_review_required",
                })

        if changes and not self.dry_run:
            self._apply_changes(path, lines, changes)

        return result

    def _fix_git_ref(
        self, finding: dict, lines: list[str],
    ) -> tuple[int, str, str] | None:
        url = finding.get("resolver_url", "")
        current = finding.get("current_value", "")
        if not url or not current:
            return None

        sha = self._cached_resolve_sha(url, current)
        if not sha or not _SHA_RE.match(sha):
            return None

        line_idx = finding.get("line_start", 0) - 1
        if line_idx < 0 or line_idx >= len(lines):
            return None

        # Search for the line containing 'value: <current>' near the reported line
        search_range = range(max(0, line_idx - 3), min(len(lines), line_idx + 4))
        for i in search_range:
            line = lines[i]
            stripped = line.strip()
            # Only match lines with 'value:' prefix containing the current ref
            if stripped.startswith("value:") and current in stripped:
                new_line = line.replace(current, sha, 1)
                return (i, line, new_line)

        return None

    def _fix_workspace_readonly(
        self, finding: dict, lines: list[str],
    ) -> tuple[int, str, str] | None:
        line_idx = finding.get("line_start", 0) - 1
        if line_idx < 0 or line_idx >= len(lines):
            return None

        # Find the secret: or secretName: line near this workspace
        for i in range(line_idx, min(len(lines), line_idx + 10)):
            if "secretName:" in lines[i] or "secret:" in lines[i]:
                indent = len(lines[i]) - len(lines[i].lstrip())
                new_line = " " * indent + "readOnly: true"
                return (i, lines[i], lines[i] + "\n" + new_line)
        return None

    def _apply_changes(
        self,
        path: Path,
        lines: list[str],
        changes: list[tuple[int, str, str]],
    ) -> None:
        # Sort changes in reverse order to preserve line numbers
        changes.sort(key=lambda x: x[0], reverse=True)

        for line_idx, old_line, new_line in changes:
            if "\n" in new_line:
                # Multi-line replacement: split and splice into the lines list
                new_lines = new_line.split("\n")
                lines[line_idx:line_idx + 1] = new_lines
            else:
                lines[line_idx] = new_line

        new_content = "\n".join(lines)
        original_mode = path.stat().st_mode if path.exists() else 0o644

        # Atomic write
        fd, tmp_path = tempfile.mkstemp(suffix=".yaml", dir=str(path.parent))
        try:
            os.write(fd, new_content.encode("utf-8"))
            os.close(fd)
            fd = -1  # mark as closed
            os.chmod(tmp_path, original_mode)
            os.rename(tmp_path, str(path))
        except Exception:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
