"""Check registry with importlib auto-discovery."""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import SEVERITY_ORDER, get_all_checks

logger = logging.getLogger(__name__)

# Auto-import all check modules in this package (excludes __init__.py and _common.py)
_pkg_dir = Path(__file__).parent
for _mod_path in sorted(_pkg_dir.glob("*.py")):
    _mod_name = _mod_path.stem
    if _mod_name.startswith("_"):
        continue
    try:
        importlib.import_module(f"tekton_guard.checks.{_mod_name}")
    except Exception:
        logger.error("Failed to import check module: %s", _mod_name, exc_info=True)

_EXPECTED_MIN_CHECKS = 27

_loaded = get_all_checks()
if len(_loaded) < _EXPECTED_MIN_CHECKS:
    logger.warning(
        "Expected at least %d checks but only %d registered. Some check modules may have failed to import.",
        _EXPECTED_MIN_CHECKS, len(_loaded),
    )


def run_checks(
    resources: list[TektonResource],
    config: ScannerConfig,
) -> list[dict[str, Any]]:
    """Run all registered checks against all resources."""
    min_sev = SEVERITY_ORDER.get(config.min_severity.upper(), 0)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    all_checks = get_all_checks()
    for resource in resources:
        for check_fn in all_checks:
            check_id = check_fn.__doc__.split(":")[0].strip() if check_fn.__doc__ else ""
            if check_id and not config.should_run_check(check_id):
                continue
            for f in check_fn(resource, config):
                if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                    continue
                dedup_key = (f["rule_id"], f["file"], f.get("line_start", 0))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(f)

    return findings
