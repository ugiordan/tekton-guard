"""Check registry with explicit imports (PyInstaller-compatible)."""

from __future__ import annotations

import logging
from typing import Any

from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import SEVERITY_ORDER, get_all_checks

logger = logging.getLogger(__name__)

# Explicit imports so PyInstaller bundles all check modules.
# importlib.import_module + Path.glob doesn't work in frozen binaries
# because the .py files don't exist on the filesystem.
from tekton_guard.checks import chains  # noqa: F401
from tekton_guard.checks import exfiltration  # noqa: F401
from tekton_guard.checks import limits  # noqa: F401
from tekton_guard.checks import logic  # noqa: F401
from tekton_guard.checks import pinning  # noqa: F401
from tekton_guard.checks import result_injection  # noqa: F401
from tekton_guard.checks import security  # noqa: F401
from tekton_guard.checks import service_account  # noqa: F401
from tekton_guard.checks import triggers  # noqa: F401
from tekton_guard.checks import trust  # noqa: F401
from tekton_guard.checks import volumes  # noqa: F401
from tekton_guard.checks import workspace  # noqa: F401

_EXPECTED_MIN_CHECKS = 59

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
    seen: set[tuple[str, str, int, str]] = set()

    all_checks = get_all_checks()
    for resource in resources:
        for check_fn in all_checks:
            check_id = check_fn.__doc__.split(":")[0].strip() if check_fn.__doc__ else ""
            if check_id and not config.should_run_check(check_id):
                continue
            for f in check_fn(resource, config):
                if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                    continue
                dedup_key = (f["rule_id"], f["file"], f.get("line_start", 0), f.get("title", ""))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(f)

    from tekton_guard.checks._common import get_all_correlation_checks
    for check_fn in get_all_correlation_checks():
        check_id = check_fn.__doc__.split(":")[0].strip() if check_fn.__doc__ else ""
        if check_id and not config.should_run_check(check_id):
            continue
        for f in check_fn(resources, config):
            if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                continue
            dedup_key = (f["rule_id"], f["file"], f.get("line_start", 0), f.get("title", ""))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(f)

    return findings
