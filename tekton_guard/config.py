"""Configuration for Tekton scanner trust lists and check settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


@dataclass
class ScannerConfig:
    trusted_git_sources: list[str] = field(default_factory=lambda: [
        "https://github.com/opendatahub-io/",
        "https://github.com/red-hat-data-services/",
        "https://github.com/konflux-ci/",
        "https://github.com/redhat-appstudio/",
    ])

    trusted_registries: list[str] = field(default_factory=lambda: [
        "quay.io/konflux-ci/",
        "quay.io/redhat-appstudio/",
        "quay.io/opendatahub/",
    ])

    skip_checks: list[str] = field(default_factory=lambda: [
        "TKN-LIMIT-001",  # noisy: fires on every step without resources, disable by default
    ])
    min_severity: str = "LOW"

    security_task_patterns: list[str] = field(default_factory=lambda: [
        "scan", "sign", "verify", "attest", "cosign",
        "enterprise-contract", "sast", "clair", "clamav",
        "sbom", "syft", "cyclonedx",
    ])

    shared_namespaces: list[str] = field(default_factory=lambda: [
        "tekton-pipelines",
        "openshift-pipelines",
    ])

    known_safe_secret_workspaces: list[str] = field(default_factory=lambda: [
        "git-auth",
    ])

    def is_trusted_git_source(self, url: str) -> bool:
        if not url:
            return False
        normalized = url.rstrip("/").removesuffix(".git")
        for trusted in self.trusted_git_sources:
            prefix = trusted.rstrip("/")
            if normalized.startswith(prefix):
                return True
        return False

    def is_trusted_registry(self, image: str) -> bool:
        if not image:
            return False
        for trusted in self.trusted_registries:
            if image.startswith(trusted):
                return True
        return False

    def should_run_check(self, check_id: str) -> bool:
        return check_id not in self.skip_checks


def load_config(config_path: str | Path | None = None) -> ScannerConfig:
    if config_path is None:
        return ScannerConfig()

    path = Path(config_path)
    if not path.exists():
        return ScannerConfig()

    yaml = YAML(typ="safe")
    with open(path) as f:
        data = yaml.load(f) or {}

    kwargs: dict[str, Any] = {}
    if "trusted_git_sources" in data:
        kwargs["trusted_git_sources"] = data["trusted_git_sources"]
    if "trusted_registries" in data:
        kwargs["trusted_registries"] = data["trusted_registries"]
    if "skip_checks" in data:
        kwargs["skip_checks"] = data["skip_checks"]
    if "min_severity" in data:
        kwargs["min_severity"] = data["min_severity"]
    if "known_safe_secret_workspaces" in data:
        kwargs["known_safe_secret_workspaces"] = data["known_safe_secret_workspaces"]
    if "security_task_patterns" in data:
        kwargs["security_task_patterns"] = data["security_task_patterns"]
    if "shared_namespaces" in data:
        kwargs["shared_namespaces"] = data["shared_namespaces"]

    return ScannerConfig(**kwargs)
