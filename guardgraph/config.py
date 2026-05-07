from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TargetConfig:
    path: str = "tests/test_app"
    language: str = "python"
    framework: str = "fastapi"


@dataclass
class ReportConfig:
    json: str = "guardgraph_report.json"
    markdown: str = "guardgraph_report.md"


@dataclass
class GitHubConfig:
    pr_comment: bool = True


@dataclass
class GuardGraphConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)


SUPPORTED_LANGUAGES = {"python"}
SUPPORTED_FRAMEWORKS = {"fastapi"}


def load_config(config_path: str | Path) -> GuardGraphConfig:
    """Load GuardGraph YAML config.

    The config is intentionally small in the MVP. Unsupported language/framework
    values fail early so CI output is explicit and easy to debug.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"GuardGraph config file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("GuardGraph config must be a YAML mapping/object")

    target_raw = _section(raw, "target")
    report_raw = _section(raw, "report")
    github_raw = _section(raw, "github")

    target = TargetConfig(
        path=str(target_raw.get("path", TargetConfig.path)),
        language=str(target_raw.get("language", TargetConfig.language)).lower(),
        framework=str(target_raw.get("framework", TargetConfig.framework)).lower(),
    )
    report = ReportConfig(
        json=str(report_raw.get("json", ReportConfig.json)),
        markdown=str(report_raw.get("markdown", ReportConfig.markdown)),
    )
    github = GitHubConfig(
        pr_comment=bool(github_raw.get("pr_comment", GitHubConfig.pr_comment)),
    )

    _validate_target(target)
    return GuardGraphConfig(target=target, report=report, github=github)


def default_config() -> GuardGraphConfig:
    return GuardGraphConfig()


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"GuardGraph config section '{name}' must be a mapping/object")
    return value


def _validate_target(target: TargetConfig) -> None:
    if target.language not in SUPPORTED_LANGUAGES:
        supported = ", ".join(sorted(SUPPORTED_LANGUAGES))
        raise ValueError(f"Unsupported language '{target.language}'. Supported: {supported}")
    if target.framework not in SUPPORTED_FRAMEWORKS:
        supported = ", ".join(sorted(SUPPORTED_FRAMEWORKS))
        raise ValueError(f"Unsupported framework '{target.framework}'. Supported: {supported}")
