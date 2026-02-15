"""Tool configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from llm_authz_audit.core.finding import Confidence, Severity


@dataclass
class ToolConfig:
    target_path: Path = field(default_factory=lambda: Path("."))
    output_format: str = "console"
    fail_on: Severity = Severity.HIGH
    enabled_analyzers: list[str] | None = None
    exclude_patterns: list[str] = field(default_factory=list)
    suppress_file: Path | None = None
    verbose: bool = False
    ai_enabled: bool = False
    ai_provider: str = "anthropic"
    ai_model: str = "claude-sonnet-4-5-20250929"
    config_file: Path | None = None
    extra_rule_dirs: list[Path] = field(default_factory=list)
    ai_max_findings: int = 20
    diff_ref: str | None = None
    min_confidence: Confidence | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ToolConfig:
        if "fail_on" in data and isinstance(data["fail_on"], str):
            data["fail_on"] = Severity(data["fail_on"])
        if "target_path" in data and isinstance(data["target_path"], str):
            data["target_path"] = Path(data["target_path"])
        if "suppress_file" in data and isinstance(data["suppress_file"], str):
            data["suppress_file"] = Path(data["suppress_file"])
        if "config_file" in data and isinstance(data["config_file"], str):
            data["config_file"] = Path(data["config_file"])
        if "extra_rule_dirs" in data:
            data["extra_rule_dirs"] = [Path(p) for p in data["extra_rule_dirs"]]
        if "min_confidence" in data and isinstance(data["min_confidence"], str):
            data["min_confidence"] = Confidence(data["min_confidence"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
