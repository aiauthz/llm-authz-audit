"""Tests for ToolConfig."""

from pathlib import Path

from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.finding import Severity


class TestToolConfig:
    def test_defaults(self):
        cfg = ToolConfig()
        assert cfg.output_format == "console"
        assert cfg.fail_on == Severity.HIGH
        assert cfg.verbose is False
        assert cfg.ai_enabled is False

    def test_from_dict(self):
        cfg = ToolConfig.from_dict({
            "target_path": "/tmp/test",
            "fail_on": "critical",
            "verbose": True,
        })
        assert cfg.target_path == Path("/tmp/test")
        assert cfg.fail_on == Severity.CRITICAL
        assert cfg.verbose is True

    def test_from_dict_ignores_unknown_keys(self):
        cfg = ToolConfig.from_dict({"unknown_key": "value"})
        assert cfg.output_format == "console"

    def test_exclude_patterns(self):
        cfg = ToolConfig(exclude_patterns=["*.test.py", "vendor/*"])
        assert len(cfg.exclude_patterns) == 2
