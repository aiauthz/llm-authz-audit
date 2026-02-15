"""Unit tests for the ASCII art intro banner."""

from pathlib import Path

from rich.console import Console

from llm_authz_audit import __version__
from llm_authz_audit.output.banner import print_banner


class TestPrintBanner:
    def _render(self, **kwargs) -> str:
        console = Console(file=None, force_terminal=True, width=120)
        defaults = dict(target=Path("/tmp/project"), analyzers_loaded=11, rules_loaded=23)
        defaults.update(kwargs)
        with console.capture() as cap:
            print_banner(console, **defaults)
        return cap.get()

    def test_contains_ascii_art(self):
        output = self._render()
        assert "╦" in output
        assert "╩" in output

    def test_contains_tool_name(self):
        output = self._render()
        assert "authz-audit" in output

    def test_contains_version(self):
        output = self._render()
        assert __version__ in output

    def test_contains_target_path(self):
        output = self._render(target=Path("/my/scan/dir"))
        assert "/my/scan/dir" in output

    def test_contains_analyzer_count(self):
        output = self._render(analyzers_loaded=5)
        assert "5 loaded" in output

    def test_contains_rule_count(self):
        output = self._render(rules_loaded=42)
        assert "42 loaded" in output

    def test_contains_url(self):
        output = self._render()
        assert "github.com/aiauthz/llm-authz-audit" in output

    def test_contains_fail_on(self):
        output = self._render(fail_on="critical")
        assert "critical" in output

    def test_default_fail_on(self):
        output = self._render()
        assert "high" in output

    def test_shows_exclude_patterns(self):
        output = self._render(exclude_patterns=["tests/*", "*.md"])
        assert "tests/*" in output
        assert "*.md" in output

    def test_no_exclude_when_empty(self):
        output = self._render()
        assert "Exclude:" not in output

    def test_shows_config_file(self):
        output = self._render(config_file=Path("/my/.llm-audit.yaml"))
        assert ".llm-audit.yaml" in output

    def test_no_config_when_none(self):
        output = self._render()
        assert "Config:" not in output

    def test_shows_min_confidence(self):
        output = self._render(min_confidence="medium")
        assert "medium" in output
        assert "Min conf:" in output

    def test_no_min_confidence_when_none(self):
        output = self._render()
        assert "Min conf:" not in output

    def test_shows_suppress_file(self):
        output = self._render(suppress_file=Path("/my/suppress.yaml"))
        assert "suppress.yaml" in output
        assert "Suppress:" in output

    def test_no_suppress_when_none(self):
        output = self._render()
        assert "Suppress:" not in output
