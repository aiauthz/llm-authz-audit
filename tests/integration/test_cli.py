"""Integration tests for CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from llm_authz_audit.cli import app

runner = CliRunner()


class TestCLIScan:
    def test_scan_vulnerable_dir(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "SEC001" in result.output

    def test_scan_clean_dir(self, tmp_path):
        (tmp_path / "app.py").write_text('import os\nx = os.environ["KEY"]\n')
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_json_format(self, tmp_path):
        import json
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "findings" in data
        assert "summary" in data

    def test_scan_nonexistent_dir(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path / "nonexistent")])
        assert result.exit_code == 2

    def test_scan_verbose(self, tmp_path):
        (tmp_path / "app.py").write_text('x = 1\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "-v"])
        assert "Scanning:" in result.output

    def test_scan_with_exclude(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--exclude", "app.py"])
        assert result.exit_code == 0

    def test_scan_fail_on_critical(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
        assert result.exit_code == 1  # SEC001 is critical

    def test_scan_console_shows_banner(self, tmp_path):
        (tmp_path / "app.py").write_text('x = 1\n')
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert "authz-audit" in result.output
        assert "Analyzers:" in result.output
        assert "Fail on:" in result.output

    def test_scan_json_has_no_banner(self, tmp_path):
        import json
        (tmp_path / "app.py").write_text('x = 1\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_quiet_suppresses_banner(self, tmp_path):
        (tmp_path / "app.py").write_text('x = 1\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
        assert "╦" not in result.output
        assert "Analyzers:" not in result.output
        assert "Fail on:" not in result.output

    def test_scan_banner_shows_exclude(self, tmp_path):
        (tmp_path / "app.py").write_text('x = 1\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--exclude", "tests/*,*.md"])
        assert "Exclude:" in result.output


class TestCLIListAnalyzers:
    def test_list_analyzers(self):
        result = runner.invoke(app, ["list-analyzers"])
        assert result.exit_code == 0
        assert "SecretsAnalyzer" in result.output
        assert "EndpointAnalyzer" in result.output
        assert "ToolRBACAnalyzer" in result.output

    def test_list_analyzers_count(self):
        result = runner.invoke(app, ["list-analyzers"])
        # Should list all 11 analyzers
        expected = [
            "SecretsAnalyzer", "EndpointAnalyzer", "ToolRBACAnalyzer",
            "RAGACLAnalyzer", "MCPPermissionAnalyzer", "SessionIsolationAnalyzer",
            "RateLimitingAnalyzer", "OutputFilteringAnalyzer",
            "CredentialForwardingAnalyzer", "AuditLoggingAnalyzer",
            "InputValidationAnalyzer",
        ]
        for name in expected:
            assert name in result.output


class TestCLIListRules:
    def test_list_rules(self):
        result = runner.invoke(app, ["list-rules"])
        assert result.exit_code == 0
        assert "SEC001" in result.output
        assert "EP001" in result.output

    def test_list_rules_shows_severity(self):
        result = runner.invoke(app, ["list-rules"])
        assert "critical" in result.output
        assert "high" in result.output


class TestCLIInit:
    def test_init(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert (tmp_path / ".llm-audit.yaml").exists()

    def test_init_already_exists(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".llm-audit.yaml").write_text("existing")
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 1
