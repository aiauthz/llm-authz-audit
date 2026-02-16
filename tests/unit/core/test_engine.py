"""Tests for ScanEngine."""


from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.engine import ScanEngine
from llm_authz_audit.core.finding import Severity


class TestScanEngine:
    def test_scan_empty_dir(self, tmp_path):
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()
        assert result.files_scanned == 0
        assert result.exit_code == 0
        assert result.findings == []

    def test_scan_detects_hardcoded_key(self, tmp_path):
        app_py = tmp_path / "app.py"
        app_py.write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()
        assert len(result.findings) > 0
        assert any(f.rule_id == "SEC001" for f in result.findings)

    def test_scan_exit_code_on_high(self, tmp_path):
        app_py = tmp_path / "app.py"
        app_py.write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path, fail_on=Severity.HIGH)
        engine = ScanEngine(config)
        result = engine.scan()
        # SEC001 is critical, which is >= high
        assert result.exit_code == 1

    def test_scan_exit_code_zero_below_threshold(self, tmp_path):
        app_py = tmp_path / "app.py"
        app_py.write_text('x = 1\n')
        config = ToolConfig(target_path=tmp_path, fail_on=Severity.HIGH)
        engine = ScanEngine(config)
        result = engine.scan()
        assert result.exit_code == 0

    def test_scan_with_exclude(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        (tmp_path / "safe.py").write_text('x = 1\n')
        config = ToolConfig(target_path=tmp_path, exclude_patterns=["app.py"])
        engine = ScanEngine(config)
        result = engine.scan()
        assert not any(f.file_path == "app.py" for f in result.findings)

    def test_scan_deduplicates(self, tmp_path):
        app_py = tmp_path / "app.py"
        app_py.write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()
        keys = [f.unique_key for f in result.findings]
        assert len(keys) == len(set(keys))

    def test_scan_with_enabled_analyzers(self, tmp_path):
        (tmp_path / "app.py").write_text('x = 1\n')
        config = ToolConfig(
            target_path=tmp_path,
            enabled_analyzers=["SecretsAnalyzer"],
        )
        engine = ScanEngine(config)
        result = engine.scan()
        assert "SecretsAnalyzer" in result.analyzers_run
        assert all(a not in result.analyzers_run for a in ["EndpointAnalyzer", "ToolRBACAnalyzer"])

    def test_analyzers_property(self, tmp_path):
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        assert len(engine.analyzers) > 0

    def test_summary(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()
        summary = result.summary
        assert isinstance(summary, dict)
        assert "critical" in summary
