"""Integration tests for the full scan pipeline."""

from pathlib import Path

from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.engine import ScanEngine
from llm_authz_audit.core.finding import Severity
from llm_authz_audit.output.formatter import FormatterFactory


class TestEnginePipeline:
    def test_full_pipeline_vulnerable_project(self, tmp_path):
        # Create a mini vulnerable project
        (tmp_path / "app.py").write_text('''
from fastapi import FastAPI
app = FastAPI()

API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"

@app.post("/chat")
async def chat(message: str):
    return {"response": "hello"}
''')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()

        assert result.files_scanned >= 1
        assert len(result.findings) >= 2  # At least secrets + endpoint
        assert result.exit_code == 1

        # Verify findings are sorted by severity
        for i in range(len(result.findings) - 1):
            assert result.findings[i].severity >= result.findings[i + 1].severity

    def test_full_pipeline_clean_project(self, tmp_path):
        (tmp_path / "app.py").write_text('''
import os
api_key = os.environ["API_KEY"]
print("clean project")
''')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()

        assert result.exit_code == 0
        assert len(result.findings) == 0

    def test_json_output(self, tmp_path):
        import json

        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()

        formatter = FormatterFactory.get("json")
        output = formatter.format(result)

        # Should be valid JSON
        data = json.loads(output)
        assert "findings" in data
        assert "summary" in data
        assert data["summary"]["total_findings"] > 0

    def test_console_output(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)
        result = engine.scan()

        formatter = FormatterFactory.get("console")
        output = formatter.format(result)
        assert "SEC001" in output
        assert "finding" in output.lower()

    def test_fail_on_critical_only(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path, fail_on=Severity.CRITICAL)
        engine = ScanEngine(config)
        result = engine.scan()
        # SEC001 is critical
        assert result.exit_code == 1

    def test_fail_on_low_catches_everything(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')
        config = ToolConfig(target_path=tmp_path, fail_on=Severity.LOW)
        engine = ScanEngine(config)
        result = engine.scan()
        assert result.exit_code == 1
