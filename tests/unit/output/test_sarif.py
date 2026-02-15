"""Tests for SARIF output formatter."""

import json

from llm_authz_audit.core.engine import ScanResult
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.output.sarif import SARIFFormatter


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="SEC001",
        title="Hardcoded API key",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_number=10,
        snippet="key = sk-proj-abc123",
        description="API key hardcoded in source.",
        remediation="Use environment variables.",
        analyzer="SecretsAnalyzer",
        owasp_llm="LLM06",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        files_scanned=1,
        analyzers_run=["SecretsAnalyzer"],
        analyzers_skipped=[],
        exit_code=1 if findings else 0,
    )


class TestSARIFFormatter:
    def test_valid_json(self):
        result = _make_result([_make_finding()])
        output = SARIFFormatter().format(result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_version(self):
        result = _make_result([_make_finding()])
        data = json.loads(SARIFFormatter().format(result))
        assert data["version"] == "2.1.0"

    def test_has_runs(self):
        result = _make_result([_make_finding()])
        data = json.loads(SARIFFormatter().format(result))
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "llm-authz-audit"

    def test_severity_critical_maps_to_error(self):
        result = _make_result([_make_finding(severity=Severity.CRITICAL)])
        data = json.loads(SARIFFormatter().format(result))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_severity_high_maps_to_error(self):
        result = _make_result([_make_finding(severity=Severity.HIGH)])
        data = json.loads(SARIFFormatter().format(result))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_severity_medium_maps_to_warning(self):
        result = _make_result([_make_finding(severity=Severity.MEDIUM)])
        data = json.loads(SARIFFormatter().format(result))
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_severity_low_maps_to_note(self):
        result = _make_result([_make_finding(severity=Severity.LOW)])
        data = json.loads(SARIFFormatter().format(result))
        assert data["runs"][0]["results"][0]["level"] == "note"

    def test_rule_dedup(self):
        findings = [
            _make_finding(rule_id="SEC001", line_number=1),
            _make_finding(rule_id="SEC001", line_number=20),
            _make_finding(rule_id="EP001", title="Missing auth", line_number=5),
        ]
        result = _make_result(findings)
        data = json.loads(SARIFFormatter().format(result))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2  # SEC001 and EP001

    def test_rule_index_reference(self):
        findings = [
            _make_finding(rule_id="SEC001", line_number=1),
            _make_finding(rule_id="EP001", title="Missing auth", line_number=5),
        ]
        result = _make_result(findings)
        data = json.loads(SARIFFormatter().format(result))
        results = data["runs"][0]["results"]
        assert results[0]["ruleIndex"] == 0
        assert results[1]["ruleIndex"] == 1

    def test_location_with_line(self):
        result = _make_result([_make_finding(file_path="src/app.py", line_number=42)])
        data = json.loads(SARIFFormatter().format(result))
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/app.py"
        assert loc["region"]["startLine"] == 42

    def test_location_without_line(self):
        result = _make_result([_make_finding(line_number=None)])
        data = json.loads(SARIFFormatter().format(result))
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "region" not in loc

    def test_empty_findings(self):
        result = _make_result([])
        data = json.loads(SARIFFormatter().format(result))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_owasp_in_properties(self):
        result = _make_result([_make_finding(owasp_llm="LLM06")])
        data = json.loads(SARIFFormatter().format(result))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["owasp_llm"] == "LLM06"

    def test_remediation_in_help(self):
        result = _make_result([_make_finding(remediation="Use env vars.")])
        data = json.loads(SARIFFormatter().format(result))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["help"]["text"] == "Use env vars."
