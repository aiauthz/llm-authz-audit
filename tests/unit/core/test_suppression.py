"""Tests for suppression loading and matching."""

from pathlib import Path

import pytest

from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.core.suppression import Suppression, SuppressionLoader, apply_suppressions


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="SEC001",
        title="Test",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="tests/app.py",
        line_number=5,
        snippet="sk-proj-abc",
        description="desc",
        remediation="fix",
        analyzer="SecretsAnalyzer",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestSuppression:
    def test_matches_by_rule_id(self):
        s = Suppression(rule_id="SEC001", file_pattern=None, reason="test")
        assert s.matches(_make_finding(rule_id="SEC001"))
        assert not s.matches(_make_finding(rule_id="EP001"))

    def test_matches_by_file_pattern(self):
        s = Suppression(rule_id=None, file_pattern="tests/*", reason="test fixtures")
        assert s.matches(_make_finding(file_path="tests/app.py"))
        assert not s.matches(_make_finding(file_path="src/app.py"))

    def test_matches_both(self):
        s = Suppression(rule_id="SEC001", file_pattern="tests/*", reason="test")
        assert s.matches(_make_finding(rule_id="SEC001", file_path="tests/app.py"))
        assert not s.matches(_make_finding(rule_id="SEC001", file_path="src/app.py"))
        assert not s.matches(_make_finding(rule_id="EP001", file_path="tests/app.py"))


class TestSuppressionLoader:
    def test_load_valid_file(self, tmp_path):
        yaml_file = tmp_path / "suppress.yaml"
        yaml_file.write_text("""\
suppressions:
  - rule_id: SEC001
    file_pattern: "tests/*"
    reason: "Test fixtures"
  - rule_id: EP001
    reason: "Known endpoint"
""")
        result = SuppressionLoader.load(yaml_file)
        assert len(result) == 2
        assert result[0].rule_id == "SEC001"
        assert result[0].file_pattern == "tests/*"
        assert result[1].rule_id == "EP001"
        assert result[1].file_pattern is None

    def test_load_missing_file(self, tmp_path):
        result = SuppressionLoader.load(tmp_path / "nonexistent.yaml")
        assert result == []

    def test_load_empty_file(self, tmp_path):
        yaml_file = tmp_path / "suppress.yaml"
        yaml_file.write_text("")
        result = SuppressionLoader.load(yaml_file)
        assert result == []

    def test_skips_entries_without_rule_or_pattern(self, tmp_path):
        yaml_file = tmp_path / "suppress.yaml"
        yaml_file.write_text("""\
suppressions:
  - reason: "No rule_id or file_pattern"
""")
        result = SuppressionLoader.load(yaml_file)
        assert result == []

    def test_skips_entries_without_reason(self, tmp_path):
        yaml_file = tmp_path / "suppress.yaml"
        yaml_file.write_text("""\
suppressions:
  - rule_id: SEC001
""")
        result = SuppressionLoader.load(yaml_file)
        assert result == []


class TestApplySuppressions:
    def test_filters_matching(self):
        findings = [_make_finding(rule_id="SEC001"), _make_finding(rule_id="EP001")]
        suppressions = [Suppression(rule_id="SEC001", file_pattern=None, reason="test")]
        result = apply_suppressions(findings, suppressions)
        assert len(result) == 1
        assert result[0].rule_id == "EP001"

    def test_empty_suppressions(self):
        findings = [_make_finding()]
        result = apply_suppressions(findings, [])
        assert len(result) == 1

    def test_all_suppressed(self):
        findings = [_make_finding(rule_id="SEC001")]
        suppressions = [Suppression(rule_id="SEC001", file_pattern=None, reason="test")]
        result = apply_suppressions(findings, suppressions)
        assert result == []
