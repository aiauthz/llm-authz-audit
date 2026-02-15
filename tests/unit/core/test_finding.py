"""Tests for Finding, Severity, Confidence."""

from llm_authz_audit.core.finding import Confidence, Finding, Severity


class TestSeverity:
    def test_ordering(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_from_string(self):
        assert Severity("critical") == Severity.CRITICAL
        assert Severity("low") == Severity.LOW

    def test_comparisons(self):
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.LOW <= Severity.HIGH
        assert not Severity.LOW > Severity.HIGH


class TestFinding:
    def _make_finding(self, **overrides) -> Finding:
        defaults = dict(
            rule_id="SEC001",
            title="Test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="app.py",
            line_number=10,
            snippet="sk-proj-abc123",
            description="Hardcoded API key",
            remediation="Use env vars",
            analyzer="SecretsAnalyzer",
        )
        defaults.update(overrides)
        return Finding(**defaults)

    def test_unique_key(self):
        f = self._make_finding()
        assert f.unique_key == ("SEC001", "app.py", 10)

    def test_unique_key_dedup(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.unique_key == f2.unique_key

    def test_to_dict(self):
        f = self._make_finding(owasp_llm="LLM06")
        d = f.to_dict()
        assert d["rule_id"] == "SEC001"
        assert d["severity"] == "high"
        assert d["confidence"] == "high"
        assert d["owasp_llm"] == "LLM06"
        assert isinstance(d["metadata"], dict)

    def test_owasp_llm_default_none(self):
        f = self._make_finding()
        assert f.owasp_llm is None


class TestConfidence:
    def test_ai_verified(self):
        assert Confidence.AI_VERIFIED.value == "ai_verified"
