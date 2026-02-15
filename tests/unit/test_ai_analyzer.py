"""Tests for AIAnalyzer with mocked LLM responses."""

from __future__ import annotations

from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.engine import ScanEngine, ScanResult
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.llm.ai_analyzer import AIAnalyzer


class MockLLMProvider:
    """Mock LLM provider for testing."""

    def __init__(self, response: str = "") -> None:
        self.response = response
        self.calls: list[str] = []

    def complete(self, prompt: str, system: str = "") -> str:
        self.calls.append(prompt)
        return self.response


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="SEC001",
        title="Test finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_number=10,
        snippet='key = "sk-proj-abc123..."',
        description="Hardcoded API key",
        remediation="Use env vars",
        analyzer="SecretsAnalyzer",
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


class TestAIAnalyzer:
    def test_true_positive_kept(self, tmp_path):
        mock_llm = MockLLMProvider(
            response=(
                "VERDICT: TRUE_POSITIVE\n"
                "CONFIDENCE: HIGH\n"
                "EXPLANATION: This is a real hardcoded API key.\n"
                "REMEDIATION: Use environment variables."
            )
        )
        (tmp_path / "app.py").write_text('key = "sk-proj-abc123456789012345678901234567"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)

        finding = _make_finding()
        result = _make_result([finding])

        analyzer = AIAnalyzer(llm_client=mock_llm)
        refined = analyzer.refine(result, engine)

        assert len(refined.findings) == 1
        assert refined.findings[0].confidence == Confidence.AI_VERIFIED
        assert "ai_explanation" in refined.findings[0].metadata

    def test_false_positive_removed(self, tmp_path):
        mock_llm = MockLLMProvider(
            response=(
                "VERDICT: FALSE_POSITIVE\n"
                "CONFIDENCE: HIGH\n"
                "EXPLANATION: This is a test fixture, not a real key.\n"
                "REMEDIATION: N/A"
            )
        )
        (tmp_path / "app.py").write_text('key = "sk-proj-testkey123456789012345678901"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)

        finding = _make_finding()
        result = _make_result([finding])

        analyzer = AIAnalyzer(llm_client=mock_llm)
        refined = analyzer.refine(result, engine)

        assert len(refined.findings) == 0

    def test_llm_error_keeps_original(self, tmp_path):
        class FailingProvider:
            def complete(self, prompt: str, system: str = "") -> str:
                raise RuntimeError("API error")

        (tmp_path / "app.py").write_text('key = "sk-proj-abc123456789012345678901234567"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)

        finding = _make_finding()
        result = _make_result([finding])

        analyzer = AIAnalyzer(llm_client=FailingProvider())
        refined = analyzer.refine(result, engine)

        assert len(refined.findings) == 1
        assert refined.findings[0].confidence == Confidence.HIGH  # unchanged

    def test_multiple_findings(self, tmp_path):
        responses = iter([
            "VERDICT: TRUE_POSITIVE\nCONFIDENCE: HIGH\nEXPLANATION: Real issue.\nREMEDIATION: Fix it.",
            "VERDICT: FALSE_POSITIVE\nCONFIDENCE: HIGH\nEXPLANATION: Not real.\nREMEDIATION: N/A",
        ])

        class MultiMock:
            def complete(self, prompt: str, system: str = "") -> str:
                return next(responses)

        (tmp_path / "app.py").write_text('key = "test"\n')
        config = ToolConfig(target_path=tmp_path)
        engine = ScanEngine(config)

        findings = [
            _make_finding(rule_id="SEC001", line_number=1),
            _make_finding(rule_id="SEC002", line_number=2),
        ]
        result = _make_result(findings)

        analyzer = AIAnalyzer(llm_client=MultiMock())
        refined = analyzer.refine(result, engine)

        assert len(refined.findings) == 1
        assert refined.findings[0].rule_id == "SEC001"

    def test_parse_response(self):
        analyzer = AIAnalyzer(llm_client=MockLLMProvider())
        verdict, confidence, explanation = analyzer._parse_response(
            "VERDICT: TRUE_POSITIVE\nCONFIDENCE: HIGH\nEXPLANATION: Real issue.\nREMEDIATION: Fix."
        )
        assert verdict == "TRUE_POSITIVE"
        assert confidence == "HIGH"
        assert "Real issue" in explanation

    def test_parse_response_defaults(self):
        analyzer = AIAnalyzer(llm_client=MockLLMProvider())
        verdict, confidence, explanation = analyzer._parse_response("Something unexpected")
        assert verdict == "TRUE_POSITIVE"
        assert confidence == "MEDIUM"
