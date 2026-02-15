"""Tests for AuditLoggingAnalyzer."""

from llm_authz_audit.analyzers.audit_logging import AuditLoggingAnalyzer


class TestAuditLoggingAnalyzer:
    def setup_method(self):
        self.analyzer = AuditLoggingAnalyzer()

    def test_detects_llm_call_without_logging(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "AL001"

    def test_suppresses_with_logging(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)
client = OpenAI()
logger.info("Making LLM call")
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_openai(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'from openai import OpenAI\n'
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_llm_lib(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
