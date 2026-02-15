"""Tests for OutputFilteringAnalyzer."""

from llm_authz_audit.analyzers.output_filtering import OutputFilteringAnalyzer


class TestOutputFilteringAnalyzer:
    def setup_method(self):
        self.analyzer = OutputFilteringAnalyzer()

    def test_detects_unfiltered_output(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
answer = response.content
return answer
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "OF001"

    def test_suppresses_with_filtering(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
answer = response.content
filtered = sanitize(answer)
return filtered
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
