"""Tests for CredentialForwardingAnalyzer."""

from llm_authz_audit.analyzers.credential_forwarding import CredentialForwardingAnalyzer


class TestCredentialForwardingAnalyzer:
    def setup_method(self):
        self.analyzer = CredentialForwardingAnalyzer()

    def test_detects_password_in_fstring_prompt(self, make_scan_context):
        ctx = make_scan_context({
            "chain.py": '''
prompt_template = f"User password is {password}, please verify"
llm_response = chat(prompt_template)
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "CF001"

    def test_detects_secret_in_format(self, make_scan_context):
        ctx = make_scan_context({
            "chain.py": '''
prompt = "The api_key is {secret}".format(secret=api_secret)
completion = llm.chat(prompt)
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "CF001"

    def test_no_false_positive_safe_code(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
name = "Alice"
greeting = f"Hello, {name}!"
print(greeting)
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_with_python_files(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'x = 1'})
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_python_files(self, make_scan_context):
        ctx = make_scan_context({"config.yaml": "key: val"})
        assert not self.analyzer.should_run(ctx)
