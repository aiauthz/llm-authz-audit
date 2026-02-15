"""Tests for SecretsAnalyzer."""

from llm_authz_audit.analyzers.secrets import SecretsAnalyzer


class TestSecretsAnalyzer:
    def setup_method(self):
        self.analyzer = SecretsAnalyzer()

    def test_detects_openai_key(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"'
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "SEC001"
        assert findings[0].severity.value == "critical"

    def test_suppresses_environ(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'OPENAI_KEY = os.environ["OPENAI_API_KEY"]'
        })
        findings = self.analyzer.analyze(ctx)
        sec001 = [f for f in findings if f.rule_id == "SEC001"]
        assert len(sec001) == 0

    def test_suppresses_getenv(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'key = os.getenv("OPENAI_API_KEY", "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890")'
        })
        findings = self.analyzer.analyze(ctx)
        sec001 = [f for f in findings if f.rule_id == "SEC001"]
        assert len(sec001) == 0

    def test_detects_anthropic_key(self, make_scan_context):
        ctx = make_scan_context({
            "config.py": 'API_KEY = "sk-ant-abcdefghijklmnopqrstuvwxyz12"'
        })
        findings = self.analyzer.analyze(ctx)
        assert any(f.rule_id == "SEC002" for f in findings)

    def test_detects_huggingface_token(self, make_scan_context):
        ctx = make_scan_context({
            "config.yaml": 'token: hf_abcdefghijklmnopqrstuvwxyz12'
        })
        findings = self.analyzer.analyze(ctx)
        assert any(f.rule_id == "SEC003" for f in findings)

    def test_detects_aws_key(self, make_scan_context):
        ctx = make_scan_context({
            "config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        })
        findings = self.analyzer.analyze(ctx)
        assert any(f.rule_id == "SEC004" for f in findings)

    def test_detects_generic_api_key(self, make_scan_context):
        ctx = make_scan_context({
            "settings.py": 'api_key = "abcdefghijklmnop1234567890"'
        })
        findings = self.analyzer.analyze(ctx)
        assert any(f.rule_id == "SEC005" for f in findings)

    def test_clean_file_no_findings(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''import os\napi_key = os.environ["API_KEY"]\n'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_with_files(self, make_scan_context):
        ctx = make_scan_context({"app.py": "x = 1"})
        assert self.analyzer.should_run(ctx)

    def test_should_run_no_files(self, make_scan_context):
        ctx = make_scan_context({})
        assert not self.analyzer.should_run(ctx)

    def test_nosec_suppression(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # nosec'
        })
        findings = self.analyzer.analyze(ctx)
        sec001 = [f for f in findings if f.rule_id == "SEC001"]
        assert len(sec001) == 0
