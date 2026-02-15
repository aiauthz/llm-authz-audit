"""Tests for InputValidationAnalyzer."""

from llm_authz_audit.analyzers.input_validation import InputValidationAnalyzer


class TestInputValidationAnalyzer:
    def setup_method(self):
        self.analyzer = InputValidationAnalyzer()

    def test_detects_unvalidated_input(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    prompt = data["message"]
    response = llm.generate(prompt)
    return response
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "IV001"

    def test_suppresses_with_validation(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from flask import Flask, request
from pydantic import BaseModel

app = Flask(__name__)

class ChatInput(BaseModel):
    message: str

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    validated = ChatInput(**data)
    return "ok"
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_flask(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'from flask import Flask\napp = Flask(__name__)\n'
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_framework(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
