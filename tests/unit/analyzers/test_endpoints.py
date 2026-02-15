"""Tests for EndpointAnalyzer."""

from llm_authz_audit.analyzers.endpoints import EndpointAnalyzer


class TestEndpointAnalyzer:
    def setup_method(self):
        self.analyzer = EndpointAnalyzer()

    def test_detects_unauth_chat_endpoint(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/chat")
async def chat(message: str):
    return {"response": "hello"}
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "EP001"

    def test_ignores_auth_endpoint(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from fastapi import FastAPI, Depends
app = FastAPI()

def get_current_user():
    pass

@app.post("/chat")
async def chat(message: str, user=Depends(get_current_user)):
    return {"response": "hello"}
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_ignores_non_llm_endpoint(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_fastapi(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from fastapi import FastAPI
app = FastAPI()
'''
        })
        assert self.analyzer.should_run(ctx)

    def test_should_run_flask(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from flask import Flask
app = Flask(__name__)
'''
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_framework(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'print("hello")'
        })
        assert not self.analyzer.should_run(ctx)

    def test_detects_completions_endpoint(self, make_scan_context):
        ctx = make_scan_context({
            "api.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/v1/completions")
async def completions(prompt: str):
    return {"text": "response"}
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1

    def test_flask_login_required_suppresses(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from flask import Flask
app = Flask(__name__)

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    return "ok"
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_detects_generate_endpoint(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/generate")
async def generate(prompt: str):
    return {"text": "generated"}
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
