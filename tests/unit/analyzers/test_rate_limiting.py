"""Tests for RateLimitingAnalyzer."""

from llm_authz_audit.analyzers.rate_limiting import RateLimitingAnalyzer


class TestRateLimitingAnalyzer:
    def setup_method(self):
        self.analyzer = RateLimitingAnalyzer()

    def test_detects_unrated_llm_endpoint(self, make_scan_context):
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
        assert findings[0].rule_id == "RL001"

    def test_suppresses_with_slowapi(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''
from fastapi import FastAPI
from slowapi import Limiter
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)

@app.post("/chat")
async def chat(message: str):
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
            "app.py": 'from fastapi import FastAPI\napp = FastAPI()\n'
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_framework(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
