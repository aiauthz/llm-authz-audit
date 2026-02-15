"""Tests for JSEndpointAnalyzer."""

import pytest

from llm_authz_audit.analyzers.js_endpoints import JSEndpointAnalyzer


@pytest.fixture
def analyzer():
    return JSEndpointAnalyzer()


class TestShouldRun:
    def test_true_for_js(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.js": "const x = 1;\n"})
        assert analyzer.should_run(ctx)

    def test_true_for_ts(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.ts": "const x = 1;\n"})
        assert analyzer.should_run(ctx)

    def test_true_for_tsx(self, analyzer, make_scan_context):
        ctx = make_scan_context({"App.tsx": "const x = 1;\n"})
        assert analyzer.should_run(ctx)

    def test_false_for_python_only(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.py": "x = 1\n"})
        assert not analyzer.should_run(ctx)


class TestAnalyze:
    def test_detects_express_post_with_llm(self, analyzer, make_scan_context):
        code = '''\
const express = require("express");
const OpenAI = require("openai");

const app = express();

app.post("/chat", async (req, res) => {
    const openai = new OpenAI();
    const response = await openai.chat.completions.create({ model: "gpt-4" });
    res.json(response);
});
'''
        ctx = make_scan_context({"app.js": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EP003"
        assert findings[0].confidence.value == "low"

    def test_detects_router_get_with_llm(self, analyzer, make_scan_context):
        code = '''\
const router = require("express").Router();
const { Anthropic } = require("anthropic");

router.get("/completion", async (req, res) => {
    const client = new Anthropic();
    res.json(await client.messages.create({}));
});
'''
        ctx = make_scan_context({"routes.ts": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) >= 1

    def test_suppressed_with_passport(self, analyzer, make_scan_context):
        code = '''\
const express = require("express");
const passport = require("passport");
const OpenAI = require("openai");

const app = express();

app.post("/chat", passport.authenticate("jwt"), async (req, res) => {
    const openai = new OpenAI();
    res.json(await openai.chat.completions.create({}));
});
'''
        ctx = make_scan_context({"app.js": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_suppressed_with_jwt_verify(self, analyzer, make_scan_context):
        code = '''\
const express = require("express");
const jwt = require("jsonwebtoken");
const OpenAI = require("openai");

const app = express();

app.post("/chat", async (req, res) => {
    jwt.verify(req.headers.authorization, secret);
    const openai = new OpenAI();
    res.json(await openai.chat.completions.create({}));
});
'''
        ctx = make_scan_context({"app.ts": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_no_findings_without_llm(self, analyzer, make_scan_context):
        code = '''\
const express = require("express");
const app = express();
app.post("/users", (req, res) => { res.json({}); });
'''
        ctx = make_scan_context({"app.js": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_python_files_ignored(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.py": 'app.post("/chat")\nimport openai\n'})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_multiple_routes(self, analyzer, make_scan_context):
        code = '''\
const express = require("express");
const OpenAI = require("openai");
const app = express();

app.post("/chat", (req, res) => {});
app.get("/completions", (req, res) => {});
'''
        ctx = make_scan_context({"app.js": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 2
