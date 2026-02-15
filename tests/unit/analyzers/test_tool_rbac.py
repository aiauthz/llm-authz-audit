"""Tests for ToolRBACAnalyzer."""

from llm_authz_audit.analyzers.tool_rbac import ToolRBACAnalyzer


class TestToolRBACAnalyzer:
    def setup_method(self):
        self.analyzer = ToolRBACAnalyzer()

    def test_detects_langchain_tool_without_rbac(self, make_scan_context):
        ctx = make_scan_context({
            "tools.py": '''
from langchain.tools import tool

@tool
def search_web(query: str) -> str:
    """Search the web."""
    return "results"
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TR001"

    def test_detects_destructive_tool(self, make_scan_context):
        ctx = make_scan_context({
            "tools.py": '''
from langchain.tools import tool

@tool
def delete_user(user_id: str) -> str:
    """Delete a user."""
    return "deleted"
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TR002"
        assert findings[0].severity.value == "critical"

    def test_suppresses_with_permission_check(self, make_scan_context):
        ctx = make_scan_context({
            "tools.py": '''
from langchain.tools import tool

@tool
def search_web(query: str) -> str:
    """Search the web."""
    permission("search")
    return "results"
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_detects_llamaindex_tool(self, make_scan_context):
        ctx = make_scan_context({
            "tools.py": '''
from llama_index.core.tools import FunctionTool

def my_func():
    return "hello"

tool = FunctionTool.from_defaults(fn=my_func)
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TR003"

    def test_should_run_langchain(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''from langchain.tools import tool\n'''
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_framework(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
