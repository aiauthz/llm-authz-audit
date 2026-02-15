"""Tests for MCPPermissionAnalyzer."""

from llm_authz_audit.analyzers.mcp_permissions import MCPPermissionAnalyzer


class TestMCPPermissionAnalyzer:
    def setup_method(self):
        self.analyzer = MCPPermissionAnalyzer()

    def test_detects_unauthenticated_server(self, make_scan_context):
        ctx = make_scan_context({
            "mcp.json": '''{
  "mcpServers": {
    "myserver": {
      "url": "http://localhost:8080",
      "env": {}
    }
  }
}'''
        })
        findings = self.analyzer.analyze(ctx)
        mcp002 = [f for f in findings if f.rule_id == "MCP002"]
        assert len(mcp002) == 1

    def test_suppresses_authenticated_server(self, make_scan_context):
        ctx = make_scan_context({
            "mcp.json": '''{
  "mcpServers": {
    "myserver": {
      "url": "http://localhost:8080",
      "headers": {"Authorization": "Bearer token"}
    }
  }
}'''
        })
        findings = self.analyzer.analyze(ctx)
        mcp002 = [f for f in findings if f.rule_id == "MCP002"]
        assert len(mcp002) == 0

    def test_detects_wildcard_tools(self, make_scan_context):
        ctx = make_scan_context({
            "mcp.json": '''{
  "mcpServers": {
    "myserver": {
      "tools": ["*"]
    }
  }
}'''
        })
        findings = self.analyzer.analyze(ctx)
        mcp003 = [f for f in findings if f.rule_id == "MCP003"]
        assert len(mcp003) >= 1

    def test_should_run_mcp_json(self, make_scan_context):
        ctx = make_scan_context({"mcp.json": "{}"})
        assert self.analyzer.should_run(ctx)

    def test_should_run_claude_desktop_config(self, make_scan_context):
        ctx = make_scan_context({"claude_desktop_config.json": "{}"})
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_mcp(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
