"""MCP*: Over-permissioned MCP server configurations."""

from __future__ import annotations

import re

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import FileEntry, ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.config_parser import parse_config_file

_MCP_CONFIG_NAMES = {
    "mcp.json", "claude_desktop_config.json",
    "mcp_config.json", "mcp_config.yaml", "mcp_config.yml",
}


@register_analyzer
class MCPPermissionAnalyzer(BaseAnalyzer):
    name = "MCPPermissionAnalyzer"
    description = "Detects over-permissioned MCP server configurations."

    def should_run(self, context: ScanContext) -> bool:
        for f in context.config_files():
            if f.path.name in _MCP_CONFIG_NAMES:
                return True
            if "mcp" in f.relative_path.lower():
                return True
        return False

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.config_files():
            if file_entry.path.name not in _MCP_CONFIG_NAMES and "mcp" not in file_entry.relative_path.lower():
                continue
            findings.extend(self._check_config(file_entry))
        return findings

    def _check_config(self, file_entry: FileEntry) -> list[Finding]:
        findings: list[Finding] = []
        data = parse_config_file(file_entry.path)
        if data is None or not isinstance(data, dict):
            return findings

        content_lines = file_entry.content.splitlines()

        # Check for root filesystem access
        content_str = file_entry.content
        for lineno, line in enumerate(content_lines, start=1):
            # Root path access
            if re.search(r'["\']/$|["\']/', line) and "args" in content_str:
                if any(kw in line.lower() for kw in ("restricted", "sandboxed", "read_only")):
                    continue
                findings.append(Finding(
                    rule_id="MCP001",
                    title="MCP server with root filesystem access",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    file_path=file_entry.relative_path,
                    line_number=lineno,
                    snippet=line.strip(),
                    description="MCP server configured with root filesystem access.",
                    remediation="Restrict MCP server to specific directories.",
                    analyzer=self.name,
                    owasp_llm="LLM06",
                ))

        # Check for HTTP without auth
        self._check_servers_auth(data, file_entry, findings, content_lines)

        # Check wildcard tool grants
        self._check_wildcard_tools(data, file_entry, findings, content_lines)

        return findings

    def _check_servers_auth(
        self, data: dict, file_entry: FileEntry, findings: list[Finding], content_lines: list[str]
    ) -> None:
        servers = data.get("mcpServers", data.get("servers", {}))
        if not isinstance(servers, dict):
            return
        for name, config in servers.items():
            if not isinstance(config, dict):
                continue
            url = config.get("url", config.get("endpoint", ""))
            if isinstance(url, str) and ("http://" in url or "localhost" in url):
                headers = config.get("headers", {})
                env = config.get("env", {})
                has_auth = any(
                    "auth" in k.lower() or "token" in k.lower() or "bearer" in k.lower()
                    for k in list(headers.keys()) + list(env.keys())
                ) if isinstance(headers, dict) and isinstance(env, dict) else False
                if not has_auth:
                    lineno = self._find_line(content_lines, name)
                    findings.append(Finding(
                        rule_id="MCP002",
                        title=f"MCP server '{name}' without authentication",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file_path=file_entry.relative_path,
                        line_number=lineno,
                        snippet=f'"{name}": url={url}',
                        description=f"MCP server '{name}' connects via HTTP without authentication.",
                        remediation="Add authentication headers to MCP server connections.",
                        analyzer=self.name,
                        owasp_llm="LLM06",
                    ))

    def _check_wildcard_tools(
        self, data: dict, file_entry: FileEntry, findings: list[Finding], content_lines: list[str]
    ) -> None:
        for lineno, line in enumerate(content_lines, start=1):
            if re.search(r'(?:tools|permissions).*\*', line):
                if any(kw in line.lower() for kw in ("restricted", "deny", "block")):
                    continue
                findings.append(Finding(
                    rule_id="MCP003",
                    title="MCP wildcard tool grants",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file_path=file_entry.relative_path,
                    line_number=lineno,
                    snippet=line.strip(),
                    description="MCP configuration grants wildcard access to tools.",
                    remediation="Use explicit tool grants instead of wildcards.",
                    analyzer=self.name,
                    owasp_llm="LLM06",
                ))

    def _find_line(self, lines: list[str], text: str) -> int | None:
        for i, line in enumerate(lines, start=1):
            if text in line:
                return i
        return None
