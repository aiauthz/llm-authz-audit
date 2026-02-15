"""TR*: LangChain/LlamaIndex tools without RBAC."""

from __future__ import annotations

import ast

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import (
    find_decorated_functions,
    find_function_calls,
    has_import,
)

_DESTRUCTIVE_NAMES = {
    "delete", "drop", "remove", "execute", "admin", "destroy",
    "truncate", "kill", "write", "update", "modify", "create",
}

_AUTH_INDICATORS = {
    "permission", "authorize", "auth_check", "rbac", "role_check",
    "allowed_tools", "check_access", "verify_permission",
}


@register_analyzer
class ToolRBACAnalyzer(BaseAnalyzer):
    name = "ToolRBACAnalyzer"
    description = "Detects LangChain/LlamaIndex tools without RBAC or permission checks."

    def should_run(self, context: ScanContext) -> bool:
        for f in context.python_files():
            tree = f.ast_tree
            if tree and (has_import(tree, "langchain") or has_import(tree, "llama_index")):
                return True
        return False

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.python_files():
            tree = file_entry.ast_tree
            if tree is None:
                continue
            content_lines = file_entry.content.splitlines()

            # Check LangChain @tool decorators
            if has_import(tree, "langchain"):
                findings.extend(
                    self._check_langchain_tools(tree, file_entry.relative_path, content_lines)
                )

            # Check LlamaIndex FunctionTool
            if has_import(tree, "llama_index"):
                findings.extend(
                    self._check_llamaindex_tools(tree, file_entry.relative_path, content_lines)
                )
        return findings

    def _check_langchain_tools(
        self, tree: ast.Module, file_path: str, content_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        decorated_funcs = find_decorated_functions(tree, "tool")
        for func_name, node, lineno in decorated_funcs:
            if self._has_auth_in_body(node, content_lines):
                continue
            severity = Severity.CRITICAL if self._is_destructive(func_name) else Severity.HIGH
            rule_id = "TR002" if self._is_destructive(func_name) else "TR001"
            snippet = content_lines[lineno - 1].strip() if lineno <= len(content_lines) else ""
            findings.append(Finding(
                rule_id=rule_id,
                title=f"LangChain tool '{func_name}' without RBAC",
                severity=severity,
                confidence=Confidence.MEDIUM,
                file_path=file_path,
                line_number=lineno,
                snippet=snippet,
                description=f"Tool '{func_name}' has no permission or authorization checks.",
                remediation="Add permission checks before tool execution.",
                analyzer=self.name,
                owasp_llm="LLM06",
            ))
        return findings

    def _check_llamaindex_tools(
        self, tree: ast.Module, file_path: str, content_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        calls = find_function_calls(tree, "from_defaults")
        for call in calls:
            if "FunctionTool" not in call.func_name:
                continue
            # Check surrounding context for auth
            start = max(0, call.lineno - 5)
            end = min(len(content_lines), call.lineno + 5)
            context_block = "\n".join(content_lines[start:end])
            if any(auth in context_block for auth in _AUTH_INDICATORS):
                continue
            snippet = content_lines[call.lineno - 1].strip() if call.lineno <= len(content_lines) else ""
            findings.append(Finding(
                rule_id="TR003",
                title="LlamaIndex FunctionTool without RBAC",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file_path=file_path,
                line_number=call.lineno,
                snippet=snippet,
                description="FunctionTool created without access control checks.",
                remediation="Implement tool-level RBAC before registering tools.",
                analyzer=self.name,
                owasp_llm="LLM06",
            ))
        return findings

    def _is_destructive(self, name: str) -> bool:
        name_lower = name.lower()
        return any(d in name_lower for d in _DESTRUCTIVE_NAMES)

    def _has_auth_in_body(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, content_lines: list[str]
    ) -> bool:
        start = node.lineno - 1
        end = node.end_lineno or (start + 10)
        body_text = "\n".join(content_lines[start:end])
        return any(auth in body_text for auth in _AUTH_INDICATORS)
