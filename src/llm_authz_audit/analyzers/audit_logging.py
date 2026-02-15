"""AL*: Missing LLM interaction logging."""

from __future__ import annotations

import ast

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import find_function_calls, has_import

_LLM_CALL_NAMES = [
    "ChatOpenAI", "ChatAnthropic", "OpenAI", "Anthropic",
    "create", "chat.completions.create", "messages.create",
    "completions.create",
]

_LOG_INDICATORS = {
    "logging", "logger", "log.", "audit", "print(",
    "structlog", "loguru",
}

_PROXIMITY = 5  # lines before/after to check for logging


@register_analyzer
class AuditLoggingAnalyzer(BaseAnalyzer):
    name = "AuditLoggingAnalyzer"
    description = "Detects LLM API calls without surrounding logging for audit trails."

    def should_run(self, context: ScanContext) -> bool:
        for f in context.python_files():
            tree = f.ast_tree
            if tree and (
                has_import(tree, "openai")
                or has_import(tree, "anthropic")
                or has_import(tree, "langchain")
            ):
                return True
        return False

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.python_files():
            tree = file_entry.ast_tree
            if tree is None:
                continue
            if not (
                has_import(tree, "openai")
                or has_import(tree, "anthropic")
                or has_import(tree, "langchain")
            ):
                continue

            content = file_entry.content
            content_lines = content.splitlines()

            for call_name in _LLM_CALL_NAMES:
                for call in find_function_calls(tree, call_name):
                    # Check 1: logging within ±5 lines
                    if self._has_logging_near(content_lines, call.lineno):
                        continue

                    # Check 2: call is in a try/except with logging in except handler
                    if self._is_in_try_with_logging(tree, call.lineno, content):
                        continue

                    # Check 3: enclosing function has logging statements
                    enclosing = self._find_enclosing_function(tree, call.lineno)
                    if enclosing and self._function_has_logging(enclosing, content):
                        continue

                    snippet = content_lines[call.lineno - 1].strip() if call.lineno <= len(content_lines) else ""
                    findings.append(Finding(
                        rule_id="AL001",
                        title="LLM API call without logging",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        file_path=file_entry.relative_path,
                        line_number=call.lineno,
                        snippet=snippet,
                        description=f"LLM call '{call_name}' without surrounding logging for audit trail.",
                        remediation="Add logging around LLM API calls for audit purposes.",
                        analyzer=self.name,
                        owasp_llm="LLM09",
                    ))
        return findings

    def _has_logging_near(self, lines: list[str], lineno: int) -> bool:
        start = max(0, lineno - 1 - _PROXIMITY)
        end = min(len(lines), lineno + _PROXIMITY)
        for i in range(start, end):
            if any(ind in lines[i] for ind in _LOG_INDICATORS):
                return True
        return False

    def _find_enclosing_function(
        self, tree: ast.Module, lineno: int
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= lineno <= node.end_lineno:  # type: ignore[operator]
                    if best is None or node.lineno > best.lineno:
                        best = node
        return best

    def _function_has_logging(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, content: str
    ) -> bool:
        source = ast.get_source_segment(content, func)
        if source is None:
            return False
        return any(ind in source for ind in _LOG_INDICATORS)

    def _is_in_try_with_logging(self, tree: ast.Module, lineno: int, content: str) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                # Check if the call is in the try body
                try_start = node.lineno
                try_end = max(
                    (n.end_lineno or n.lineno for n in node.body),
                    default=try_start,
                )
                if try_start <= lineno <= try_end:
                    # Check if any handler has logging
                    for handler in node.handlers:
                        handler_source = ast.get_source_segment(content, handler)
                        if handler_source and any(ind in handler_source for ind in _LOG_INDICATORS):
                            return True
        return False
