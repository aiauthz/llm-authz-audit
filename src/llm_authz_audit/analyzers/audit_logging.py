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

            content_lines = file_entry.content.splitlines()

            # Check if file has any logging at all
            if any(li in file_entry.content for li in _LOG_INDICATORS):
                continue

            for call_name in _LLM_CALL_NAMES:
                for call in find_function_calls(tree, call_name):
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
