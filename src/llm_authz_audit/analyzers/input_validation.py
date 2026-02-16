"""IV*: Missing input sanitization."""

from __future__ import annotations

import re

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import has_import

_INPUT_PATTERNS = [
    r"request\.body",
    r"request\.json",
    r"request\.form",
    r"request\.data",
    r"request\.query",
    r"request\.get_json",
    r"request\.args",
]

_VALIDATION_INDICATORS = {
    "validate", "sanitize", "clean", "strip", "escape",
    "max_length", "len(", "pydantic", "BaseModel",
    "Field(", "validator", "Schema",
}


@register_analyzer
class InputValidationAnalyzer(BaseAnalyzer):
    name = "InputValidationAnalyzer"
    description = "Detects user input passed directly to LLM without validation."

    def should_run(self, context: ScanContext) -> bool:
        for f in context.python_files():
            tree = f.ast_tree
            if tree and (has_import(tree, "fastapi") or has_import(tree, "flask")):
                return True
        return False

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.python_files():
            tree = file_entry.ast_tree
            if tree is None:
                continue
            if not (has_import(tree, "fastapi") or has_import(tree, "flask")):
                continue

            content = file_entry.content
            content_lines = content.splitlines()

            # If the file has validation imports/patterns, lower confidence
            has_validation = any(vi in content for vi in _VALIDATION_INDICATORS)

            for lineno, line in enumerate(content_lines, start=1):
                for pattern in _INPUT_PATTERNS:
                    if re.search(pattern, line):
                        # Check surrounding context for LLM usage
                        func_context = self._get_function_context(content_lines, lineno)
                        if not self._has_llm_usage(func_context):
                            continue
                        if has_validation:
                            continue
                        findings.append(Finding(
                            rule_id="IV001",
                            title="User input passed to LLM without validation",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            file_path=file_entry.relative_path,
                            line_number=lineno,
                            snippet=line.strip(),
                            description="User input may be passed directly to LLM without validation or sanitization.",
                            remediation="Validate and sanitize user input before passing to LLM.",
                            analyzer=self.name,
                            owasp_llm="LLM01",
                        ))
                        break
        return findings

    def _get_function_context(self, lines: list[str], lineno: int) -> str:
        start = max(0, lineno - 15)
        end = min(len(lines), lineno + 15)
        return "\n".join(lines[start:end])

    def _has_llm_usage(self, context: str) -> bool:
        llm_indicators = (
            "openai", "anthropic", "llm", "chat", "completion",
            "generate", "prompt", "chain", "agent",
        )
        context_lower = context.lower()
        return any(li in context_lower for li in llm_indicators)
