"""OF*: Missing PII/output filtering."""

from __future__ import annotations

import re

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import has_import

_OUTPUT_PATTERNS = [
    r"\.content\b",
    r"\.text\b",
    r"response\[.message.\]",
    r"completion\.choices",
    r"\.generations\b",
]

_FILTER_INDICATORS = {
    "filter", "sanitize", "redact", "pii", "mask",
    "guard", "moderate", "content_filter", "guardrail",
}


@register_analyzer
class OutputFilteringAnalyzer(BaseAnalyzer):
    name = "OutputFilteringAnalyzer"
    description = "Detects LLM output used without content filtering or PII redaction."

    def should_run(self, context: ScanContext) -> bool:
        for f in context.python_files():
            tree = f.ast_tree
            if tree and (
                has_import(tree, "openai")
                or has_import(tree, "anthropic")
                or has_import(tree, "langchain")
                or has_import(tree, "llama_index")
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
                or has_import(tree, "llama_index")
            ):
                continue

            content = file_entry.content
            # Check if file has any filtering
            if any(fi in content for fi in _FILTER_INDICATORS):
                continue

            content_lines = content.splitlines()
            for lineno, line in enumerate(content_lines, start=1):
                for pattern in _OUTPUT_PATTERNS:
                    if re.search(pattern, line):
                        # Only flag if it looks like LLM output access
                        if any(kw in line for kw in ("response", "completion", "result", "output", "answer", "reply")):
                            findings.append(Finding(
                                rule_id="OF001",
                                title="LLM output without filtering",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.LOW,
                                file_path=file_entry.relative_path,
                                line_number=lineno,
                                snippet=line.strip(),
                                description="LLM output used without content filtering or PII redaction.",
                                remediation="Add output filtering for PII, sensitive data, and harmful content.",
                                analyzer=self.name,
                                owasp_llm="LLM02",
                            ))
                            break  # one finding per line
        return findings
