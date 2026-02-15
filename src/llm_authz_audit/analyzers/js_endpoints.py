"""EP003: JavaScript/TypeScript endpoint detection."""

from __future__ import annotations

import re

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity

_JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}

_ROUTE_PATTERN = re.compile(
    r"""(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["'](/[^"']*)["']""",
    re.IGNORECASE,
)

_LLM_INDICATORS = re.compile(
    r"(?:openai|anthropic|llm|chat|completion|generate|langchain|ChatOpenAI|gpt|claude)",
    re.IGNORECASE,
)

_AUTH_INDICATORS = {
    "passport", "jwt.verify", "jsonwebtoken", "auth", "bearer",
    "authenticate", "isAuthenticated", "requireAuth", "verifyToken",
    "authorization",
}


@register_analyzer
class JSEndpointAnalyzer(BaseAnalyzer):
    name = "JSEndpointAnalyzer"
    description = "Detects JS/TS API endpoints handling LLM interactions without auth."

    def should_run(self, context: ScanContext) -> bool:
        return any(
            f.path.suffix in _JS_EXTENSIONS
            for f in context.files
        )

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.files:
            if file_entry.path.suffix not in _JS_EXTENSIONS:
                continue

            content = file_entry.content
            if not _LLM_INDICATORS.search(content):
                continue

            # File-level auth check — if any auth indicator, suppress all findings
            content_lower = content.lower()
            if any(ind in content_lower for ind in _AUTH_INDICATORS):
                continue

            lines = content.splitlines()
            for lineno, line in enumerate(lines, start=1):
                match = _ROUTE_PATTERN.search(line)
                if not match:
                    continue
                route_path = match.group(1)
                findings.append(Finding(
                    rule_id="EP003",
                    title="JS/TS LLM endpoint without authentication",
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    file_path=file_entry.relative_path,
                    line_number=lineno,
                    snippet=line.strip(),
                    description=f"Route '{route_path}' in a file with LLM usage has no visible authentication.",
                    remediation="Add authentication middleware (e.g., passport, JWT verification) to LLM-facing endpoints.",
                    analyzer=self.name,
                    owasp_llm="LLM02",
                ))
        return findings
