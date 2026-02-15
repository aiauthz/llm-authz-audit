"""RL*: Missing rate limits on LLM endpoints."""

from __future__ import annotations

import ast

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import has_import

_RATE_LIMIT_INDICATORS = {
    "slowapi", "limiter", "rate_limit", "throttle",
    "RateLimiter", "fastapi_limiter", "flask_limiter",
}

_LLM_PATH_KEYWORDS = {
    "chat", "completion", "completions", "generate", "llm",
    "prompt", "inference", "embed", "agent",
}


@register_analyzer
class RateLimitingAnalyzer(BaseAnalyzer):
    name = "RateLimitingAnalyzer"
    description = "Detects LLM endpoints without rate limiting middleware."

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

            # Check if the file has any rate limiting imports
            has_rate_limiting = any(
                has_import(tree, rl) for rl in ("slowapi", "fastapi_limiter", "flask_limiter")
            )
            if has_rate_limiting:
                continue

            content_lines = file_entry.content.splitlines()
            content_full = file_entry.content

            # Check if rate limiting appears anywhere in the file
            if any(rl in content_full for rl in _RATE_LIMIT_INDICATORS):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        name = self._get_dotted_name(dec.func)
                        if name and any(name.endswith(f".{m}") for m in ("post", "get", "put", "delete", "patch", "route")):
                            path = ""
                            if dec.args and isinstance(dec.args[0], ast.Constant):
                                path = str(dec.args[0].value)
                            combined = f"{path} {node.name}".lower()
                            if any(kw in combined for kw in _LLM_PATH_KEYWORDS):
                                snippet = content_lines[dec.lineno - 1].strip() if dec.lineno <= len(content_lines) else ""
                                findings.append(Finding(
                                    rule_id="RL001",
                                    title="LLM endpoint without rate limiting",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.MEDIUM,
                                    file_path=file_entry.relative_path,
                                    line_number=dec.lineno,
                                    snippet=snippet,
                                    description=f"Endpoint '{path or node.name}' serves LLM functionality without rate limiting.",
                                    remediation="Add rate limiting with slowapi or fastapi-limiter.",
                                    analyzer=self.name,
                                    owasp_llm="LLM04",
                                ))
        return findings

    def _get_dotted_name(self, node: ast.Attribute) -> str:
        parts = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
