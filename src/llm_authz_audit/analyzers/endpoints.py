"""EP*: Unauthenticated FastAPI/Flask LLM endpoints."""

from __future__ import annotations

import ast

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import has_import

# Route decorator names indicating endpoints
_ROUTE_DECORATORS = {
    "app.post", "app.get", "app.put", "app.delete", "app.patch",
    "app.route", "router.post", "router.get", "router.put",
    "router.delete", "router.patch", "router.route",
    "api.post", "api.get", "api.put", "api.delete", "api.patch",
}

# LLM-related path keywords
_LLM_PATH_KEYWORDS = {
    "chat", "completion", "completions", "generate", "llm",
    "prompt", "inference", "embed", "embedding", "agent",
    "ask", "query", "predict", "rag", "retrieve",
}

# Auth-related decorator/dependency names
_AUTH_INDICATORS = {
    "Depends", "login_required", "require_auth", "auth_required",
    "requires_auth", "jwt_required", "token_required",
    "get_current_user", "verify_token", "authenticate",
    "permission_required", "permissions_required",
    "HTTPBearer", "OAuth2PasswordBearer", "Security",
}


@register_analyzer
class EndpointAnalyzer(BaseAnalyzer):
    name = "EndpointAnalyzer"
    description = "Detects unauthenticated FastAPI/Flask endpoints serving LLM functionality."

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

            content_lines = file_entry.content.splitlines()
            findings.extend(self._check_endpoints(tree, file_entry.relative_path, content_lines))
        return findings

    def _check_endpoints(
        self, tree: ast.Module, file_path: str, content_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                dec_info = self._parse_route_decorator(dec)
                if dec_info is None:
                    continue
                dec_name, route_path, lineno = dec_info
                if not self._is_llm_endpoint(route_path, node.name):
                    continue
                if self._has_auth(node, tree):
                    continue

                snippet = content_lines[lineno - 1].strip() if lineno <= len(content_lines) else ""
                findings.append(Finding(
                    rule_id="EP001",
                    title="Unauthenticated LLM endpoint",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file_path=file_path,
                    line_number=lineno,
                    snippet=snippet,
                    description=f"Endpoint '{route_path or node.name}' appears to serve LLM functionality without authentication.",
                    remediation="Add authentication dependency: Depends(get_current_user) for FastAPI, or @login_required for Flask.",
                    analyzer=self.name,
                    owasp_llm="LLM06",
                ))
        return findings

    def _parse_route_decorator(self, dec: ast.expr) -> tuple[str, str, int] | None:
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute):
                name = self._get_dotted_name(func)
                if name in _ROUTE_DECORATORS:
                    path = ""
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        path = str(dec.args[0].value)
                    return (name, path, dec.lineno)
        return None

    def _get_dotted_name(self, node: ast.Attribute) -> str:
        parts = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _is_llm_endpoint(self, route_path: str, func_name: str) -> bool:
        combined = f"{route_path} {func_name}".lower()
        return any(kw in combined for kw in _LLM_PATH_KEYWORDS)

    def _has_auth(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.Module) -> bool:
        # Check decorator arguments for auth dependencies
        for dec in func_node.decorator_list:
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "dependencies":
                        dep_src = ast.dump(kw.value)
                        if any(auth in dep_src for auth in _AUTH_INDICATORS):
                            return True

        # Check function parameters for Depends() with auth
        for arg in func_node.args.args:
            if arg.annotation:
                ann_src = ast.dump(arg.annotation)
                if any(auth in ann_src for auth in _AUTH_INDICATORS):
                    return True
            # Check defaults
        for default in func_node.args.defaults:
            if isinstance(default, ast.Call):
                call_name = self._get_call_name(default.func)
                if call_name in _AUTH_INDICATORS:
                    return True
                if call_name == "Depends" and default.args:
                    inner = self._get_call_name(default.args[0])
                    if inner and any(auth in inner for auth in _AUTH_INDICATORS):
                        return True
        for default in func_node.args.kw_defaults:
            if default and isinstance(default, ast.Call):
                call_name = self._get_call_name(default.func)
                if call_name in _AUTH_INDICATORS:
                    return True

        # Check function-level decorators for auth
        for dec in func_node.decorator_list:
            dec_name = None
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_name = self._get_dotted_name(dec)
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_name = self._get_dotted_name(dec.func)
            if dec_name and any(auth in dec_name for auth in _AUTH_INDICATORS):
                return True

        return False

    def _get_call_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_dotted_name(node)
        return None
