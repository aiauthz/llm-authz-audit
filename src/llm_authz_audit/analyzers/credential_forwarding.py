"""CF*: Secrets in prompt templates/chains."""

from __future__ import annotations

import ast
import re

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import find_fstring_variables, has_import

_SENSITIVE_NAMES = {
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "credential", "private_key",
    "access_key", "secret_key", "auth_token",
}


@register_analyzer
class CredentialForwardingAnalyzer(BaseAnalyzer):
    name = "CredentialForwardingAnalyzer"
    description = "Detects credentials being forwarded to LLM via prompt templates."

    def should_run(self, context: ScanContext) -> bool:
        return len(context.python_files()) > 0

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.python_files():
            tree = file_entry.ast_tree
            if tree is None:
                continue
            content_lines = file_entry.content.splitlines()

            # Check f-strings for sensitive variables
            for var_name, lineno in find_fstring_variables(tree):
                if self._is_sensitive(var_name):
                    line = content_lines[lineno - 1] if lineno <= len(content_lines) else ""
                    # Check if this is in a prompt-like context
                    if self._is_prompt_context(content_lines, lineno):
                        if any(s in line for s in ("mask", "redact", "# nosec")):
                            continue
                        findings.append(Finding(
                            rule_id="CF001",
                            title="Credential in prompt template",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.MEDIUM,
                            file_path=file_entry.relative_path,
                            line_number=lineno,
                            snippet=line.strip(),
                            description=f"Sensitive variable '{var_name}' used in what appears to be a prompt template.",
                            remediation="Never include credentials in prompt templates. Use sanitized references.",
                            analyzer=self.name,
                            owasp_llm="LLM06",
                        ))

            # Check .format() calls with sensitive vars
            for lineno, line in enumerate(content_lines, start=1):
                if ".format(" in line:
                    for name in _SENSITIVE_NAMES:
                        if re.search(rf'\b{name}\b', line, re.IGNORECASE):
                            if self._is_prompt_context(content_lines, lineno):
                                if any(s in line for s in ("mask", "redact", "# nosec")):
                                    continue
                                findings.append(Finding(
                                    rule_id="CF001",
                                    title="Credential in prompt template",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.MEDIUM,
                                    file_path=file_entry.relative_path,
                                    line_number=lineno,
                                    snippet=line.strip(),
                                    description=f"Sensitive value '{name}' in .format() call in prompt context.",
                                    remediation="Never include credentials in prompt templates.",
                                    analyzer=self.name,
                                    owasp_llm="LLM06",
                                ))
                                break
        return findings

    def _is_sensitive(self, name: str) -> bool:
        name_lower = name.lower()
        return any(s in name_lower for s in _SENSITIVE_NAMES)

    def _is_prompt_context(self, lines: list[str], lineno: int) -> bool:
        start = max(0, lineno - 5)
        end = min(len(lines), lineno + 5)
        context = "\n".join(lines[start:end]).lower()
        prompt_indicators = (
            "prompt", "template", "system_message", "human_message",
            "user_message", "llm", "chat", "completion", "instruction",
        )
        return any(pi in context for pi in prompt_indicators)
