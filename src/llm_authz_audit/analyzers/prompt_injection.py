"""PI*: Prompt injection detection."""

from __future__ import annotations

import ast
import re

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import (
    find_fstring_variables,
    get_function_defs,
    has_import,
)

_LLM_MODULES = ("openai", "anthropic", "langchain", "llama_index")

_USER_INPUT_NAMES = {
    "user_input", "query", "message", "prompt", "question",
    "user_message", "user_query", "user_prompt", "input_text",
    "request", "body", "data",
}

# Narrower set for PI003 — excludes ambiguous names like 'prompt' that
# are commonly used for the prompt variable itself, not user input.
_PI003_USER_INPUT_NAMES = {
    "user_input", "query", "message", "question",
    "user_message", "user_query", "user_prompt", "input_text",
    "request", "body", "data",
}

_PROMPT_VAR_NAMES = {"prompt", "template", "instruction", "messages", "system_prompt"}

_LLM_CALL_PATTERNS = re.compile(
    r"(openai|anthropic|chat|completion|generate|llm|chain|invoke|create|send_message)",
    re.IGNORECASE,
)

_SANITIZATION_INDICATORS = {
    "sanitize", "escape", "delimiter", "validate", "bleach",
    "markupsafe", "clean_input", "strip_tags", "html.escape",
    "```", "<input>", "</input>", "<user>", "</user>",
}


@register_analyzer
class PromptInjectionAnalyzer(BaseAnalyzer):
    name = "PromptInjectionAnalyzer"
    description = "Detects potential prompt injection vulnerabilities (LLM01)."

    def should_run(self, context: ScanContext) -> bool:
        for f in context.python_files():
            tree = f.ast_tree
            if tree:
                for mod in _LLM_MODULES:
                    if has_import(tree, mod):
                        return True
        return False

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file_entry in context.python_files():
            tree = file_entry.ast_tree
            if tree is None:
                continue
            if not any(has_import(tree, mod) for mod in _LLM_MODULES):
                continue

            content = file_entry.content
            if self._has_sanitization(content):
                continue

            findings.extend(self._check_pi001(file_entry, tree, content))
            findings.extend(self._check_pi002(file_entry, tree, content))
            findings.extend(self._check_pi003(file_entry, tree, content))
        return findings

    def _has_sanitization(self, content: str) -> bool:
        content_lower = content.lower()
        return any(ind in content_lower for ind in _SANITIZATION_INDICATORS)

    def _check_pi001(self, file_entry, tree: ast.Module, content: str) -> list[Finding]:
        """Unsanitized user input in LLM prompt via f-string or .format()."""
        findings: list[Finding] = []
        lines = content.splitlines()

        # Check f-strings with user-input variable names
        fstring_vars = find_fstring_variables(tree)
        for var_name, lineno in fstring_vars:
            base_name = var_name.split(".")[-1].lower()
            if base_name not in _USER_INPUT_NAMES:
                continue
            # Check if near LLM call context (±10 lines)
            context_start = max(0, lineno - 11)
            context_end = min(len(lines), lineno + 10)
            context_text = "\n".join(lines[context_start:context_end])
            if not _LLM_CALL_PATTERNS.search(context_text):
                continue
            findings.append(Finding(
                rule_id="PI001",
                title="Unsanitized user input in LLM prompt",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path=file_entry.relative_path,
                line_number=lineno,
                snippet=lines[lineno - 1].strip() if lineno <= len(lines) else "",
                description="User input variable is directly interpolated into an LLM prompt via f-string without sanitization.",
                remediation="Sanitize user input before interpolation, or use structured prompt templates with input delimiters.",
                analyzer=self.name,
                owasp_llm="LLM01",
            ))

        # Check .format() with user-input variable names
        for lineno, line in enumerate(lines, start=1):
            if ".format(" not in line:
                continue
            format_match = re.search(r"\.format\(([^)]*)\)", line)
            if not format_match:
                continue
            args_text = format_match.group(1)
            for user_var in _USER_INPUT_NAMES:
                if user_var in args_text:
                    context_start = max(0, lineno - 11)
                    context_end = min(len(lines), lineno + 10)
                    context_text = "\n".join(lines[context_start:context_end])
                    if not _LLM_CALL_PATTERNS.search(context_text):
                        continue
                    findings.append(Finding(
                        rule_id="PI001",
                        title="Unsanitized user input in LLM prompt",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        file_path=file_entry.relative_path,
                        line_number=lineno,
                        snippet=line.strip(),
                        description="User input variable is directly interpolated into an LLM prompt via .format() without sanitization.",
                        remediation="Sanitize user input before interpolation, or use structured prompt templates with input delimiters.",
                        analyzer=self.name,
                        owasp_llm="LLM01",
                    ))
                    break

        return findings

    def _check_pi002(self, file_entry, tree: ast.Module, content: str) -> list[Finding]:
        """Direct string concatenation in LLM prompt."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Check: prompt = "..." + data
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.lower() in _PROMPT_VAR_NAMES:
                        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                            findings.append(Finding(
                                rule_id="PI002",
                                title="Direct string concatenation in LLM prompt",
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                file_path=file_entry.relative_path,
                                line_number=node.lineno,
                                snippet=content.splitlines()[node.lineno - 1].strip() if node.lineno <= len(content.splitlines()) else "",
                                description="Prompt variable is constructed via string concatenation, which may allow injection.",
                                remediation="Use parameterized prompt templates instead of string concatenation.",
                                analyzer=self.name,
                                owasp_llm="LLM01",
                            ))
            # Check: prompt += extra
            if isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and node.target.id.lower() in _PROMPT_VAR_NAMES:
                    if isinstance(node.op, ast.Add):
                        findings.append(Finding(
                            rule_id="PI002",
                            title="Direct string concatenation in LLM prompt",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=file_entry.relative_path,
                            line_number=node.lineno,
                            snippet=content.splitlines()[node.lineno - 1].strip() if node.lineno <= len(content.splitlines()) else "",
                            description="Prompt variable is extended via += concatenation, which may allow injection.",
                            remediation="Use parameterized prompt templates instead of string concatenation.",
                            analyzer=self.name,
                            owasp_llm="LLM01",
                        ))

        return findings

    def _check_pi003(self, file_entry, tree: ast.Module, content: str) -> list[Finding]:
        """Missing prompt/input delimiter."""
        findings: list[Finding] = []

        for func_node in get_function_defs(tree):
            func_source = ast.get_source_segment(content, func_node)
            if func_source is None:
                continue
            func_lower = func_source.lower()

            has_user_input = any(name in func_lower for name in _PI003_USER_INPUT_NAMES)
            has_llm_call = bool(_LLM_CALL_PATTERNS.search(func_lower))

            if not (has_user_input and has_llm_call):
                continue

            # Check for delimiter indicators
            has_delimiter = any(
                ind in func_source
                for ind in ("```", "<input>", "</input>", "<user>", "</user>",
                            "delimiter", "---", "###")
            )
            if has_delimiter:
                continue

            findings.append(Finding(
                rule_id="PI003",
                title="Missing prompt/input delimiter",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                file_path=file_entry.relative_path,
                line_number=func_node.lineno,
                snippet=f"def {func_node.name}(...):",
                description="Function combines user input with LLM calls but lacks input delimiters to separate instructions from data.",
                remediation="Use clear delimiters (e.g., ```...```, XML tags) to separate user input from system instructions.",
                analyzer=self.name,
                owasp_llm="LLM01",
            ))

        return findings
