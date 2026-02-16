"""SI*: Shared memory without tenant boundaries."""

from __future__ import annotations


from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import find_class_instantiations, find_function_calls, has_import

_MEMORY_CLASSES = [
    "ConversationBufferMemory",
    "ConversationSummaryMemory",
    "ConversationBufferWindowMemory",
    "ChatMessageHistory",
    "ConversationTokenBufferMemory",
]

_SCOPE_INDICATORS = {
    "user_id", "session_id", "tenant", "user_key",
    "namespace", "chat_store_key", "memory_key",
}


@register_analyzer
class SessionIsolationAnalyzer(BaseAnalyzer):
    name = "SessionIsolationAnalyzer"
    description = "Detects shared conversation memory without user/session scoping."

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

            # Check LangChain memory classes
            for cls_name in _MEMORY_CLASSES:
                for call in find_class_instantiations(tree, cls_name):
                    if self._has_scope(call, content_lines):
                        continue
                    snippet = content_lines[call.lineno - 1].strip() if call.lineno <= len(content_lines) else ""
                    findings.append(Finding(
                        rule_id="SI001",
                        title=f"Shared {cls_name} without user scoping",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file_path=file_entry.relative_path,
                        line_number=call.lineno,
                        snippet=snippet,
                        description=f"{cls_name} created without user/session scoping — memory may be shared across users.",
                        remediation=f"Scope memory per user: {cls_name}(memory_key=f'history_{{user_id}}').",
                        analyzer=self.name,
                        owasp_llm="LLM06",
                    ))

            # Check LlamaIndex ChatMemoryBuffer
            for call in find_function_calls(tree, "from_defaults"):
                if "ChatMemoryBuffer" not in call.func_name:
                    continue
                if self._has_scope(call, content_lines):
                    continue
                snippet = content_lines[call.lineno - 1].strip() if call.lineno <= len(content_lines) else ""
                findings.append(Finding(
                    rule_id="SI002",
                    title="LlamaIndex ChatMemoryBuffer without user scoping",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file_path=file_entry.relative_path,
                    line_number=call.lineno,
                    snippet=snippet,
                    description="Chat memory buffer may be shared across users.",
                    remediation="Scope with chat_store_key parameter.",
                    analyzer=self.name,
                    owasp_llm="LLM06",
                ))
        return findings

    def _has_scope(self, call, content_lines: list[str]) -> bool:
        # Check keyword args
        for key in call.keyword_args:
            if any(s in key for s in _SCOPE_INDICATORS):
                return True
        # Check surrounding context
        start = max(0, call.lineno - 3)
        end = min(len(content_lines), call.lineno + 3)
        context = "\n".join(content_lines[start:end])
        return any(s in context for s in _SCOPE_INDICATORS)
