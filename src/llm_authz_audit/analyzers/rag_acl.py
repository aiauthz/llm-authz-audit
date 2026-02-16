"""RAG*: Retrieval without document ACLs."""

from __future__ import annotations


from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.parsers.python_ast import find_function_calls, has_import

_ACL_INDICATORS = {
    "filter", "metadata_filter", "where_filter", "user_id",
    "doc_ids", "node_postprocessor", "search_kwargs",
}


@register_analyzer
class RAGACLAnalyzer(BaseAnalyzer):
    name = "RAGACLAnalyzer"
    description = "Detects vector store retrievals without document-level access controls."

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

            # Check .as_retriever() calls (LangChain)
            for call in find_function_calls(tree, "as_retriever"):
                if self._has_acl_in_call(call, content_lines):
                    continue
                snippet = content_lines[call.lineno - 1].strip() if call.lineno <= len(content_lines) else ""
                findings.append(Finding(
                    rule_id="RAG001",
                    title="Retriever without document ACLs",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file_path=file_entry.relative_path,
                    line_number=call.lineno,
                    snippet=snippet,
                    description="Retriever created without metadata filters for document-level access control.",
                    remediation="Add search_kwargs with filter: store.as_retriever(search_kwargs={'filter': {'user_id': uid}}).",
                    analyzer=self.name,
                    owasp_llm="LLM06",
                ))

            # Check .as_query_engine() calls (LlamaIndex)
            for call in find_function_calls(tree, "as_query_engine"):
                if self._has_acl_in_call(call, content_lines):
                    continue
                snippet = content_lines[call.lineno - 1].strip() if call.lineno <= len(content_lines) else ""
                findings.append(Finding(
                    rule_id="RAG002",
                    title="Query engine without document ACLs",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file_path=file_entry.relative_path,
                    line_number=call.lineno,
                    snippet=snippet,
                    description="Query engine created without document-level access controls.",
                    remediation="Add metadata filters or node postprocessors for access control.",
                    analyzer=self.name,
                    owasp_llm="LLM06",
                ))
        return findings

    def _has_acl_in_call(self, call, content_lines: list[str]) -> bool:
        # Check keyword args
        for key in call.keyword_args:
            if any(acl in key for acl in _ACL_INDICATORS):
                return True
        # Check surrounding context
        start = max(0, call.lineno - 3)
        end = min(len(content_lines), call.lineno + 3)
        context = "\n".join(content_lines[start:end])
        return any(acl in context for acl in _ACL_INDICATORS)
