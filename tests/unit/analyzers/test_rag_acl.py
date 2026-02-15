"""Tests for RAGACLAnalyzer."""

from llm_authz_audit.analyzers.rag_acl import RAGACLAnalyzer


class TestRAGACLAnalyzer:
    def setup_method(self):
        self.analyzer = RAGACLAnalyzer()

    def test_detects_retriever_without_filter(self, make_scan_context):
        ctx = make_scan_context({
            "rag.py": '''
from langchain.vectorstores import Chroma

vectorstore = Chroma()
retriever = vectorstore.as_retriever()
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "RAG001"

    def test_suppresses_retriever_with_filter(self, make_scan_context):
        ctx = make_scan_context({
            "rag.py": '''
from langchain.vectorstores import Chroma

vectorstore = Chroma()
retriever = vectorstore.as_retriever(search_kwargs={"filter": {"user_id": uid}})
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_detects_query_engine_without_acl(self, make_scan_context):
        ctx = make_scan_context({
            "rag.py": '''
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex([])
engine = index.as_query_engine()
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "RAG002"

    def test_suppresses_query_engine_with_filter(self, make_scan_context):
        ctx = make_scan_context({
            "rag.py": '''
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex([])
engine = index.as_query_engine(filters=metadata_filter)
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_langchain(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'from langchain.vectorstores import Chroma\n'
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_framework(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
