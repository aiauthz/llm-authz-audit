"""Tests for SessionIsolationAnalyzer."""

from llm_authz_audit.analyzers.session_isolation import SessionIsolationAnalyzer


class TestSessionIsolationAnalyzer:
    def setup_method(self):
        self.analyzer = SessionIsolationAnalyzer()

    def test_detects_shared_memory(self, make_scan_context):
        ctx = make_scan_context({
            "chain.py": '''
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory()
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "SI001"

    def test_suppresses_scoped_memory(self, make_scan_context):
        ctx = make_scan_context({
            "chain.py": '''
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory(memory_key=f"history_{user_id}")
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_detects_llamaindex_memory(self, make_scan_context):
        ctx = make_scan_context({
            "chat.py": '''
from llama_index.core.memory import ChatMemoryBuffer

memory = ChatMemoryBuffer.from_defaults()
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "SI002"

    def test_suppresses_scoped_llamaindex_memory(self, make_scan_context):
        ctx = make_scan_context({
            "chat.py": '''
from llama_index.core.memory import ChatMemoryBuffer

memory = ChatMemoryBuffer.from_defaults(chat_store_key=session_id)
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_langchain(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'from langchain.memory import ConversationBufferMemory\n'
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_framework(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
