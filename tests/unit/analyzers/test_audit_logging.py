"""Tests for AuditLoggingAnalyzer."""

from llm_authz_audit.analyzers.audit_logging import AuditLoggingAnalyzer


class TestAuditLoggingAnalyzer:
    def setup_method(self):
        self.analyzer = AuditLoggingAnalyzer()

    def test_detects_llm_call_without_logging(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''\
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1
        assert findings[0].rule_id == "AL001"

    def test_suppresses_with_logging_near(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''\
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)
client = OpenAI()
logger.info("Making LLM call")
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_detects_when_logging_far_away(self, make_scan_context):
        # Logging is 20+ lines away from the LLM call
        ctx = make_scan_context({
            "app.py": '''\
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)
logger.info("starting up")
x = 1
x = 2
x = 3
x = 4
x = 5
x = 6
x = 7
x = 8
x = 9
x = 10
x = 11
x = 12
x = 13
x = 14
x = 15

def bare_call():
    client = OpenAI()
    response = client.chat.completions.create(model="gpt-4", messages=[])
    return response
'''
        })
        findings = self.analyzer.analyze(ctx)
        # The call is far from any logging and enclosing function has no logging
        assert len(findings) >= 1

    def test_suppresses_with_try_except_logging(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''\
from openai import OpenAI
import logging

def call_llm():
    client = OpenAI()
    try:
        response = client.chat.completions.create(model="gpt-4", messages=[])
    except Exception as e:
        logging.error(f"LLM call failed: {e}")
        raise
    return response
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_suppresses_with_enclosing_function_logging(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''\
from openai import OpenAI
import logging

def call_llm(prompt):
    logger = logging.getLogger(__name__)
    logger.info(f"Calling LLM with prompt length {len(prompt)}")
    client = OpenAI()
    # ... lots of setup ...
    x = 1
    y = 2
    z = 3
    a = 4
    b = 5
    c = 6
    d = 7
    e = 8
    response = client.chat.completions.create(model="gpt-4", messages=[])
    return response
'''
        })
        findings = self.analyzer.analyze(ctx)
        # Logging is in the same function but more than 5 lines away
        # The enclosing function check should catch this
        assert len(findings) == 0

    def test_no_logging_at_all(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''\
from openai import OpenAI

def call():
    client = OpenAI()
    return client.chat.completions.create(model="gpt-4", messages=[])
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) >= 1

    def test_structlog_suppresses(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '''\
import structlog
from openai import OpenAI

log = structlog.get_logger()
log.info("calling llm")
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        })
        findings = self.analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_should_run_openai(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'from openai import OpenAI\n'
        })
        assert self.analyzer.should_run(ctx)

    def test_should_not_run_no_llm_lib(self, make_scan_context):
        ctx = make_scan_context({"app.py": 'print("hello")'})
        assert not self.analyzer.should_run(ctx)
