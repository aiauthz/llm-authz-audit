"""Tests for PromptInjectionAnalyzer."""

import pytest

from llm_authz_audit.analyzers.prompt_injection import PromptInjectionAnalyzer


@pytest.fixture
def analyzer():
    return PromptInjectionAnalyzer()


class TestShouldRun:
    def test_true_for_openai(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.py": "import openai\n"})
        assert analyzer.should_run(ctx)

    def test_true_for_anthropic(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.py": "import anthropic\n"})
        assert analyzer.should_run(ctx)

    def test_true_for_langchain(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.py": "from langchain import LLMChain\n"})
        assert analyzer.should_run(ctx)

    def test_false_for_no_llm(self, analyzer, make_scan_context):
        ctx = make_scan_context({"app.py": "import os\n"})
        assert not analyzer.should_run(ctx)


class TestPI001:
    def test_fstring_user_input(self, analyzer, make_scan_context):
        code = '''\
import openai
def chat(user_input):
    prompt = f"Answer: {user_input}"
    openai.ChatCompletion.create(prompt=prompt)
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi001 = [f for f in findings if f.rule_id == "PI001"]
        assert len(pi001) >= 1
        assert pi001[0].severity.value == "critical"
        assert pi001[0].owasp_llm == "LLM01"

    def test_format_with_query(self, analyzer, make_scan_context):
        code = '''\
import openai
def search(query):
    template = "Search for: {}"
    prompt = template.format(query)
    openai.ChatCompletion.create(prompt=prompt)
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi001 = [f for f in findings if f.rule_id == "PI001"]
        assert len(pi001) >= 1

    def test_suppressed_with_sanitize(self, analyzer, make_scan_context):
        code = '''\
import openai
def chat(user_input):
    clean = sanitize(user_input)
    prompt = f"Answer: {clean}"
    openai.ChatCompletion.create(prompt=prompt)
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi001 = [f for f in findings if f.rule_id == "PI001"]
        assert len(pi001) == 0


class TestPI002:
    def test_string_concat_prompt(self, analyzer, make_scan_context):
        code = '''\
import openai
def build():
    prompt = "System: " + user_data
    openai.ChatCompletion.create(prompt=prompt)
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi002 = [f for f in findings if f.rule_id == "PI002"]
        assert len(pi002) >= 1
        assert pi002[0].severity.value == "high"

    def test_augmented_assign(self, analyzer, make_scan_context):
        code = '''\
import openai
def build():
    prompt = "System instruction"
    prompt += extra_data
    openai.ChatCompletion.create(prompt=prompt)
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi002 = [f for f in findings if f.rule_id == "PI002"]
        assert len(pi002) >= 1


class TestPI003:
    def test_missing_delimiter(self, analyzer, make_scan_context):
        code = '''\
import openai
def chat(user_input):
    result = openai.ChatCompletion.create(prompt=user_input)
    return result
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi003 = [f for f in findings if f.rule_id == "PI003"]
        assert len(pi003) >= 1
        assert pi003[0].confidence.value == "low"

    def test_suppressed_with_backtick_delimiter(self, analyzer, make_scan_context):
        code = '''\
import openai
def chat(user_input):
    prompt = f"Analyze:\\n```\\n{user_input}\\n```"
    result = openai.ChatCompletion.create(prompt=prompt)
    return result
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        pi003 = [f for f in findings if f.rule_id == "PI003"]
        assert len(pi003) == 0


class TestCleanCode:
    def test_no_false_positives(self, analyzer, make_scan_context):
        code = '''\
import openai
def safe_call():
    prompt = "Static instruction with no user input"
    return openai.ChatCompletion.create(prompt=prompt)
'''
        ctx = make_scan_context({"app.py": code})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0

    def test_non_python_ignored(self, analyzer, make_scan_context):
        ctx = make_scan_context({"readme.md": "# Prompt injection user_input openai"})
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0
