"""SEC*: Hardcoded API keys, tokens, and passwords."""

from __future__ import annotations

import re
from fnmatch import fnmatch

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.analyzers.base import BaseAnalyzer
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.core.rule import RuleLoader


@register_analyzer
class SecretsAnalyzer(BaseAnalyzer):
    name = "SecretsAnalyzer"
    description = "Detects hardcoded API keys, tokens, and passwords in source and config files."

    def __init__(self) -> None:
        self.rules = RuleLoader.load_builtin("secrets.yaml")

    def should_run(self, context: ScanContext) -> bool:
        return len(context.files) > 0

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            matching_files = context.files_matching_any(rule.file_types)
            pattern = re.compile(rule.pattern)
            suppress_patterns = [re.compile(s) for s in rule.suppress_if]

            for file_entry in matching_files:
                content = file_entry.content
                for lineno, line in enumerate(content.splitlines(), start=1):
                    if pattern.search(line):
                        if any(sp.search(line) for sp in suppress_patterns):
                            continue
                        findings.append(Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=Confidence.HIGH,
                            file_path=file_entry.relative_path,
                            line_number=lineno,
                            snippet=line.strip(),
                            description=rule.description,
                            remediation=rule.remediation,
                            analyzer=self.name,
                            owasp_llm=rule.owasp_llm,
                        ))
        return findings
