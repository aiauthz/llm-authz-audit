"""Tests for Rule and RuleLoader."""


import yaml

from llm_authz_audit.core.finding import Severity
from llm_authz_audit.core.rule import Rule, RuleLoader


class TestRule:
    def test_rule_fields(self):
        rule = Rule(
            id="SEC001",
            title="Test rule",
            severity=Severity.HIGH,
            pattern="sk-[a-zA-Z0-9]+",
        )
        assert rule.id == "SEC001"
        assert rule.severity == Severity.HIGH
        assert rule.file_types == ["*.py"]
        assert rule.suppress_if == []

    def test_rule_defaults(self):
        rule = Rule(id="X001", title="T", severity=Severity.LOW, pattern="x")
        assert rule.owasp_llm is None
        assert rule.remediation == ""
        assert rule.analyzer == ""


class TestRuleLoader:
    def test_load_file(self, tmp_path):
        rule_file = tmp_path / "test.yaml"
        data = {
            "rules": [
                {
                    "id": "TEST001",
                    "title": "Test rule",
                    "severity": "high",
                    "pattern": "test_pattern",
                    "file_types": ["*.py"],
                    "remediation": "Fix it",
                }
            ]
        }
        rule_file.write_text(yaml.dump(data))
        rules = RuleLoader.load_file(rule_file)
        assert len(rules) == 1
        assert rules[0].id == "TEST001"
        assert rules[0].severity == Severity.HIGH

    def test_load_empty_file(self, tmp_path):
        rule_file = tmp_path / "empty.yaml"
        rule_file.write_text("")
        rules = RuleLoader.load_file(rule_file)
        assert rules == []

    def test_load_file_no_rules_key(self, tmp_path):
        rule_file = tmp_path / "bad.yaml"
        rule_file.write_text(yaml.dump({"something": "else"}))
        rules = RuleLoader.load_file(rule_file)
        assert rules == []

    def test_load_builtin_secrets(self):
        rules = RuleLoader.load_builtin("secrets.yaml")
        assert len(rules) >= 1
        ids = {r.id for r in rules}
        assert "SEC001" in ids

    def test_load_all_builtin(self):
        rules = RuleLoader.load_all_builtin()
        assert len(rules) >= 1

    def test_load_directory(self, tmp_path):
        for i in range(3):
            data = {
                "rules": [
                    {
                        "id": f"T{i:03d}",
                        "title": f"Rule {i}",
                        "severity": "low",
                        "pattern": f"pattern_{i}",
                    }
                ]
            }
            (tmp_path / f"rules_{i}.yaml").write_text(yaml.dump(data))
        rules = RuleLoader.load_directory(tmp_path)
        assert len(rules) == 3

    def test_load_nonexistent_directory(self, tmp_path):
        rules = RuleLoader.load_directory(tmp_path / "nope")
        assert rules == []

    def test_load_nonexistent_builtin(self):
        rules = RuleLoader.load_builtin("nonexistent.yaml")
        assert rules == []
