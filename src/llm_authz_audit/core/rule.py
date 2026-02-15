"""Rule dataclass and YAML rule loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from llm_authz_audit.core.finding import Severity


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    pattern: str
    file_types: list[str] = field(default_factory=lambda: ["*.py"])
    suppress_if: list[str] = field(default_factory=list)
    owasp_llm: str | None = None
    remediation: str = ""
    description: str = ""
    analyzer: str = ""


class RuleLoader:
    """Load rules from YAML files."""

    BUILTIN_DIR = Path(__file__).parent.parent / "rules" / "builtin"

    @classmethod
    def load_file(cls, path: Path) -> list[Rule]:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "rules" not in data:
            return []
        rules = []
        for entry in data["rules"]:
            rules.append(Rule(
                id=entry["id"],
                title=entry["title"],
                severity=Severity(entry["severity"]),
                pattern=entry["pattern"],
                file_types=entry.get("file_types", ["*.py"]),
                suppress_if=entry.get("suppress_if", []),
                owasp_llm=entry.get("owasp_llm"),
                remediation=entry.get("remediation", ""),
                description=entry.get("description", ""),
                analyzer=entry.get("analyzer", ""),
            ))
        return rules

    @classmethod
    def load_builtin(cls, filename: str) -> list[Rule]:
        path = cls.BUILTIN_DIR / filename
        if not path.exists():
            return []
        return cls.load_file(path)

    @classmethod
    def load_all_builtin(cls) -> list[Rule]:
        if not cls.BUILTIN_DIR.is_dir():
            return []
        rules: list[Rule] = []
        for yaml_file in sorted(cls.BUILTIN_DIR.glob("*.yaml")):
            rules.extend(cls.load_file(yaml_file))
        return rules

    @classmethod
    def load_directory(cls, path: Path) -> list[Rule]:
        if not path.is_dir():
            return []
        rules: list[Rule] = []
        for yaml_file in sorted(path.glob("*.yaml")):
            rules.extend(cls.load_file(yaml_file))
        return rules
