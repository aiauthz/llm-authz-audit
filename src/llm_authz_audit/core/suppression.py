"""Suppression loading and matching."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from llm_authz_audit.core.finding import Finding


@dataclass
class Suppression:
    rule_id: str | None
    file_pattern: str | None
    reason: str

    def matches(self, finding: Finding) -> bool:
        if self.rule_id and self.rule_id != finding.rule_id:
            return False
        if self.file_pattern and not fnmatch(finding.file_path, self.file_pattern):
            return False
        return True


class SuppressionLoader:
    @staticmethod
    def load(path: Path) -> list[Suppression]:
        if not path.exists():
            return []
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "suppressions" not in data:
            return []
        result: list[Suppression] = []
        for entry in data["suppressions"]:
            rule_id = entry.get("rule_id")
            file_pattern = entry.get("file_pattern")
            reason = entry.get("reason", "")
            if not rule_id and not file_pattern:
                continue
            if not reason:
                continue
            result.append(Suppression(rule_id=rule_id, file_pattern=file_pattern, reason=reason))
        return result


def apply_suppressions(findings: list[Finding], suppressions: list[Suppression]) -> list[Finding]:
    return [f for f in findings if not any(s.matches(f) for s in suppressions)]
