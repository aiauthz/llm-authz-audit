"""Finding and severity data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self > other


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    AI_VERIFIED = "ai_verified"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_number: int | None
    snippet: str
    description: str
    remediation: str
    analyzer: str
    owasp_llm: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def unique_key(self) -> tuple[str, str, int | None]:
        """Key for deduplication: (rule_id, file_path, line_number)."""
        return (self.rule_id, self.file_path, self.line_number)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
            "analyzer": self.analyzer,
            "owasp_llm": self.owasp_llm,
            "metadata": self.metadata,
        }
