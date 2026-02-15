"""Pydantic validation for YAML rule files."""

from __future__ import annotations

from pydantic import BaseModel, field_validator


class RuleSchema(BaseModel):
    id: str
    title: str
    severity: str
    pattern: str
    file_types: list[str] = ["*.py"]
    suppress_if: list[str] = []
    owasp_llm: str | None = None
    remediation: str = ""
    description: str = ""
    analyzer: str = ""

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got '{v}'")
        return v.lower()

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not v or len(v) < 3:
            raise ValueError(f"Rule id must be at least 3 characters, got '{v}'")
        return v


class RuleFileSchema(BaseModel):
    rules: list[RuleSchema]


def validate_rule_file(data: dict) -> RuleFileSchema:
    return RuleFileSchema(**data)
