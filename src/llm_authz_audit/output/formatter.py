"""Base formatter and factory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llm_authz_audit.core.engine import ScanResult


class BaseFormatter(ABC):
    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """Format scan results into a string."""


class FormatterFactory:
    _formatters: dict[str, type[BaseFormatter]] = {}

    @classmethod
    def register(cls, name: str, formatter_cls: type[BaseFormatter]) -> None:
        cls._formatters[name] = formatter_cls

    @classmethod
    def get(cls, name: str) -> BaseFormatter:
        if name not in cls._formatters:
            # Trigger imports
            from llm_authz_audit.output import console, json_output  # noqa: F401
        if name not in cls._formatters:
            raise ValueError(f"Unknown formatter: {name}. Available: {list(cls._formatters.keys())}")
        return cls._formatters[name]()

    @classmethod
    def available(cls) -> list[str]:
        from llm_authz_audit.output import console, json_output  # noqa: F401
        return list(cls._formatters.keys())
