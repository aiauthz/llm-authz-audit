"""Base analyzer abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llm_authz_audit.core.context import ScanContext
    from llm_authz_audit.core.finding import Finding


class BaseAnalyzer(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def should_run(self, context: ScanContext) -> bool:
        """Return True if this analyzer is relevant to the target project."""

    @abstractmethod
    def analyze(self, context: ScanContext) -> list[Finding]:
        """Run analysis and return findings."""
