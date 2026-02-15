"""Analyzer registry and auto-discovery."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llm_authz_audit.analyzers.base import BaseAnalyzer

_ANALYZER_CLASSES: list[type[BaseAnalyzer]] = []
_discovered = False


def register_analyzer(cls: type[BaseAnalyzer]) -> type[BaseAnalyzer]:
    """Decorator to register an analyzer class."""
    if cls not in _ANALYZER_CLASSES:
        _ANALYZER_CLASSES.append(cls)
    return cls


def get_registered_analyzers() -> list[type[BaseAnalyzer]]:
    """Return all registered analyzer classes. Triggers auto-import on first call."""
    global _discovered
    if not _discovered:
        _auto_discover()
        _discovered = True
    return list(_ANALYZER_CLASSES)


def _auto_discover() -> None:
    """Import all analyzer modules to trigger registration."""
    from llm_authz_audit.analyzers import (  # noqa: F401
        audit_logging,
        credential_forwarding,
        endpoints,
        input_validation,
        mcp_permissions,
        output_filtering,
        rag_acl,
        rate_limiting,
        secrets,
        session_isolation,
        tool_rbac,
    )
