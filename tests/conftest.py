"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.context import FileEntry, ScanContext


@pytest.fixture
def make_scan_context(tmp_path: Path):
    """Factory fixture: write files to tmp_path and return a ScanContext."""

    def _make(
        files: dict[str, str],
        config: ToolConfig | None = None,
    ) -> ScanContext:
        entries: list[FileEntry] = []
        for rel_path, content in files.items():
            full_path = tmp_path / rel_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8")
            entries.append(FileEntry(path=full_path, relative_path=rel_path))

        return ScanContext(
            target_path=tmp_path,
            files=entries,
            config=config or ToolConfig(target_path=tmp_path),
        )

    return _make
