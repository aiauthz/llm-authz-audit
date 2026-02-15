"""Scan context and file entry models."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from llm_authz_audit.core.config import ToolConfig


@dataclass
class FileEntry:
    path: Path
    relative_path: str
    _content: str | None = field(default=None, repr=False)
    _ast_tree: ast.Module | None = field(default=None, repr=False)

    @property
    def content(self) -> str:
        if self._content is None:
            try:
                self._content = self.path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                self._content = ""
        return self._content

    @property
    def ast_tree(self) -> ast.Module | None:
        if self._ast_tree is None and self.path.suffix == ".py":
            try:
                self._ast_tree = ast.parse(self.content, filename=str(self.path))
            except SyntaxError:
                return None
        return self._ast_tree

    @property
    def suffix(self) -> str:
        return self.path.suffix


@dataclass
class ScanContext:
    target_path: Path
    files: list[FileEntry]
    config: ToolConfig

    def python_files(self) -> list[FileEntry]:
        return [f for f in self.files if f.suffix == ".py"]

    def config_files(self) -> list[FileEntry]:
        config_suffixes = {".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".cfg"}
        return [f for f in self.files if f.suffix in config_suffixes]

    def files_matching(self, pattern: str) -> list[FileEntry]:
        return [f for f in self.files if fnmatch(f.relative_path, pattern)]

    def files_matching_any(self, patterns: list[str]) -> list[FileEntry]:
        return [
            f for f in self.files
            if any(fnmatch(f.relative_path, p) for p in patterns)
        ]
