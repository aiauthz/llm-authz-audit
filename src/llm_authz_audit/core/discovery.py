"""File discovery — walks target directory, respects .gitignore and exclude patterns."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from llm_authz_audit.core.context import FileEntry


# Directories always skipped
_ALWAYS_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "*.egg-info",
}

# Binary/irrelevant extensions
_SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2",
    ".db", ".sqlite", ".sqlite3",
}


def _load_gitignore_patterns(target_path: Path) -> list[str]:
    gitignore = target_path / ".gitignore"
    if not gitignore.is_file():
        return []
    patterns = []
    for line in gitignore.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _should_skip_dir(name: str, gitignore_patterns: list[str]) -> bool:
    if name in _ALWAYS_SKIP_DIRS:
        return True
    for pattern in _ALWAYS_SKIP_DIRS:
        if "*" in pattern and fnmatch(name, pattern):
            return True
    for pattern in gitignore_patterns:
        stripped = pattern.rstrip("/")
        if fnmatch(name, stripped):
            return True
    return False


def _should_skip_file(
    relative_path: str,
    suffix: str,
    exclude_patterns: list[str],
    gitignore_patterns: list[str],
) -> bool:
    if suffix in _SKIP_EXTENSIONS:
        return True
    for pattern in exclude_patterns:
        if fnmatch(relative_path, pattern):
            return True
    for pattern in gitignore_patterns:
        if fnmatch(relative_path, pattern):
            return True
    return False


def get_diff_files(target_path: Path, ref: str) -> set[str]:
    """Get files changed since *ref* using git diff.

    Returns relative paths. Returns empty set on any failure.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", ref],
            capture_output=True,
            text=True,
            cwd=target_path,
            timeout=30,
        )
        if result.returncode != 0:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return set()


class FileDiscovery:
    """Walk target directory and build a list of FileEntry objects."""

    def __init__(
        self,
        target_path: Path,
        exclude_patterns: list[str] | None = None,
        diff_files: set[str] | None = None,
    ):
        self.target_path = target_path.resolve()
        self.exclude_patterns = exclude_patterns or []
        self.diff_files = diff_files

    def discover(self) -> list[FileEntry]:
        if not self.target_path.is_dir():
            return []

        gitignore_patterns = _load_gitignore_patterns(self.target_path)
        entries: list[FileEntry] = []

        for item in sorted(self.target_path.rglob("*")):
            if not item.is_file():
                continue

            # Check if any parent dir should be skipped
            relative = item.relative_to(self.target_path)
            skip = False
            for part in relative.parts[:-1]:
                if _should_skip_dir(part, gitignore_patterns):
                    skip = True
                    break
            if skip:
                continue

            relative_path = str(relative)
            if _should_skip_file(
                relative_path, item.suffix, self.exclude_patterns, gitignore_patterns
            ):
                continue

            entries.append(FileEntry(path=item, relative_path=relative_path))

        # Filter to diff files if set
        if self.diff_files is not None:
            entries = [e for e in entries if e.relative_path in self.diff_files]

        return entries
