"""Tests for --diff mode: get_diff_files and FileDiscovery filtering."""

from pathlib import Path
from unittest.mock import patch

from llm_authz_audit.core.discovery import FileDiscovery, get_diff_files


class TestGetDiffFiles:
    def test_returns_files_from_git(self, tmp_path):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "app.py\nsrc/utils.py\n"
            result = get_diff_files(tmp_path, "HEAD~1")
        assert result == {"app.py", "src/utils.py"}

    def test_empty_on_failure(self, tmp_path):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            result = get_diff_files(tmp_path, "HEAD~1")
        assert result == set()

    def test_empty_on_timeout(self, tmp_path):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 30)):
            result = get_diff_files(tmp_path, "HEAD~1")
        assert result == set()

    def test_empty_on_no_git(self, tmp_path):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = get_diff_files(tmp_path, "HEAD~1")
        assert result == set()

    def test_strips_whitespace(self, tmp_path):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "  app.py  \n\n  utils.py  \n"
            result = get_diff_files(tmp_path, "main")
        assert result == {"app.py", "utils.py"}


class TestFileDiscoveryDiffFilter:
    def test_filters_to_diff_files(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "other.py").write_text("y = 2\n")

        discovery = FileDiscovery(tmp_path, diff_files={"app.py"})
        files = discovery.discover()

        paths = {f.relative_path for f in files}
        assert "app.py" in paths
        assert "other.py" not in paths

    def test_no_filter_when_none(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "other.py").write_text("y = 2\n")

        discovery = FileDiscovery(tmp_path, diff_files=None)
        files = discovery.discover()

        paths = {f.relative_path for f in files}
        assert "app.py" in paths
        assert "other.py" in paths

    def test_empty_diff_returns_empty(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")

        discovery = FileDiscovery(tmp_path, diff_files=set())
        files = discovery.discover()
        assert files == []
