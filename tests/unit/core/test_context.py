"""Tests for ScanContext and FileEntry."""

from pathlib import Path

from llm_authz_audit.core.context import FileEntry, ScanContext
from llm_authz_audit.core.config import ToolConfig


class TestFileEntry:
    def test_lazy_content_loading(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        entry = FileEntry(path=f, relative_path="test.py")
        assert entry._content is None
        assert entry.content == "print('hello')"
        assert entry._content is not None

    def test_ast_tree_for_python(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1")
        entry = FileEntry(path=f, relative_path="test.py")
        tree = entry.ast_tree
        assert tree is not None

    def test_ast_tree_none_for_non_python(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("key: value")
        entry = FileEntry(path=f, relative_path="test.yaml")
        assert entry.ast_tree is None

    def test_ast_tree_none_for_syntax_error(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text("def (broken:")
        entry = FileEntry(path=f, relative_path="bad.py")
        assert entry.ast_tree is None

    def test_suffix(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("")
        entry = FileEntry(path=f, relative_path="test.py")
        assert entry.suffix == ".py"


class TestScanContext:
    def test_python_files(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": "x = 1",
            "config.yaml": "key: val",
            "utils.py": "y = 2",
        })
        assert len(ctx.python_files()) == 2

    def test_config_files(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": "x = 1",
            "config.yaml": "key: val",
            "settings.json": "{}",
            "setup.toml": "[tool]",
        })
        assert len(ctx.config_files()) == 3

    def test_files_matching(self, make_scan_context):
        ctx = make_scan_context({
            "src/app.py": "x = 1",
            "src/utils.py": "y = 2",
            "tests/test_app.py": "z = 3",
        })
        assert len(ctx.files_matching("src/*.py")) == 2

    def test_files_matching_any(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": "",
            "config.yaml": "",
            "data.json": "",
        })
        results = ctx.files_matching_any(["*.py", "*.yaml"])
        assert len(results) == 2
