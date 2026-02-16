"""Tests for FileDiscovery."""


from llm_authz_audit.core.discovery import FileDiscovery


class TestFileDiscovery:
    def test_discovers_python_files(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "utils.py").write_text("y = 2")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert "app.py" in paths
        assert "utils.py" in paths

    def test_skips_git_dir(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("gitconfig")
        (tmp_path / "app.py").write_text("x = 1")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert "app.py" in paths
        assert not any(".git" in p for p in paths)

    def test_skips_pycache(self, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "app.cpython-311.pyc").write_text("")
        (tmp_path / "app.py").write_text("x = 1")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert not any("__pycache__" in p for p in paths)

    def test_skips_binary_extensions(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        (tmp_path / "app.py").write_text("x = 1")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert "image.png" not in paths
        assert "app.py" in paths

    def test_respects_exclude_patterns(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "test_app.py").write_text("test")
        discovery = FileDiscovery(tmp_path, exclude_patterns=["test_*.py"])
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert "app.py" in paths
        assert "test_app.py" not in paths

    def test_respects_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\nbuild/\n")
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "debug.log").write_text("log")
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        (build_dir / "out.js").write_text("js")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert "app.py" in paths
        assert "debug.log" not in paths
        assert not any("build" in p for p in paths)

    def test_discovers_nested_files(self, tmp_path):
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        (src_dir / "main.py").write_text("x = 1")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert any("main.py" in p for p in paths)

    def test_nonexistent_directory(self, tmp_path):
        discovery = FileDiscovery(tmp_path / "nonexistent")
        entries = discovery.discover()
        assert entries == []

    def test_discovers_config_files(self, tmp_path):
        (tmp_path / "config.yaml").write_text("key: val")
        (tmp_path / "settings.json").write_text("{}")
        (tmp_path / ".env").write_text("KEY=val")
        discovery = FileDiscovery(tmp_path)
        entries = discovery.discover()
        paths = {e.relative_path for e in entries}
        assert "config.yaml" in paths
        assert "settings.json" in paths
        assert ".env" in paths
