"""Unified parser for YAML, JSON, TOML, and .env config files."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


def parse_config_file(path: Path) -> dict | list | None:
    """Parse a config file and return its contents."""
    suffix = path.suffix.lower()
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    try:
        if suffix in (".yaml", ".yml"):
            return yaml.safe_load(content)
        elif suffix == ".json":
            return json.loads(content)
        elif suffix == ".toml":
            return _parse_toml(content)
        elif suffix == ".env":
            return _parse_env(content)
    except Exception:
        return None
    return None


def parse_config_string(content: str, format: str) -> dict | list | None:
    """Parse config content from a string."""
    try:
        if format in ("yaml", "yml"):
            return yaml.safe_load(content)
        elif format == "json":
            return json.loads(content)
        elif format == "toml":
            return _parse_toml(content)
        elif format == "env":
            return _parse_env(content)
    except Exception:
        return None
    return None


def _parse_toml(content: str) -> dict:
    """Parse TOML content. Uses tomllib if available (Python 3.11+)."""
    import tomllib
    return tomllib.loads(content)


def _parse_env(content: str) -> dict[str, str]:
    """Parse .env file format (KEY=value lines)."""
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            result[key] = value
    return result
