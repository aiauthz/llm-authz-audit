"""ASCII art intro banner for console output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from llm_authz_audit import __version__

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import Console


_ART = """\
  [bold cyan]╦   ╦   ╔╦╗[/bold cyan]
  [bold cyan]║   ║   ║║║[/bold cyan]
  [bold cyan]╩═╝ ╩═╝ ╩ ╩[/bold cyan]   [bold blue]authz-audit[/bold blue]"""

_TAGLINE = "  Static Security Analyzer for LLM Applications"
_URL = "https://github.com/aiauthz/llm-authz-audit"


def print_banner(
    console: Console,
    *,
    target: Path,
    analyzers_loaded: int,
    rules_loaded: int,
) -> None:
    """Render the intro banner to *console*."""
    console.print(_ART, highlight=False)
    console.print(f"[dim]{_TAGLINE}  v{__version__}[/dim]", highlight=False)
    console.print(f"[dim underline]{_URL}[/dim underline]", highlight=False)
    console.print()
    console.print(f"  [dim]Target:[/dim]    [dim bold]{target}[/dim bold]", highlight=False)
    console.print(
        f"  [dim]Analyzers:[/dim] [dim bold]{analyzers_loaded} loaded[/dim bold]"
        f" [dim]|[/dim] [dim]Rules:[/dim] [dim bold]{rules_loaded} loaded[/dim bold]",
        highlight=False,
    )
    console.print()
    console.print("[dim]  Usage:[/dim]", highlight=False)
    console.print("[dim]    llm-authz-audit scan /path/to/project[/dim]", highlight=False)
    console.print("[dim]    llm-authz-audit scan . --format json[/dim]", highlight=False)
    console.print("[dim]    llm-authz-audit scan . --analyzers SecretsAnalyzer,EndpointAnalyzer[/dim]", highlight=False)
    console.print("[dim]    llm-authz-audit scan . --ai                  [italic]# LLM-powered deep analysis[/italic][/dim]", highlight=False)
    console.print("[dim]    llm-authz-audit scan . --fail-on critical    [italic]# exit non-zero only on critical[/italic][/dim]", highlight=False)
    console.print()
