"""ASCII art intro banner for console output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from llm_authz_audit import __version__

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import Console


_ART = """\
  [bold #10b981]╦   ╦   ╔╦╗[/bold #10b981]
  [bold #10b981]║   ║   ║║║[/bold #10b981]
  [bold #10b981]╩═╝ ╩═╝ ╩ ╩[/bold #10b981]   [bold #e2e8f0]authz[/bold #e2e8f0][#64748b]-[/#64748b][bold #10b981]audit[/bold #10b981]"""

_TAGLINE = "  Static Security Analyzer for LLM Applications"
_URL = "  https://github.com/aiauthz/llm-authz-audit"


def print_banner(
    console: Console,
    *,
    target: Path,
    analyzers_loaded: int,
    rules_loaded: int,
    fail_on: str = "high",
    exclude_patterns: list[str] | None = None,
    config_file: Path | None = None,
    suppress_file: Path | None = None,
    min_confidence: str | None = None,
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
    console.print(f"  [dim]Fail on:[/dim]  [dim bold]{fail_on}[/dim bold]", highlight=False)
    if config_file:
        console.print(f"  [dim]Config:[/dim]   [dim bold]{config_file}[/dim bold]", highlight=False)
    if suppress_file:
        console.print(f"  [dim]Suppress:[/dim] [dim bold]{suppress_file}[/dim bold]", highlight=False)
    if min_confidence:
        console.print(f"  [dim]Min conf:[/dim] [dim bold]{min_confidence}[/dim bold]", highlight=False)
    if exclude_patterns:
        console.print(
            f"  [dim]Exclude:[/dim]  [dim bold]{', '.join(exclude_patterns)}[/dim bold]",
            highlight=False,
        )
    console.print()
