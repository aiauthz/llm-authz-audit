"""Typer CLI — scan, list-analyzers, list-rules, init."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.engine import ScanEngine
from llm_authz_audit.core.finding import Severity
from llm_authz_audit.output.formatter import FormatterFactory

app = typer.Typer(
    name="llm-authz-audit",
    help="Static security analyzer for LLM applications.",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Target directory to scan")] = Path("."),
    format: Annotated[str, typer.Option("--format", help="Output format: console|json")] = "console",
    fail_on: Annotated[str, typer.Option("--fail-on", help="Minimum severity to fail: critical|high|medium|low")] = "high",
    analyzers: Annotated[Optional[str], typer.Option("--analyzers", help="Comma-separated list of analyzers to enable")] = None,
    exclude: Annotated[Optional[str], typer.Option("--exclude", help="Comma-separated glob patterns to skip")] = None,
    ai: Annotated[bool, typer.Option("--ai", help="Enable LLM-powered deep analysis")] = False,
    ai_provider: Annotated[str, typer.Option("--ai-provider", help="AI provider: openai|anthropic")] = "anthropic",
    ai_model: Annotated[str, typer.Option("--ai-model", help="AI model name")] = "claude-sonnet-4-5-20250929",
    config: Annotated[Optional[Path], typer.Option("--config", help="Path to config file")] = None,
    suppress: Annotated[Optional[Path], typer.Option("--suppress", help="Path to suppression file")] = None,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Show debug output")] = False,
) -> None:
    """Scan a directory for LLM security issues."""
    target = path.resolve()
    if not target.is_dir():
        console.print(f"[red]Error: {path} is not a directory[/red]")
        raise typer.Exit(code=2)

    tool_config = ToolConfig(
        target_path=target,
        output_format=format,
        fail_on=Severity(fail_on),
        enabled_analyzers=analyzers.split(",") if analyzers else None,
        exclude_patterns=exclude.split(",") if exclude else [],
        suppress_file=suppress,
        verbose=verbose,
        ai_enabled=ai,
        ai_provider=ai_provider,
        ai_model=ai_model,
        config_file=config,
    )

    if verbose:
        console.print(f"[dim]Scanning: {target}[/dim]")
        console.print(f"[dim]Format: {format}, Fail on: {fail_on}[/dim]")

    engine = ScanEngine(tool_config)
    result = engine.scan()

    if verbose:
        console.print(f"[dim]Files scanned: {result.files_scanned}[/dim]")
        console.print(f"[dim]Analyzers run: {', '.join(result.analyzers_run)}[/dim]")
        if result.analyzers_skipped:
            console.print(f"[dim]Analyzers skipped: {', '.join(result.analyzers_skipped)}[/dim]")

    # AI mode
    if ai and result.findings:
        try:
            from llm_authz_audit.llm.ai_analyzer import AIAnalyzer
            ai_analyzer = AIAnalyzer(provider=ai_provider, model=ai_model)
            result = ai_analyzer.refine(result, engine)
        except ImportError:
            console.print("[yellow]Warning: AI dependencies not installed. Run: pip install llm-authz-audit[ai][/yellow]")

    formatter = FormatterFactory.get(format)
    output = formatter.format(result)
    print(output)

    raise typer.Exit(code=result.exit_code)


@app.command("list-analyzers")
def list_analyzers() -> None:
    """Show available analyzers."""
    from llm_authz_audit.analyzers import get_registered_analyzers

    table = Table(title="Available Analyzers", show_header=True, header_style="bold")
    table.add_column("Name", style="bold")
    table.add_column("Description")

    for cls in get_registered_analyzers():
        instance = cls()
        table.add_row(instance.name, instance.description)

    console.print(table)


@app.command("list-rules")
def list_rules() -> None:
    """Show all rules with IDs and severity."""
    from llm_authz_audit.core.rule import RuleLoader

    rules = RuleLoader.load_all_builtin()

    table = Table(title="Built-in Rules", show_header=True, header_style="bold")
    table.add_column("ID", style="bold")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("OWASP LLM")

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }

    for rule in sorted(rules, key=lambda r: r.id):
        color = severity_colors.get(rule.severity.value, "white")
        table.add_row(
            rule.id,
            rule.title,
            f"[{color}]{rule.severity.value}[/{color}]",
            rule.owasp_llm or "-",
        )

    console.print(table)


@app.command()
def init() -> None:
    """Generate a .llm-audit.yaml config template."""
    template = """\
# llm-authz-audit configuration
# See: https://github.com/llm-authz-audit/llm-authz-audit

# Output format: console or json
format: console

# Minimum severity to cause non-zero exit: critical, high, medium, low
fail_on: high

# Analyzers to enable (omit to enable all)
# analyzers:
#   - SecretsAnalyzer
#   - EndpointAnalyzer
#   - ToolRBACAnalyzer
#   - RAGACLAnalyzer
#   - MCPPermissionAnalyzer
#   - SessionIsolationAnalyzer
#   - RateLimitingAnalyzer
#   - OutputFilteringAnalyzer
#   - CredentialForwardingAnalyzer
#   - AuditLoggingAnalyzer
#   - InputValidationAnalyzer

# Glob patterns to exclude
exclude:
  - "tests/*"
  - "*.test.py"

# AI-powered deep analysis
ai:
  enabled: false
  provider: anthropic
  model: claude-sonnet-4-5-20250929
"""
    config_path = Path(".llm-audit.yaml")
    if config_path.exists():
        console.print(f"[yellow]Config file already exists: {config_path}[/yellow]")
        raise typer.Exit(code=1)

    config_path.write_text(template)
    console.print(f"[green]Created config template: {config_path}[/green]")
