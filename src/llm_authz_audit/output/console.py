"""Rich-based colored terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from llm_authz_audit.core.engine import ScanResult
from llm_authz_audit.core.finding import Severity
from llm_authz_audit.output.formatter import BaseFormatter, FormatterFactory

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
}


class ConsoleFormatter(BaseFormatter):
    def format(self, result: ScanResult) -> str:
        console = Console(record=True, width=120)

        if not result.findings:
            console.print(Panel(
                "[bold green]No security findings detected.[/bold green]",
                title="llm-authz-audit",
                border_style="green",
            ))
        else:
            console.print(Panel(
                f"[bold]{len(result.findings)} finding(s) detected[/bold]",
                title="llm-authz-audit",
                border_style="red" if result.exit_code else "yellow",
            ))

            for finding in result.findings:
                sev_color = _SEVERITY_COLORS.get(finding.severity, "white")
                icon = _SEVERITY_ICONS.get(finding.severity, "[-]")

                header = Text()
                header.append(f"{icon} ", style=sev_color)
                header.append(f"{finding.rule_id}: ", style="bold")
                header.append(finding.title)

                console.print(header)
                location = f"  {finding.file_path}"
                if finding.line_number:
                    location += f":{finding.line_number}"
                console.print(location, style="dim")

                if finding.snippet:
                    console.print(f"  > {finding.snippet}", style="dim italic")

                console.print(f"  {finding.description}")
                console.print(f"  Fix: {finding.remediation}", style="green")

                if finding.owasp_llm:
                    console.print(f"  OWASP LLM: {finding.owasp_llm}", style="dim")
                console.print()

        # Summary table
        table = Table(title="Summary", show_header=True, header_style="bold")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_row("Files scanned", str(result.files_scanned))
        table.add_row("Analyzers run", str(len(result.analyzers_run)))
        table.add_row("Total findings", str(len(result.findings)))
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = result.summary.get(sev.value, 0)
            style = _SEVERITY_COLORS.get(sev, "white") if count > 0 else "dim"
            table.add_row(sev.value.capitalize(), Text(str(count), style=style))
        console.print(table)

        return console.export_text()


FormatterFactory.register("console", ConsoleFormatter)
