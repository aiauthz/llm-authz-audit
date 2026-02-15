"""Semgrep-style colored terminal output."""

from __future__ import annotations

import io
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from llm_authz_audit.core.engine import ScanResult
from llm_authz_audit.core.finding import Finding, Severity
from llm_authz_audit.output.formatter import BaseFormatter, FormatterFactory

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}

_SEVERITY_CHEVRONS = {
    Severity.CRITICAL: "\u276f\u276f\u276f\u2771",   # ❯❯❯❱
    Severity.HIGH: "\u276f\u276f\u2771",              # ❯❯❱
    Severity.MEDIUM: "\u276f\u2771",                  # ❯❱
    Severity.LOW: "\u2771",                           # ❱
}


def _section_box(title: str) -> Panel:
    """Semgrep-style section header: ┌──────┐ │ Title │ └──────┘"""
    return Panel(
        Text(title, style="bold"),
        expand=False,
        border_style="dim",
        padding=(0, 1),
    )


class ConsoleFormatter(BaseFormatter):
    def format(self, result: ScanResult) -> str:
        console = Console(record=True, width=120, file=io.StringIO())

        # ── Findings ──
        if not result.findings:
            console.print(_section_box("Scan Complete"))
            console.print("  [bold green]\u2705 No security findings detected.[/bold green]")
            console.print()
        else:
            count = len(result.findings)
            blocking = sum(
                1 for f in result.findings
                if f.severity >= Severity.HIGH
            )
            label = f"{count} Code Finding{'s' if count != 1 else ''}"
            console.print(_section_box(label))
            console.print()

            self._print_findings(console, result.findings)

        # ── Scan Summary ──
        console.print(_section_box("Scan Summary"))
        self._print_summary(console, result)

        return console.export_text()

    def _print_findings(self, console: Console, findings: list[Finding]) -> None:
        # Group findings by file path (preserving severity order within each file)
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_file[f.file_path].append(f)

        for file_path, file_findings in by_file.items():
            console.print(f"    {file_path}", highlight=False)

            for finding in file_findings:
                sev_color = _SEVERITY_COLORS.get(finding.severity, "white")
                chevron = _SEVERITY_CHEVRONS.get(finding.severity, "\u2771")

                # ❯❯❱ rule_id
                header = Text()
                header.append(f"   {chevron} ", style=sev_color)
                header.append(finding.rule_id, style="bold")
                if finding.owasp_llm:
                    header.append(f"  [{finding.owasp_llm}]", style="dim")
                console.print(header, highlight=False)

                # Indented description
                console.print(f"          {finding.title}", highlight=False)

                # Code snippet with line number: 5┆ code here
                if finding.snippet and finding.line_number:
                    console.print(
                        f"          [dim]{finding.line_number}\u2506[/dim] {finding.snippet}",
                        highlight=False,
                    )
                elif finding.snippet:
                    console.print(
                        f"          [dim]\u2506[/dim] {finding.snippet}",
                        highlight=False,
                    )

                # Remediation
                console.print(
                    f"          [green]fix:[/green] [dim]{finding.remediation}[/dim]",
                    highlight=False,
                )
                console.print()

    def _print_summary(self, console: Console, result: ScanResult) -> None:
        if result.findings:
            blocking = sum(1 for f in result.findings if f.severity >= Severity.HIGH)
            console.print(
                f"  [bold]\u26a0 Findings:[/bold] {len(result.findings)}"
                f" ({blocking} blocking)",
                highlight=False,
            )
        else:
            console.print(
                "  [bold green]\u2705 Scan completed successfully.[/bold green]",
                highlight=False,
            )

        console.print(f"  [dim]\u2022[/dim] Analyzers run: {len(result.analyzers_run)}", highlight=False)
        console.print(f"  [dim]\u2022[/dim] Files scanned: {result.files_scanned}", highlight=False)

        # Severity breakdown
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = result.summary.get(sev.value, 0)
            if count > 0:
                color = _SEVERITY_COLORS.get(sev, "white")
                chevron = _SEVERITY_CHEVRONS.get(sev, "\u2771")
                console.print(
                    f"  [dim]\u2022[/dim] [{color}]{chevron} {sev.value.capitalize()}: {count}[/{color}]",
                    highlight=False,
                )

        console.print()


FormatterFactory.register("console", ConsoleFormatter)
