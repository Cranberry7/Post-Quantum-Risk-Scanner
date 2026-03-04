"""Console reporter — renders analysis results to the terminal.

Uses the ``rich`` library for colored, structured output.
"""

from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pq_risk_scanner.models import AnalysisResult, RiskCategory

_RISK_COLORS = {
    RiskCategory.QUANTUM_UNSAFE: "bold red",
    RiskCategory.QUANTUM_WEAKENED: "bold yellow",
    RiskCategory.QUANTUM_SAFE: "bold green",
    RiskCategory.UNKNOWN: "dim",
}

_RISK_ICONS = {
    RiskCategory.QUANTUM_UNSAFE: "✗",
    RiskCategory.QUANTUM_WEAKENED: "⚠",
    RiskCategory.QUANTUM_SAFE: "✓",
    RiskCategory.UNKNOWN: "?",
}


def print_results(results: List[AnalysisResult], verbose: bool = False) -> None:
    """Print analysis results to the console."""
    console = Console()

    if not results:
        console.print("[dim]No cryptographic findings detected.[/dim]")
        return

    # --- Summary banner ---------------------------------------------------
    counts = _count_by_risk(results)
    console.print()
    console.print(
        Panel(
            _summary_text(counts),
            title="[bold]Post-Quantum Risk Scan Summary[/bold]",
            border_style="blue",
        )
    )
    console.print()

    # --- Findings table ---------------------------------------------------
    table = Table(
        title="Cryptographic Inventory",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Algorithm", min_width=12)
    table.add_column("Key Size", justify="right")
    table.add_column("Context")
    table.add_column("Risk", min_width=16)
    table.add_column("PQ Bits", justify="right")
    table.add_column("Source")

    for r in results:
        risk_style = _RISK_COLORS.get(r.risk_category, "")
        icon = _RISK_ICONS.get(r.risk_category, "")
        table.add_row(
            r.finding.algorithm,
            str(r.finding.key_size) if r.finding.key_size else "—",
            r.finding.usage_context.value,
            Text(f"{icon} {r.risk_category.value}", style=risk_style),
            str(r.effective_post_quantum_bits) if r.effective_post_quantum_bits is not None else "—",
            _short_source(r.finding.source_file),
        )

    console.print(table)

    # --- Verbose details --------------------------------------------------
    if verbose:
        _print_details(console, results)


def _count_by_risk(results: List[AnalysisResult]) -> dict[RiskCategory, int]:
    """Count findings per risk category."""
    counts: dict[RiskCategory, int] = {}
    for r in results:
        counts[r.risk_category] = counts.get(r.risk_category, 0) + 1
    return counts


def _summary_text(counts: dict[RiskCategory, int]) -> str:
    """Build a one-line summary string."""
    parts = []
    for cat in (RiskCategory.QUANTUM_UNSAFE, RiskCategory.QUANTUM_WEAKENED, RiskCategory.QUANTUM_SAFE, RiskCategory.UNKNOWN):
        n = counts.get(cat, 0)
        if n:
            icon = _RISK_ICONS[cat]
            parts.append(f"{icon} {n} {cat.value}")
    return "  |  ".join(parts) if parts else "No findings"


def _short_source(path: str) -> str:
    """Shorten a source file path for display."""
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 3:
        return path
    return "…/" + "/".join(parts[-2:])


def _print_details(console: Console, results: List[AnalysisResult]) -> None:
    """Print detailed quantum explanations and migration guidance."""
    console.print()
    console.print("[bold]Detailed Analysis[/bold]")
    console.print("─" * 60)

    for r in results:
        console.print(f"\n[bold]{r.finding.algorithm}[/bold] ({r.finding.usage_context.value})")

        if r.quantum_explanation:
            console.print(f"  [cyan]Impact:[/cyan] {r.quantum_explanation.impact_summary}")
            console.print(f"  [dim]{r.quantum_explanation.detailed_explanation}[/dim]")

        if r.migration_guidance:
            console.print(f"  [green]Migrate to:[/green] {r.migration_guidance.recommended_replacement}")
            console.print(f"  [dim]Standard: {r.migration_guidance.standard_reference}[/dim]")
