#!/usr/bin/env python3
"""PQ Risk Scanner — CLI entry point.

Wires all pipeline layers together:
  scan → classify → explain → advise → report
"""

from __future__ import annotations

from pathlib import Path

import click

from pq_risk_scanner.analysis.migration_advisor import advise_batch
from pq_risk_scanner.analysis.risk_classifier import classify_findings
from pq_risk_scanner.quantum import enrich_batch
from pq_risk_scanner.reporting.console_reporter import print_results
from pq_risk_scanner.reporting.markdown_reporter import generate_report
from pq_risk_scanner.reporting.json_reporter import generate_json_report
from pq_risk_scanner.scanners import scan_path


@click.group()
@click.version_option(package_name="pq_risk_scanner")
def cli() -> None:
    """Post-Quantum Risk Scanner — assess cryptographic post-quantum readiness."""


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output-format",
    type=click.Choice(["console", "markdown", "json"], case_sensitive=False),
    default="console",
    help="Output format (default: console).",
)
@click.option(
    "--output-file",
    type=click.Path(),
    default=None,
    help="Path to write the markdown report (only with --output-format markdown).",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed quantum explanations.")
@click.option("--no-recursive", is_flag=True, help="Don't recurse into subdirectories.")
def scan(
    target: str,
    output_format: str,
    output_file: str | None,
    verbose: bool,
    no_recursive: bool,
) -> None:
    """Scan TARGET (file or directory) for cryptographic primitives."""
    target_path = Path(target)

    # ── Stage 1: Scan ─────────────────────────────────────────────────
    findings = scan_path(target_path, recursive=not no_recursive)

    if not findings:
        click.echo("No cryptographic primitives detected.")
        return

    # ── Stage 2: Classify ─────────────────────────────────────────────
    results = classify_findings(findings)

    # ── Stage 3: Quantum Reasoning ────────────────────────────────────
    results = enrich_batch(results)

    # ── Stage 4: Migration Guidance ───────────────────────────────────
    results = advise_batch(results)

    # ── Stage 5: Report ───────────────────────────────────────────────
    if output_format == "markdown":
        out = Path(output_file) if output_file else Path("report.md")
        generate_report(results, output_path=out)
        click.echo(f"Report written to {out}")
    elif output_format == "json":
        if output_file:
            out = Path(output_file)
            generate_json_report(results, output_path=out)
            click.echo(f"JSON report written to {out}")
        else:
            json_out = generate_json_report(results)
            click.echo(json_out)
    else:
        print_results(results, verbose=verbose)


if __name__ == "__main__":
    cli()
