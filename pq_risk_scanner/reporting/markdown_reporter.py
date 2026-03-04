"""Markdown report generator.

Produces a structured ``.md`` report with inventory, risk table,
quantum explanations, and migration recommendations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from pq_risk_scanner.models import AnalysisResult, RiskCategory

_RISK_EMOJI = {
    RiskCategory.QUANTUM_UNSAFE: "🔴",
    RiskCategory.QUANTUM_WEAKENED: "🟡",
    RiskCategory.QUANTUM_SAFE: "🟢",
    RiskCategory.UNKNOWN: "⚪",
}


def generate_report(results: List[AnalysisResult], output_path: Path | None = None) -> str:
    """Generate a Markdown report and optionally write to *output_path*.

    Returns the report text.
    """
    lines: list[str] = []
    _header(lines)
    _summary(lines, results)
    _inventory_table(lines, results)
    _detailed_findings(lines, results)
    _migration_section(lines, results)
    _footer(lines)

    report = "\n".join(lines)

    if output_path is not None:
        output_path.write_text(report, encoding="utf-8")

    return report


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _header(lines: list[str]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("# Post-Quantum Risk Assessment Report")
    lines.append(f"\n*Generated: {now}*\n")
    lines.append("---\n")


def _summary(lines: list[str], results: List[AnalysisResult]) -> None:
    lines.append("## Summary\n")
    counts = _count_by_risk(results)
    for cat in (RiskCategory.QUANTUM_UNSAFE, RiskCategory.QUANTUM_WEAKENED, RiskCategory.QUANTUM_SAFE, RiskCategory.UNKNOWN):
        n = counts.get(cat, 0)
        if n:
            lines.append(f"- {_RISK_EMOJI[cat]} **{n}** finding(s) classified as **{cat.value}**")
    lines.append(f"\n**Total findings:** {len(results)}\n")
    lines.append("---\n")


def _inventory_table(lines: list[str], results: List[AnalysisResult]) -> None:
    lines.append("## Cryptographic Inventory\n")
    lines.append("| Algorithm | Key Size | Context | Risk | PQ Bits | Source |")
    lines.append("|-----------|----------|---------|------|---------|--------|")
    for r in results:
        emoji = _RISK_EMOJI.get(r.risk_category, "")
        key_sz = str(r.finding.key_size) if r.finding.key_size else "—"
        pq_bits = str(r.effective_post_quantum_bits) if r.effective_post_quantum_bits is not None else "—"
        src = _short_source(r.finding.source_file)
        lines.append(
            f"| {r.finding.algorithm} | {key_sz} | {r.finding.usage_context.value} "
            f"| {emoji} {r.risk_category.value} | {pq_bits} | {src} |"
        )
    lines.append("\n---\n")


def _detailed_findings(lines: list[str], results: List[AnalysisResult]) -> None:
    detailed = [r for r in results if r.quantum_explanation]
    if not detailed:
        return

    lines.append("## Quantum Impact Analysis\n")
    for r in detailed:
        lines.append(f"### {r.finding.algorithm}")
        lines.append(f"\n**{r.quantum_explanation.impact_summary}**\n")
        lines.append(r.quantum_explanation.detailed_explanation)
        lines.append("")
    lines.append("---\n")


def _migration_section(lines: list[str], results: List[AnalysisResult]) -> None:
    migratable = [r for r in results if r.migration_guidance]
    if not migratable:
        return

    lines.append("## Migration Recommendations\n")
    lines.append("| Current Algorithm | Recommended Replacement | Standard |")
    lines.append("|-------------------|-------------------------|----------|")
    seen: set[str] = set()
    for r in migratable:
        key = r.finding.algorithm
        if key in seen:
            continue
        seen.add(key)
        mg = r.migration_guidance
        lines.append(f"| {key} | {mg.recommended_replacement} | {mg.standard_reference} |")

    lines.append("\n### Rationale\n")
    seen.clear()
    for r in migratable:
        key = r.finding.algorithm
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- **{key}:** {r.migration_guidance.rationale}")
    lines.append("\n---\n")


def _footer(lines: list[str]) -> None:
    lines.append(
        "*This report provides analytical insight based on current public research "
        "and NIST standards. It does not constitute a security guarantee or "
        "compliance assessment.*\n"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_by_risk(results: List[AnalysisResult]) -> dict[RiskCategory, int]:
    counts: dict[RiskCategory, int] = {}
    for r in results:
        counts[r.risk_category] = counts.get(r.risk_category, 0) + 1
    return counts


def _short_source(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 3:
        return path
    return "…/" + "/".join(parts[-2:])
