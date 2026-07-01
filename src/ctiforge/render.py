"""Stage 5 — writers: report.json, report.md, iocs.csv."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .config import REVIEW_BANNER
from .models import ReportAnalysis

def _esc(text: str) -> str:
    """Escape pipe characters for Markdown table cells."""
    return (text or "").replace("|", "\\|").replace("\n", " ")


def _context_lookup(analysis: ReportAnalysis) -> dict[str, tuple[str, str]]:
    """value(lower) -> (role, context)."""
    return {c.value.lower(): (c.role, c.context) for c in analysis.indicator_context}


def write_json(analysis: ReportAnalysis, out_dir: Path) -> Path:
    path = out_dir / "report.json"
    payload = {"review_banner": REVIEW_BANNER, **analysis.model_dump(mode="json")}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_csv(analysis: ReportAnalysis, out_dir: Path) -> Path:
    path = out_dir / "iocs.csv"
    ctx = _context_lookup(analysis)
    tech_conf = "n/a"  # confidence column applies to indicator context, default n/a
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["value", "type", "context", "confidence"])
        for ind in analysis.indicators:
            role, context = ctx.get(ind.value.lower(), ("", ""))
            cell = f"{role}: {context}".strip(": ").strip() if (role or context) else ""
            writer.writerow([ind.value, ind.type, cell, tech_conf])
    return path


def _md_ioc_table(analysis: ReportAnalysis) -> str:
    ctx = _context_lookup(analysis)
    by_type: dict[str, list] = {}
    for ind in analysis.indicators:
        by_type.setdefault(ind.type, []).append(ind)
    if not by_type:
        return "_No indicators were extracted._\n"

    parts: list[str] = []
    for itype in sorted(by_type):
        parts.append(f"#### {itype.upper()} ({len(by_type[itype])})\n")
        parts.append("| Value | Original | Role | Context |")
        parts.append("| --- | --- | --- | --- |")
        for ind in by_type[itype]:
            role, context = ctx.get(ind.value.lower(), ("", ""))
            orig = ind.defanged_original or ""
            parts.append(f"| `{ind.value}` | {orig} | {role} | {_esc(context)} |")
        parts.append("")
    return "\n".join(parts)


def write_markdown(analysis: ReportAnalysis, out_dir: Path) -> Path:
    path = out_dir / "report.md"
    a = analysis
    lines: list[str] = []

    lines.append(f"> ⚠️ **{REVIEW_BANNER}**\n")
    lines.append(f"# Threat Report Analysis — {a.title or 'Untitled'}\n")
    lines.append(f"- **Source:** {a.source_url_or_path}")
    if a.retrieved_at:
        lines.append(f"- **Retrieved:** {a.retrieved_at.isoformat()}")
    lines.append(f"- **Model:** {a.model}")
    lines.append("")

    lines.append("## Overview\n")
    lines.append(a.summary or "_No summary produced._")
    lines.append("")

    lines.append("## Threat Actors & Malware\n")
    lines.append(f"- **Threat actors:** {', '.join(a.threat_actors) or '_none stated_'}")
    lines.append(f"- **Malware / tools:** {', '.join(a.malware_families) or '_none stated_'}")
    lines.append(f"- **Targeted sectors:** {', '.join(a.targeting.sectors) or '_none stated_'}")
    lines.append(f"- **Targeted regions:** {', '.join(a.targeting.regions) or '_none stated_'}")
    lines.append("")

    lines.append("## ATT&CK Techniques\n")
    if a.techniques:
        lines.append("| ID | Name | Tactics | Confidence | Behavior | Evidence |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for t in a.techniques:
            ev = _esc(t.evidence)
            beh = _esc(t.behavior)
            lines.append(
                f"| {t.technique_id} | {t.name} | {', '.join(t.tactics)} | "
                f"{t.confidence} | {beh} | \"{ev}\" |"
            )
    else:
        lines.append("_No validated ATT&CK techniques._")
    lines.append("")

    lines.append("## Indicators of Compromise\n")
    lines.append(_md_ioc_table(a))

    lines.append("## Appendix — Rejected ATT&CK Mappings\n")
    if a.rejected_mappings:
        lines.append(
            "These technique IDs were proposed by the LLM but failed validation "
            "against the ATT&CK dataset (or lacked evidence) and were excluded:\n"
        )
        lines.append("| Proposed ID | Reason | Behavior |")
        lines.append("| --- | --- | --- |")
        for r in a.rejected_mappings:
            lines.append(f"| {r.technique_id} | {r.reason} | {_esc(r.behavior)} |")
    else:
        lines.append("_None._")
    lines.append("")

    if a.dropped_indicators:
        lines.append("## Appendix — Dropped LLM Indicator References\n")
        lines.append(
            "The LLM referenced these values that were NOT in the deterministically "
            "extracted list; they were dropped:\n"
        )
        for v in a.dropped_indicators:
            lines.append(f"- `{v}`")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def render_all(analysis: ReportAnalysis, out_dir: Path, formats: list[str] | None = None) -> list[Path]:
    """Write requested output files. formats subset of {json, md, csv}; default all."""
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = formats or ["json", "md", "csv"]
    written: list[Path] = []
    if "json" in formats:
        written.append(write_json(analysis, out_dir))
    if "md" in formats:
        written.append(write_markdown(analysis, out_dir))
    if "csv" in formats:
        written.append(write_csv(analysis, out_dir))
    return written
