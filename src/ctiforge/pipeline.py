"""Shared orchestration layer over the ctiforge stages.

The CLI, MCP server, and REST API all sit on top of these functions so the
ingest → extract → validate → analyze sequence lives in exactly one place.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from .analyze import analyze as _run_analysis
from .attack import AttackIndex
from .extract import extract_indicators
from .ingest import ingest
from .models import Indicator, ReportAnalysis

logger = logging.getLogger("ctiforge.pipeline")

_INDEX: AttackIndex | None = None


def get_index(force_refresh: bool = False) -> AttackIndex:
    """Return a process-wide cached ATT&CK index (built at most once per run)."""
    global _INDEX
    if _INDEX is None or force_refresh:
        _INDEX = AttackIndex.load(force_refresh=force_refresh)
    return _INDEX


def analyze_text(
    text: str,
    *,
    title: str = "pasted text",
    source_url_or_path: str = "(inline text)",
    include_private: bool = False,
    model: str | None = None,
    index: AttackIndex | None = None,
    indicators: list[Indicator] | None = None,
) -> ReportAnalysis:
    """Run the full analysis pipeline over report text.

    ``indicators`` may be supplied by a caller that already extracted them
    (e.g. the CLI, which prints the count first) to avoid re-extraction.
    """
    if indicators is None:
        indicators = extract_indicators(text, include_private=include_private)
    analysis = _run_analysis(
        text, indicators, model=model, attack_index=index or get_index()
    )
    analysis.title = title
    analysis.source_url_or_path = source_url_or_path
    analysis.retrieved_at = datetime.now(UTC)
    return analysis


def analyze_source(
    source: str,
    *,
    include_private: bool = False,
    model: str | None = None,
    index: AttackIndex | None = None,
) -> ReportAnalysis:
    """Ingest a URL / PDF / text file and run the full analysis pipeline."""
    report = ingest(source)
    analysis = analyze_text(
        report.text,
        title=report.title,
        source_url_or_path=report.source_url_or_path,
        include_private=include_private,
        model=model,
        index=index,
    )
    analysis.retrieved_at = report.retrieved_at
    return analysis
