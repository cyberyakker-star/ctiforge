"""MCP server exposing ctiforge to AI agents.

Three tools, deliberately split by cost and trust:

* ``extract_iocs`` — deterministic, no API key, no network, no cost. Cannot
  hallucinate: it returns exactly what the regex/validation layer found.
* ``validate_attack_technique`` — instant ATT&CK ID check against the cached
  official dataset.
* ``analyze_report`` — the full pipeline including the LLM analysis. Requires
  ``ANTHROPIC_API_KEY`` and makes a paid model call.

Run with the ``ctiforge-mcp`` console script (stdio transport).
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .analyze import AnalyzeError
from .attack import AttackError
from .config import REVIEW_BANNER
from .extract import extract_indicators
from .ingest import IngestError
from .pipeline import analyze_source, get_index

mcp = FastMCP("ctiforge")


@mcp.tool()
def extract_iocs(text: str, include_private: bool = False) -> dict[str, Any]:
    """Extract indicators of compromise from report text — deterministically.

    No API key, no network calls, no cost. Indicators are found by regex and
    validation only, so this tool cannot hallucinate values. Use it to pull
    IPs, domains, URLs, hashes and emails out of any pasted text. Defanged
    forms (hxxp://, evil[.]com, 1.2.3[.]4) are refanged automatically.

    Args:
        text: The report text to scan.
        include_private: Keep private/reserved IP addresses (dropped by default).
    """
    indicators = extract_indicators(text, include_private=include_private)
    return {
        "count": len(indicators),
        "indicators": [i.model_dump() for i in indicators],
    }


@mcp.tool()
def validate_attack_technique(technique_id: str) -> dict[str, Any]:
    """Validate a MITRE ATT&CK technique ID against the official dataset.

    No API key needed. Rejects unknown, malformed, deprecated and revoked IDs.
    Accepts sub-technique format (e.g. T1566.001).

    Args:
        technique_id: The technique ID to check, e.g. "T1566" or "T1059.001".
    """
    result = get_index().validate(technique_id)
    if result.valid:
        return {
            "valid": True,
            "technique_id": result.technique_id,
            "name": result.name,
            "tactics": result.tactics,
        }
    return {
        "valid": False,
        "technique_id": result.technique_id,
        "reason": result.reason,
    }


@mcp.tool()
def analyze_report(
    source: str, include_private: bool = False, model: str | None = None
) -> dict[str, Any]:
    """Analyze a full threat report into structured, validated intelligence.

    COST/LATENCY: this makes a paid LLM call (requires the ANTHROPIC_API_KEY
    environment variable) and can take 10-60 seconds. Prefer `extract_iocs`
    when you only need indicators.

    The result is machine-drafted and requires human review: indicators are
    extracted deterministically, but the summary, ATT&CK mappings and
    indicator context are LLM-generated. Every ATT&CK ID is validated and
    every mapping's evidence is checked against the report text; rejected
    mappings and dropped (invented) indicators are surfaced, not hidden.

    Args:
        source: A URL, PDF path, or text/markdown file path to analyze.
        include_private: Keep private/reserved IP addresses (dropped by default).
        model: Override the Anthropic model (defaults to CTIFORGE_MODEL / built-in).
    """
    try:
        analysis = analyze_source(
            source, include_private=include_private, model=model, index=get_index()
        )
    except (IngestError, AttackError, AnalyzeError) as exc:
        # Surface a clean, actionable message instead of a stack trace.
        raise ValueError(str(exc)) from exc
    return {"review_banner": REVIEW_BANNER, **analysis.model_dump(mode="json")}


def main() -> None:
    """Console entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
