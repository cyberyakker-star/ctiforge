"""Sigma rule drafting — STUB ONLY (planned for ctiforge v0.2).

This module is intentionally unimplemented. It sketches the interface for
turning the validated, evidence-backed ATT&CK technique mappings and extracted
indicators from a ``ReportAnalysis`` into draft Sigma detection rules.

Design intent (v0.2):
- Draft rules are ALWAYS labeled machine-generated and require analyst review,
  exactly like the rest of ctiforge's LLM-assisted output.
- Detections are grounded in the deterministically-extracted indicators and the
  validated ATT&CK techniques — never in free-form LLM speculation.
- Each generated rule carries provenance back to the source report and the
  verbatim evidence sentence that justified its technique mapping.

Sketch of the target schema (subject to change):

    SigmaRule:
        title: str
        id: str                 # deterministic UUID derived from source + logic
        status: str             # always "experimental" for machine drafts
        description: str
        references: list[str]   # source report URL/path
        tags: list[str]         # e.g. ["attack.t1059.001"]
        logsource: {category, product, service}
        detection: dict         # selection/condition mapping
        falsepositives: list[str]
        level: str              # low|medium|high

TODO(v0.2):
- Map indicator types -> appropriate Sigma logsource + field selections
  (e.g. domain/url -> proxy or dns; hash -> sysmon image/hash fields).
- Map validated technique IDs -> ATT&CK tags and detection heuristics.
- Emit valid Sigma YAML and validate it against the Sigma schema before write.
- Add a ``--sigma`` output format flag to the CLI and a ``rules/`` output dir.
- Never emit a rule without an evidence reference and a review banner.
"""

from __future__ import annotations

from .models import ReportAnalysis


def draft_sigma_rules(analysis: ReportAnalysis) -> list[dict]:  # pragma: no cover
    """Draft Sigma rules from a ReportAnalysis. Not implemented in v0.1."""
    raise NotImplementedError(
        "Sigma rule drafting is planned for ctiforge v0.2 and is not implemented yet."
    )
