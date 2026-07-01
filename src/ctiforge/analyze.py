"""Stage 4 — LLM analysis with hallucination guards.

The LLM classifies and contextualizes; it is never the source of truth for
indicator values or ATT&CK IDs. Everything it returns is post-processed:
indicators not in the extracted list are dropped; technique IDs are validated
against the ATT&CK dataset and invalid ones are surfaced in ``rejected_mappings``.
"""

from __future__ import annotations

import json
import logging

from .attack import AttackIndex
from .config import CHUNK_THRESHOLD_CHARS, get_api_key, resolve_model
from .models import (
    Indicator,
    IndicatorContext,
    RejectedMapping,
    ReportAnalysis,
    Targeting,
    TechniqueMapping,
)

logger = logging.getLogger("ctiforge.analyze")

_VALID_ROLES = {"c2", "payload_delivery", "phishing", "exfiltration", "scanning", "unknown"}

SYSTEM_PROMPT = """\
You are a cyber threat intelligence analyst assisting with structured
extraction from a published threat report. You will receive: (1) the
report text, (2) a list of indicators ALREADY EXTRACTED from the report
by deterministic tooling.

Respond with ONLY a JSON object matching this schema — no prose, no
markdown fences:

{
  "summary": "3-5 sentence executive summary",
  "threat_actors": ["names/aliases explicitly stated in the report"],
  "malware_families": ["explicitly named families/tools"],
  "targeting": {"sectors": [], "regions": []},
  "techniques": [
    {
      "technique_id": "T1566.001",
      "behavior": "one-sentence description of the behavior in this report",
      "evidence": "verbatim sentence from the report supporting this mapping",
      "confidence": "high|medium|low"
    }
  ],
  "indicator_context": [
    {
      "value": "must be copied exactly from the provided indicator list",
      "role": "c2|payload_delivery|phishing|exfiltration|scanning|unknown",
      "context": "one sentence on how the report describes this indicator"
    }
  ]
}

Hard rules:
- Use ONLY information present in the report text. Do not add knowledge
  from outside the report, even if you recognize the campaign.
- Never invent, modify, or complete indicator values. Only classify
  values from the provided list. Omit any you cannot find context for.
- Only map ATT&CK techniques you can support with a verbatim evidence
  sentence. Fewer, well-evidenced mappings beat many speculative ones.
- If the text is not a threat report, return the schema with empty
  arrays and state why in "summary".
"""

MERGE_SYSTEM_PROMPT = """\
You are consolidating several partial JSON analyses of the SAME threat report
(each covered a different chunk). Merge them into ONE JSON object using the
exact same schema. Deduplicate threat_actors, malware_families, targeting,
techniques (by technique_id, keeping the best-evidenced), and indicator_context
(by value). Write a single coherent 3-5 sentence summary. Respond with ONLY the
JSON object — no prose, no markdown fences.
"""


class AnalyzeError(Exception):
    """Raised when the LLM analysis cannot be completed."""


def _client():
    api_key = get_api_key()
    if not api_key:
        raise AnalyzeError(
            "ANTHROPIC_API_KEY is not set. Export your Anthropic API key "
            "(it is read from the environment only, never a config file)."
        )
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover
        raise AnalyzeError("The 'anthropic' package is not installed.") from exc
    return anthropic.Anthropic(api_key=api_key)


def _chunk_text(text: str, limit: int) -> list[str]:
    if len(text) <= limit:
        return [text]
    paragraphs = text.split("\n\n")
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if current and len(current) + len(para) + 2 > limit:
            chunks.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        chunks.append(current)
    return chunks


def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1] if "\n" in raw else raw
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]
    return raw.strip()


def _call_json(client, model: str, system: str, user: str) -> dict:
    """Call the model and parse JSON, retrying once with the error appended."""
    messages = [{"role": "user", "content": user}]
    last_err = ""
    for attempt in range(2):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=4096,
                system=system,
                messages=messages,
            )
        except Exception as exc:  # noqa: BLE001 - surface any SDK/network error loudly
            raise AnalyzeError(f"LLM request failed: {exc}") from exc

        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        )
        if not text.strip():
            raise AnalyzeError("LLM returned an empty response (possible refusal).")

        try:
            return json.loads(_strip_fences(text))
        except json.JSONDecodeError as exc:
            last_err = str(exc)
            logger.warning("LLM returned invalid JSON (attempt %d): %s", attempt + 1, exc)
            messages = [
                {"role": "user", "content": user},
                {"role": "assistant", "content": text},
                {
                    "role": "user",
                    "content": (
                        f"That was not valid JSON ({last_err}). Respond again with "
                        "ONLY the JSON object, no prose and no markdown fences."
                    ),
                },
            ]
    raise AnalyzeError(f"LLM did not return valid JSON after retry: {last_err}")


def _build_user_prompt(text: str, indicators: list[Indicator]) -> str:
    listing = "\n".join(f"- [{i.type}] {i.value}" for i in indicators) or "(none extracted)"
    return (
        f"REPORT TEXT:\n{text}\n\n"
        f"INDICATORS ALREADY EXTRACTED (classify only these; do not invent others):\n"
        f"{listing}"
    )


def analyze(
    text: str,
    indicators: list[Indicator],
    model: str | None = None,
    attack_index: AttackIndex | None = None,
) -> ReportAnalysis:
    """Run the LLM analysis and apply all hallucination guards."""
    resolved_model = resolve_model(model)
    client = _client()

    chunks = _chunk_text(text, CHUNK_THRESHOLD_CHARS)
    if len(chunks) == 1:
        raw = _call_json(
            client, resolved_model, SYSTEM_PROMPT, _build_user_prompt(chunks[0], indicators)
        )
    else:
        logger.info("Report is large: analyzing %d chunks then merging.", len(chunks))
        partials = [
            _call_json(
                client, resolved_model, SYSTEM_PROMPT, _build_user_prompt(c, indicators)
            )
            for c in chunks
        ]
        merge_user = "PARTIAL ANALYSES TO MERGE:\n" + json.dumps(partials, ensure_ascii=False)
        raw = _call_json(client, resolved_model, MERGE_SYSTEM_PROMPT, merge_user)

    if attack_index is None:
        attack_index = AttackIndex.load()

    return _post_process(raw, indicators, attack_index, resolved_model)


def _post_process(
    raw: dict,
    indicators: list[Indicator],
    attack_index: AttackIndex,
    model: str,
) -> ReportAnalysis:
    """Apply the guards: drop invented indicators, validate every technique ID."""
    allowed = {i.value.lower(): i.value for i in indicators}

    # Indicator context — drop anything not in the extracted list.
    contexts: list[IndicatorContext] = []
    dropped: list[str] = []
    for item in raw.get("indicator_context") or []:
        value = str(item.get("value", "")).strip()
        canonical = allowed.get(value.lower())
        if canonical is None:
            logger.warning("Dropping LLM-invented indicator not in extracted list: %r", value)
            dropped.append(value)
            continue
        role = item.get("role", "unknown")
        if role not in _VALID_ROLES:
            role = "unknown"
        contexts.append(
            IndicatorContext(
                value=canonical,
                role=role,
                context=str(item.get("context", "")).strip(),
            )
        )

    # Techniques — validate every ID against ATT&CK.
    techniques: list[TechniqueMapping] = []
    rejected: list[RejectedMapping] = []
    for item in raw.get("techniques") or []:
        tid = str(item.get("technique_id", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
        behavior = str(item.get("behavior", "")).strip()
        result = attack_index.validate(tid)
        if not result.valid:
            rejected.append(
                RejectedMapping(
                    technique_id=tid or "(empty)",
                    reason=result.reason,
                    behavior=behavior,
                    evidence=evidence,
                )
            )
            continue
        if not evidence:
            rejected.append(
                RejectedMapping(
                    technique_id=tid,
                    reason="no verbatim evidence sentence supplied",
                    behavior=behavior,
                )
            )
            continue
        conf = item.get("confidence", "low")
        techniques.append(
            TechniqueMapping(
                technique_id=result.technique_id,
                name=result.name,
                tactics=result.tactics,
                behavior=behavior,
                evidence=evidence,
                confidence=conf if conf in ("high", "medium", "low") else "low",
            )
        )

    targeting_raw = raw.get("targeting") or {}
    return ReportAnalysis(
        summary=str(raw.get("summary", "")).strip(),
        threat_actors=[str(a) for a in (raw.get("threat_actors") or [])],
        malware_families=[str(m) for m in (raw.get("malware_families") or [])],
        targeting=Targeting(
            sectors=[str(s) for s in (targeting_raw.get("sectors") or [])],
            regions=[str(r) for r in (targeting_raw.get("regions") or [])],
        ),
        techniques=techniques,
        indicator_context=contexts,
        rejected_mappings=rejected,
        dropped_indicators=dropped,
        model=model,
        indicators=indicators,
    )
