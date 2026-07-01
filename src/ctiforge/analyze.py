"""Stage 4 — LLM analysis with hallucination guards.

The LLM classifies and contextualizes; it is never the source of truth for
indicator values or ATT&CK IDs. Everything it returns is post-processed:
indicators not in the extracted list are dropped; technique IDs are validated
against the ATT&CK dataset and invalid ones are surfaced in ``rejected_mappings``.
"""

from __future__ import annotations

import json
import logging
import re

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
    """Call the model and parse a JSON object, retrying once with the error appended."""
    messages = [{"role": "user", "content": user}]
    last_err = ""
    for attempt in range(2):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=8192,
                system=system,
                messages=messages,
            )
        except Exception as exc:  # noqa: BLE001 - surface any SDK/network error loudly
            raise AnalyzeError(f"LLM request failed: {exc}") from exc

        if getattr(resp, "stop_reason", None) == "max_tokens":
            # Retrying with the same limit would truncate again — fail loudly.
            raise AnalyzeError(
                "LLM response was truncated at the output-token limit; results "
                "would be incomplete. The report may be too dense to analyze "
                "in one pass."
            )

        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        )
        if not text.strip():
            raise AnalyzeError("LLM returned an empty response (possible refusal).")

        try:
            parsed = json.loads(_strip_fences(text))
            if isinstance(parsed, dict):
                return parsed
            last_err = f"top-level JSON must be an object, got {type(parsed).__name__}"
        except json.JSONDecodeError as exc:
            last_err = str(exc)
        logger.warning("LLM returned unusable JSON (attempt %d): %s", attempt + 1, last_err)
        messages = [
            {"role": "user", "content": user},
            {"role": "assistant", "content": text},
            {
                "role": "user",
                "content": (
                    f"That was not a valid JSON object ({last_err}). Respond again "
                    "with ONLY the JSON object, no prose and no markdown fences."
                ),
            },
        ]
    raise AnalyzeError(f"LLM did not return a valid JSON object after retry: {last_err}")


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

    if attack_index is None:
        attack_index = AttackIndex.load()

    pre_rejected: list[RejectedMapping] = []
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
        # Validate technique IDs in the partials BEFORE the merge call: the
        # merge LLM may drop a bogus ID during consolidation, and a rejected
        # hallucination must be surfaced, never silently vanish.
        pre_rejected = _pre_validate_partials(partials, attack_index)
        merge_user = "PARTIAL ANALYSES TO MERGE:\n" + json.dumps(partials, ensure_ascii=False)
        raw = _call_json(client, resolved_model, MERGE_SYSTEM_PROMPT, merge_user)

    return _post_process(
        raw, indicators, attack_index, resolved_model, text, pre_rejected=pre_rejected
    )


def _pre_validate_partials(
    partials: list[dict], attack_index: AttackIndex
) -> list[RejectedMapping]:
    """Collect invalid technique IDs proposed in per-chunk partial analyses."""
    rejected: list[RejectedMapping] = []
    seen: set[str] = set()
    for partial in partials:
        if not isinstance(partial, dict):
            continue
        for item in partial.get("techniques") or []:
            if not isinstance(item, dict):
                continue
            tid = str(item.get("technique_id", "")).strip()
            result = attack_index.validate(tid)
            if result.valid or tid.upper() in seen:
                continue
            seen.add(tid.upper())
            rejected.append(
                RejectedMapping(
                    technique_id=tid or "(empty)",
                    reason=result.reason,
                    behavior=str(item.get("behavior", "")).strip(),
                    evidence=str(item.get("evidence", "")).strip(),
                )
            )
    return rejected


def _normalize_for_match(s: str) -> str:
    """Casefold and collapse whitespace so quotes can be matched tolerantly."""
    return re.sub(r"\s+", " ", s).casefold().strip().strip("\"'“”‘’")


def _str_list(value: object) -> list[str]:
    """Coerce an LLM-supplied value to a list of strings (defensively)."""
    if isinstance(value, list):
        return [str(x) for x in value]
    return []


def _post_process(
    raw: dict,
    indicators: list[Indicator],
    attack_index: AttackIndex,
    model: str,
    report_text: str,
    pre_rejected: list[RejectedMapping] | None = None,
) -> ReportAnalysis:
    """Apply the guards: drop invented indicators, validate every technique ID,
    and require each mapping's evidence to actually appear in the report."""
    allowed = {i.value.lower(): i.value for i in indicators}
    # Match evidence against both the raw text and a refanged copy, since the
    # model may normalize defanged indicators when quoting.
    from .extract import _refang_text

    norm_report = _normalize_for_match(report_text)
    norm_report_refanged = _normalize_for_match(_refang_text(report_text))

    def _grounded(evidence: str) -> bool:
        needle = _normalize_for_match(evidence)
        return bool(needle) and (needle in norm_report or needle in norm_report_refanged)

    def _items(key: str) -> list[dict]:
        value = raw.get(key)
        if not isinstance(value, list):
            if value is not None:
                logger.warning("LLM returned non-list for %r; ignoring.", key)
            return []
        out = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            else:
                logger.warning("Skipping malformed %s entry: %r", key, item)
        return out

    # Indicator context — drop anything not in the extracted list; dedupe by value.
    contexts: list[IndicatorContext] = []
    seen_values: set[str] = set()
    dropped: list[str] = []
    for item in _items("indicator_context"):
        value = str(item.get("value", "")).strip()
        canonical = allowed.get(value.lower())
        if canonical is None:
            logger.warning("Dropping LLM-invented indicator not in extracted list: %r", value)
            dropped.append(value)
            continue
        if canonical.lower() in seen_values:
            continue
        seen_values.add(canonical.lower())
        role = item.get("role", "unknown")
        if not isinstance(role, str) or role not in _VALID_ROLES:
            role = "unknown"
        contexts.append(
            IndicatorContext(
                value=canonical,
                role=role,
                context=str(item.get("context", "")).strip(),
            )
        )

    # Techniques — validate every ID against ATT&CK; require grounded evidence;
    # dedupe by technique ID (first occurrence wins).
    techniques: list[TechniqueMapping] = []
    rejected: list[RejectedMapping] = list(pre_rejected or [])
    seen_rejected: set[str] = {r.technique_id.upper() for r in rejected}
    seen_accepted: set[str] = set()
    def _reject(tid: str, reason: str, behavior: str, evidence: str) -> None:
        if tid.upper() in seen_rejected:
            return
        seen_rejected.add(tid.upper())
        rejected.append(
            RejectedMapping(
                technique_id=tid or "(empty)",
                reason=reason,
                behavior=behavior,
                evidence=evidence,
            )
        )

    for item in _items("techniques"):
        tid = str(item.get("technique_id", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
        behavior = str(item.get("behavior", "")).strip()
        result = attack_index.validate(tid)

        if not result.valid:
            _reject(tid, result.reason, behavior, evidence)
            continue
        if not evidence:
            _reject(tid, "no verbatim evidence sentence supplied", behavior, evidence)
            continue
        if not _grounded(evidence):
            logger.warning(
                "Rejecting %s: evidence sentence not found in report text.", tid
            )
            _reject(
                tid, "evidence sentence not found verbatim in the report",
                behavior, evidence,
            )
            continue
        if result.technique_id in seen_accepted:
            continue
        seen_accepted.add(result.technique_id)
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

    targeting_raw = raw.get("targeting")
    if not isinstance(targeting_raw, dict):
        targeting_raw = {}
    return ReportAnalysis(
        summary=str(raw.get("summary", "")).strip(),
        threat_actors=_str_list(raw.get("threat_actors")),
        malware_families=_str_list(raw.get("malware_families")),
        targeting=Targeting(
            sectors=_str_list(targeting_raw.get("sectors")),
            regions=_str_list(targeting_raw.get("regions")),
        ),
        techniques=techniques,
        indicator_context=contexts,
        rejected_mappings=rejected,
        dropped_indicators=dropped,
        model=model,
        indicators=indicators,
    )
