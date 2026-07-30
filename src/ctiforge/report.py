"""Run-report serializer — emits the ``ctiforge.run/1`` artifact.

This is a pure reporting layer over state the pipeline already produced. It adds
no model calls and does not re-derive indicators or technique mappings.

Honesty note on provenance
--------------------------
Indicators are extracted deterministically, so each carries the name of the
extraction ``rule`` that fired plus its byte ``offset`` into the analyzed text.

Technique mappings in ctiforge come from the guarded LLM stage, **not** from a
keyword rule engine. Rather than dress LLM output up as a pattern match, each
technique's ``match`` field states the verbatim evidence sentence that the
mapping was required to quote from the source, and ``offset`` is where that
sentence actually occurs in the report text (``null`` if it could not be
located). ``provenance`` names the mechanism explicitly. Every ``validation``
value is the real result of the STIX check in :mod:`ctiforge.attack`.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Indicator, ReportAnalysis

SCHEMA = "ctiforge.run/1"
DECISIONS_SCHEMA = "ctiforge.decisions/1"

# Human-readable labels for the pipeline stages, in run order.
STAGE_LABELS = {
    "ingest": "Ingest",
    "extract": "Extract",
    "map": "Map TTPs",
    "validate": "Validate",
    "emit": "Emit",
}


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(started: datetime | None = None) -> str:
    """A stable-ish unique run id, e.g. ``cf-20260729-1402-a91c``."""
    started = started or datetime.now(UTC)
    return f"cf-{started.astimezone(UTC):%Y%m%d-%H%M}-{secrets.token_hex(2)}"


@dataclass
class Stage:
    """One pipeline stage's outcome."""

    id: str
    status: str = "ok"  # ok | warn | err
    duration_ms: int = 0
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": STAGE_LABELS.get(self.id, self.id.title()),
            "status": self.status,
            "duration_ms": int(self.duration_ms),
            "note": self.note,
        }


@dataclass
class LogEntry:
    ts: str
    level: str  # info | warn | err
    stage: str
    msg: str

    def to_json(self) -> dict[str, Any]:
        return {"ts": self.ts, "level": self.level, "stage": self.stage, "msg": self.msg}


@dataclass
class RunRecorder:
    """Collects stage timings and log lines while a run executes.

    The pipeline calls :meth:`stage` / :meth:`log`; nothing here influences
    extraction, mapping, or validation.
    """

    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    run_id: str = ""
    stages: list[Stage] = field(default_factory=list)
    log: list[LogEntry] = field(default_factory=list)
    source_name: str = ""
    source_sha256: str | None = None
    source_bytes: int | None = None
    source_pages: int | None = None

    def __post_init__(self) -> None:
        if not self.run_id:
            self.run_id = new_run_id(self.started_at)

    # -- collection -----------------------------------------------------
    def stage(self, stage_id: str, duration_ms: float, note: str = "",
              status: str = "ok") -> None:
        self.stages.append(
            Stage(id=stage_id, status=status, duration_ms=round(duration_ms), note=note)
        )

    def log_line(self, stage: str, msg: str, level: str = "info") -> None:
        self.log.append(
            LogEntry(ts=datetime.now(UTC).strftime("%H:%M:%S"), level=level,
                     stage=stage, msg=msg)
        )

    def set_source(self, name: str, *, path: Path | None = None,
                   text: str | None = None, pages: int | None = None) -> None:
        """Record source metadata; hashes the input file when one exists."""
        self.source_name = name
        self.source_pages = pages
        if path is not None and path.is_file():
            data = path.read_bytes()
            self.source_sha256 = hashlib.sha256(data).hexdigest()
            self.source_bytes = len(data)
        elif text is not None:
            raw = text.encode("utf-8")
            self.source_sha256 = hashlib.sha256(raw).hexdigest()
            self.source_bytes = len(raw)


def _find_offset(needle: str, haystack: str) -> int | None:
    """Byte offset of ``needle`` in ``haystack``, tolerant of whitespace runs."""
    if not needle:
        return None
    pos = haystack.find(needle)
    if pos >= 0:
        return pos
    # fall back to a whitespace-insensitive search
    pattern = r"\s+".join(re.escape(w) for w in needle.split())
    m = re.search(pattern, haystack, flags=re.IGNORECASE)
    return m.start() if m else None


def _techniques(analysis: ReportAnalysis, text: str) -> list[dict[str, Any]]:
    """Accepted + rejected mappings, with the real STIX validation outcome."""
    out: list[dict[str, Any]] = []
    for t in analysis.techniques:
        out.append({
            "id": t.technique_id,
            "name": t.name,
            "tactic": ", ".join(t.tactics) or "—",
            # Provenance is the required verbatim evidence quote, not a keyword.
            "match": f"evidence:“{t.evidence}”" if t.evidence else "—",
            "offset": _find_offset(t.evidence, text),
            "validation": "validated",
            "provenance": "llm-mapped, evidence-verified, STIX-validated",
            "confidence": t.confidence,
            "behavior": t.behavior,
        })
    for r in analysis.rejected_mappings:
        # "ambiguous" is reserved for mappings the guards could not resolve;
        # everything the STIX check refused is "rejected".
        ambiguous = "not found verbatim" in r.reason or "no verbatim" in r.reason
        out.append({
            "id": r.technique_id,
            "name": "—",
            "tactic": "—",
            "match": f"evidence:“{r.evidence}”" if r.evidence else "—",
            "offset": _find_offset(r.evidence, text),
            "validation": "ambiguous" if ambiguous else "rejected",
            "provenance": "llm-mapped, rejected by guard",
            "note": r.reason,
        })
    return out


def _indicators(analysis: ReportAnalysis) -> list[dict[str, Any]]:
    ctx = {c.value.lower(): c for c in analysis.indicator_context}

    def one(i: Indicator) -> dict[str, Any]:
        extra = ctx.get(i.value.lower())
        return {
            "type": i.type,
            "value": i.value,
            "rule": i.rule or "unknown_rule",
            "offset": i.offset,
            # Prefer the source snippet the rule matched in; fall back to the
            # LLM's one-line description of the indicator's role.
            "context": i.context or (extra.context if extra else ""),
            "defanged_original": i.defanged_original,
            "role": extra.role if extra else None,
        }

    return [one(i) for i in analysis.indicators]


def _review(analysis: ReportAnalysis) -> list[dict[str, Any]]:
    """Items the deterministic guards could not resolve — needs a human call.

    Always a list: an empty review queue serializes as ``[]``, never omitted.
    """
    items: list[dict[str, Any]] = []
    n = 0
    for r in analysis.rejected_mappings:
        n += 1
        items.append({
            "id": f"r{n}",
            "kind": "Rejected mapping",
            "ref": r.technique_id,
            "reason": (
                f"{r.reason.rstrip('.')}. Evidence offered: “{r.evidence}”"
                if r.evidence
                else r.reason
            ),
        })
    for value in analysis.dropped_indicators:
        n += 1
        items.append({
            "id": f"r{n}",
            "kind": "Dropped indicator",
            "ref": value,
            "reason": (
                "Referenced by the model but absent from the deterministic "
                "extraction, so it was dropped rather than reported."
            ),
        })
    return items


def build_run_report(
    analysis: ReportAnalysis,
    *,
    text: str = "",
    recorder: RunRecorder | None = None,
    attack_dataset: str = "enterprise-attack",
    attack_version: str | None = None,
    attack_retrieved: str | None = None,
    duration_ms: int | None = None,
) -> dict[str, Any]:
    """Build the ``ctiforge.run/1`` payload from completed run state."""
    rec = recorder or RunRecorder()
    started = rec.started_at
    if duration_ms is None:
        duration_ms = round((datetime.now(UTC) - started).total_seconds() * 1000)

    source: dict[str, Any] = {
        "name": rec.source_name or analysis.source_url_or_path or analysis.title or "—",
        "sha256": rec.source_sha256,
        "bytes": rec.source_bytes,
    }
    if rec.source_pages is not None:
        source["pages"] = rec.source_pages

    return {
        "schema": SCHEMA,
        "run_id": rec.run_id,
        "started_at": _iso(started),
        "duration_ms": int(duration_ms),
        "source": source,
        "mitre": {
            "dataset": attack_dataset,
            "version": attack_version,
            "retrieved": attack_retrieved,
        },
        "model": analysis.model,
        "stages": [s.to_json() for s in rec.stages],
        "review": _review(analysis),
        "techniques": _techniques(analysis, text),
        "indicators": _indicators(analysis),
        "log": [entry.to_json() for entry in rec.log],
    }


def write_run_report(payload: dict[str, Any], path: Path) -> Path:
    """Write the run report as pretty-printed JSON."""
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_decisions(path: Path) -> dict[str, str]:
    """Read a ``ctiforge.decisions/1`` file → ``{review_ref: verdict}``.

    Keyed by ``ref`` (the technique ID or indicator value) rather than the
    per-run ``review_id``, so verdicts survive across runs where ids shift.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read decisions file {path}: {exc}") from exc
    schema = str(data.get("schema", ""))
    if not schema.startswith("ctiforge.decisions/"):
        raise ValueError(
            f"{path} is not a ctiforge decisions artifact "
            f'(expected schema "ctiforge.decisions/1", got {schema!r}).'
        )
    out: dict[str, str] = {}
    for d in data.get("decisions") or []:
        if isinstance(d, dict) and d.get("ref") and d.get("verdict"):
            out[str(d["ref"])] = str(d["verdict"])
    return out


def apply_decisions(payload: dict[str, Any], decisions: dict[str, str]) -> dict[str, Any]:
    """Drop review items whose ``ref`` already has an accepted/rejected verdict.

    Deferred items stay in the queue. The techniques/indicators tables are left
    untouched — a human decision resolves the review, it does not rewrite what
    the pipeline observed.
    """
    if not decisions:
        return payload
    settled = {ref for ref, verdict in decisions.items()
               if verdict in ("accepted", "rejected")}
    kept, resolved = [], []
    for item in payload.get("review") or []:
        if item.get("ref") in settled:
            resolved.append(item)
        else:
            kept.append(item)
    payload["review"] = kept
    if resolved:
        payload["resolved_review"] = [
            {**item, "verdict": decisions[item["ref"]]} for item in resolved
        ]
    return payload
