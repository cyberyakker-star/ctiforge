"""Tests for the ctiforge.run/1 run-report serializer."""

import json

import pytest

from ctiforge.models import (
    Indicator,
    IndicatorContext,
    RejectedMapping,
    ReportAnalysis,
    TechniqueMapping,
)
from ctiforge.report import (
    SCHEMA,
    RunRecorder,
    apply_decisions,
    build_run_report,
    load_decisions,
    new_run_id,
    write_run_report,
)

REPORT_TEXT = (
    "The actors sent spearphishing emails to staff. "
    "Beacon traffic reached evil-c2.net over HTTPS. "
    "The dropper hash was 44d88612fea8a8f36de82e1278abb02f."
)

EVIDENCE = "The actors sent spearphishing emails to staff."


def _analysis() -> ReportAnalysis:
    return ReportAnalysis(
        summary="Summary.",
        threat_actors=["FANCY EXAMPLE"],
        techniques=[
            TechniqueMapping(
                technique_id="T1566",
                name="Phishing",
                tactics=["initial-access"],
                behavior="phishing",
                evidence=EVIDENCE,
                confidence="high",
            )
        ],
        rejected_mappings=[
            RejectedMapping(
                technique_id="T9999",
                reason="unknown technique ID (not present in ATT&CK enterprise)",
                behavior="bogus",
                evidence="Beacon traffic reached evil-c2.net over HTTPS.",
            ),
            RejectedMapping(
                technique_id="T1041",
                reason="evidence sentence not found verbatim in the report",
                behavior="fabricated",
                evidence="This never appeared in the source.",
            ),
        ],
        dropped_indicators=["invented.example"],
        indicator_context=[
            IndicatorContext(value="evil-c2.net", role="c2", context="C2 domain.")
        ],
        indicators=[
            Indicator(
                value="evil-c2.net", type="domain", rule="domain_plausible_tld",
                offset=78, context="Beacon traffic reached evil-c2.net over HTTPS.",
            ),
            Indicator(
                value="44d88612fea8a8f36de82e1278abb02f", type="md5",
                rule="hash_md5", offset=124, context="The dropper hash was ...",
            ),
        ],
        model="test-model",
    )


def _recorder() -> RunRecorder:
    rec = RunRecorder()
    rec.set_source("advisory.txt", text=REPORT_TEXT)
    rec.stage("ingest", 120.4, "1,000 chars")
    rec.stage("extract", 40.0, "2 indicators · 2 rules")
    rec.log_line("extract", "2 indicators, 0 model calls")
    rec.log_line("validate", "T9999 rejected", "err")
    return rec


def _payload(analysis=None, rec=None):
    return build_run_report(
        analysis or _analysis(),
        text=REPORT_TEXT,
        recorder=rec or _recorder(),
        attack_version="18.0",
        attack_retrieved="2026-07-02",
    )


# --- schema completeness --------------------------------------------------

def test_schema_top_level_completeness():
    p = _payload()
    assert p["schema"] == SCHEMA
    for key in (
        "run_id", "started_at", "duration_ms", "source", "mitre",
        "stages", "review", "techniques", "indicators", "log",
    ):
        assert key in p, f"missing top-level key: {key}"
    assert p["started_at"].endswith("Z")
    assert isinstance(p["duration_ms"], int)


def test_source_and_mitre_blocks():
    p = _payload()
    assert p["source"]["name"] == "advisory.txt"
    assert len(p["source"]["sha256"]) == 64
    assert p["source"]["bytes"] == len(REPORT_TEXT.encode())
    assert p["mitre"] == {
        "dataset": "enterprise-attack", "version": "18.0", "retrieved": "2026-07-02",
    }


def test_stage_entries_have_required_fields():
    p = _payload()
    assert [s["id"] for s in p["stages"]] == ["ingest", "extract"]
    for s in p["stages"]:
        assert set(s) == {"id", "label", "status", "duration_ms", "note"}
        assert s["status"] in ("ok", "warn", "err")
        assert isinstance(s["duration_ms"], int)
    assert p["stages"][0]["label"] == "Ingest"


def test_log_entries_have_required_fields():
    p = _payload()
    assert p["log"]
    for entry in p["log"]:
        assert set(entry) == {"ts", "level", "stage", "msg"}
        assert entry["level"] in ("info", "warn", "err")


def test_run_id_is_stable_shape():
    rid = new_run_id()
    assert rid.startswith("cf-")
    assert len(rid.split("-")) == 4


# --- provenance (brief: never emit an artifact without rule/offset) -------

def test_every_indicator_has_rule_and_offset():
    p = _payload()
    assert p["indicators"]
    for i in p["indicators"]:
        assert i["rule"] and i["rule"] != "unknown_rule"
        assert isinstance(i["offset"], int)
        assert i["context"]


def test_technique_provenance_quotes_evidence_and_locates_it():
    p = _payload()
    validated = [t for t in p["techniques"] if t["validation"] == "validated"]
    assert len(validated) == 1
    t = validated[0]
    assert EVIDENCE in t["match"]
    # offset points at the evidence sentence inside the report text
    assert REPORT_TEXT[t["offset"]:].startswith(EVIDENCE)
    # provenance is labelled honestly, not as a keyword rule
    assert "llm-mapped" in t["provenance"]


# --- correct validation values --------------------------------------------

def test_validation_values_reflect_the_real_stix_check():
    p = _payload()
    by_id = {t["id"]: t for t in p["techniques"]}
    assert by_id["T1566"]["validation"] == "validated"
    # unknown ID -> rejected, with the reason carried in note
    assert by_id["T9999"]["validation"] == "rejected"
    assert "not present in ATT&CK" in by_id["T9999"]["note"]
    # guard could not verify the quote -> ambiguous, never silently passed
    assert by_id["T1041"]["validation"] == "ambiguous"
    assert by_id["T1041"]["note"]
    assert all(t["validation"] in ("validated", "rejected", "ambiguous")
               for t in p["techniques"])


def test_unvalidated_techniques_always_carry_a_note():
    p = _payload()
    for t in p["techniques"]:
        if t["validation"] != "validated":
            assert t.get("note"), f"{t['id']} lacks a note"


# --- review queue ---------------------------------------------------------

def test_review_holds_rejected_and_dropped_items():
    p = _payload()
    refs = {r["ref"] for r in p["review"]}
    assert {"T9999", "T1041", "invented.example"} <= refs
    for r in p["review"]:
        assert set(r) == {"id", "kind", "ref", "reason"}


def test_review_reason_attaches_the_offered_evidence_readably():
    """The README features this text verbatim; keep it a clean sentence."""
    p = _payload()
    item = next(r for r in p["review"] if r["ref"] == "T1041")
    assert item["reason"] == (
        "evidence sentence not found verbatim in the report. "
        "Evidence offered: “This never appeared in the source.”"
    )


def test_empty_review_serializes_as_empty_list_not_omitted():
    clean = ReportAnalysis(
        summary="Nothing to review.",
        techniques=[
            TechniqueMapping(technique_id="T1566", name="Phishing", evidence=EVIDENCE)
        ],
        indicators=[
            Indicator(value="evil-c2.net", type="domain",
                      rule="domain_plausible_tld", offset=78, context="ctx")
        ],
    )
    p = _payload(analysis=clean)
    assert "review" in p
    assert p["review"] == []
    # and it survives a JSON round-trip as [] rather than disappearing
    assert json.loads(json.dumps(p))["review"] == []


# --- file writing ---------------------------------------------------------

def test_write_run_report_round_trips(tmp_path):
    p = _payload()
    out = write_run_report(p, tmp_path / "nested" / "run.json")
    assert out.exists()
    loaded = json.loads(out.read_text())
    assert loaded["schema"] == SCHEMA
    assert loaded["review"] == p["review"]


# --- decisions round-trip -------------------------------------------------

def test_load_and_apply_decisions_clears_settled_items(tmp_path):
    d = tmp_path / "decisions.json"
    d.write_text(json.dumps({
        "schema": "ctiforge.decisions/1",
        "run_id": "cf-x",
        "decisions": [
            {"review_id": "r1", "ref": "T9999", "verdict": "rejected"},
            {"review_id": "r3", "ref": "invented.example", "verdict": "deferred"},
        ],
    }))
    verdicts = load_decisions(d)
    assert verdicts == {"T9999": "rejected", "invented.example": "deferred"}

    p = apply_decisions(_payload(), verdicts)
    refs = {r["ref"] for r in p["review"]}
    assert "T9999" not in refs          # settled -> out of the queue
    assert "invented.example" in refs   # deferred -> still needs a human
    assert p["resolved_review"][0]["verdict"] == "rejected"


def test_load_decisions_rejects_wrong_schema(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "something/else", "decisions": []}))
    with pytest.raises(ValueError, match="not a ctiforge decisions artifact"):
        load_decisions(bad)
