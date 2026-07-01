"""Tests for post-processing guards and rendered outputs."""

import csv
import json

from ctiforge.analyze import _post_process
from ctiforge.attack import AttackIndex
from ctiforge.models import Indicator
from ctiforge.render import render_all

from .test_attack import _FAKE_STIX


def _index():
    return AttackIndex(AttackIndex._build_index(_FAKE_STIX))


def _indicators():
    return [
        Indicator(value="evil.com", type="domain"),
        Indicator(value="45.77.88.99", type="ipv4"),
    ]


def test_hallucinated_technique_id_rejected():
    raw = {
        "summary": "s",
        "techniques": [
            {
                "technique_id": "T9999",
                "behavior": "made up",
                "evidence": "some sentence",
                "confidence": "high",
            },
            {
                "technique_id": "T1566",
                "behavior": "phishing",
                "evidence": "The actors sent spearphishing emails.",
                "confidence": "high",
            },
        ],
    }
    result = _post_process(raw, _indicators(), _index(), "test-model")
    valid_ids = [t.technique_id for t in result.techniques]
    rejected_ids = [r.technique_id for r in result.rejected_mappings]
    assert "T1566" in valid_ids
    assert "T9999" not in valid_ids
    assert "T9999" in rejected_ids


def test_invented_indicator_dropped():
    raw = {
        "summary": "s",
        "indicator_context": [
            {"value": "evil.com", "role": "c2", "context": "beacon"},
            {"value": "totally-invented.net", "role": "c2", "context": "hallucinated"},
        ],
    }
    result = _post_process(raw, _indicators(), _index(), "test-model")
    kept = [c.value for c in result.indicator_context]
    assert "evil.com" in kept
    assert "totally-invented.net" not in kept
    assert "totally-invented.net" in result.dropped_indicators


def test_technique_without_evidence_rejected():
    raw = {
        "techniques": [
            {"technique_id": "T1566", "behavior": "phishing", "evidence": ""}
        ]
    }
    result = _post_process(raw, _indicators(), _index(), "test-model")
    assert not result.techniques
    assert result.rejected_mappings[0].technique_id == "T1566"


def test_render_all_writes_three_files(tmp_path):
    raw = {
        "summary": "An example threat report.",
        "threat_actors": ["FANCY EXAMPLE"],
        "indicator_context": [{"value": "evil.com", "role": "c2", "context": "c2 domain"}],
        "techniques": [
            {
                "technique_id": "T1566",
                "behavior": "phishing",
                "evidence": "The actors sent spearphishing emails.",
                "confidence": "high",
            }
        ],
    }
    result = _post_process(raw, _indicators(), _index(), "test-model")
    written = render_all(result, tmp_path)
    names = {p.name for p in written}
    assert names == {"report.json", "report.md", "iocs.csv"}

    data = json.loads((tmp_path / "report.json").read_text())
    assert data["review_banner"]
    assert data["threat_actors"] == ["FANCY EXAMPLE"]

    md = (tmp_path / "report.md").read_text()
    assert "REQUIRES HUMAN REVIEW" in md
    assert "T1566" in md

    rows = list(csv.DictReader((tmp_path / "iocs.csv").read_text().splitlines()))
    assert {"value", "type", "context", "confidence"} == set(rows[0].keys())
    assert any(r["value"] == "evil.com" for r in rows)
