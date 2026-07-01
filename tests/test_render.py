"""Tests for post-processing guards and rendered outputs."""

import csv
import json

from ctiforge.analyze import _post_process
from ctiforge.models import Indicator
from ctiforge.render import render_all

# Report text the evidence sentences must be grounded in.
REPORT_TEXT = (
    "The actors sent spearphishing emails. "
    "The domain evil.com was used as command and control. "
    "The server 45.77.88.99 hosted the payload."
)


def _indicators():
    return [
        Indicator(value="evil.com", type="domain"),
        Indicator(value="45.77.88.99", type="ipv4"),
    ]


def test_hallucinated_technique_id_rejected(fake_index):
    raw = {
        "summary": "s",
        "techniques": [
            {
                "technique_id": "T9999",
                "behavior": "made up",
                "evidence": "The actors sent spearphishing emails.",
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
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    valid_ids = [t.technique_id for t in result.techniques]
    rejected_ids = [r.technique_id for r in result.rejected_mappings]
    assert "T1566" in valid_ids
    assert "T9999" not in valid_ids
    assert "T9999" in rejected_ids


def test_invented_indicator_dropped(fake_index):
    raw = {
        "summary": "s",
        "indicator_context": [
            {"value": "evil.com", "role": "c2", "context": "beacon"},
            {"value": "totally-invented.net", "role": "c2", "context": "hallucinated"},
        ],
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    kept = [c.value for c in result.indicator_context]
    assert "evil.com" in kept
    assert "totally-invented.net" not in kept
    assert "totally-invented.net" in result.dropped_indicators


def test_technique_without_evidence_rejected(fake_index):
    raw = {
        "techniques": [
            {"technique_id": "T1566", "behavior": "phishing", "evidence": ""}
        ]
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    assert not result.techniques
    assert result.rejected_mappings[0].technique_id == "T1566"


def test_fabricated_evidence_rejected(fake_index):
    """Evidence that does not appear in the report text must be rejected."""
    raw = {
        "techniques": [
            {
                "technique_id": "T1566",
                "behavior": "phishing",
                "evidence": "This sentence was never in the source report.",
                "confidence": "high",
            }
        ]
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    assert not result.techniques
    assert "not found verbatim" in result.rejected_mappings[0].reason


def test_evidence_matching_tolerates_case_and_whitespace(fake_index):
    raw = {
        "techniques": [
            {
                "technique_id": "T1566",
                "behavior": "phishing",
                "evidence": "the actors  sent\nspearphishing EMAILS.",
                "confidence": "high",
            }
        ]
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    assert [t.technique_id for t in result.techniques] == ["T1566"]


def test_duplicate_techniques_and_contexts_deduped(fake_index):
    raw = {
        "techniques": [
            {
                "technique_id": "T1566",
                "behavior": "phishing",
                "evidence": "The actors sent spearphishing emails.",
            },
            {
                "technique_id": "t1566",
                "behavior": "phishing again",
                "evidence": "The actors sent spearphishing emails.",
            },
        ],
        "indicator_context": [
            {"value": "evil.com", "role": "c2", "context": "first"},
            {"value": "EVIL.COM", "role": "c2", "context": "second"},
        ],
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    assert len(result.techniques) == 1
    assert len(result.indicator_context) == 1


def test_malformed_llm_shapes_do_not_crash(fake_index):
    """Structurally wrong (but valid) JSON must not raise raw exceptions."""
    raw = {
        "summary": "s",
        "threat_actors": "APT-STRING-NOT-LIST",
        "targeting": "not-a-dict",
        "techniques": ["just-a-string", {"technique_id": "T1566", "role": ["x"]}],
        "indicator_context": [
            "just-a-string",
            {"value": "evil.com", "role": ["c2"], "context": "list role"},
        ],
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    assert result.threat_actors == []  # string is not silently exploded into chars
    assert result.indicator_context[0].role == "unknown"


def test_pre_rejected_mappings_surface(fake_index):
    """Invalid IDs found in chunk partials must appear in rejected_mappings."""
    from ctiforge.analyze import _pre_validate_partials

    partials = [
        {"techniques": [{"technique_id": "T9999", "behavior": "bogus", "evidence": "x"}]},
        {"techniques": [{"technique_id": "T9999", "behavior": "bogus dup", "evidence": "x"}]},
    ]
    pre = _pre_validate_partials(partials, fake_index)
    assert len(pre) == 1  # deduped
    result = _post_process(
        {"summary": "s"}, _indicators(), fake_index, "test-model", REPORT_TEXT,
        pre_rejected=pre,
    )
    assert [r.technique_id for r in result.rejected_mappings] == ["T9999"]


def test_render_all_writes_three_files(tmp_path, fake_index):
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
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
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


def test_csv_context_preserves_colons(tmp_path, fake_index):
    """The role/context CSV cell must not strip legitimate ':' characters."""
    raw = {
        "indicator_context": [
            {"value": "evil.com", "role": "", "context": ":443 callback:"}
        ],
    }
    result = _post_process(raw, _indicators(), fake_index, "test-model", REPORT_TEXT)
    render_all(result, tmp_path, ["csv"])
    rows = list(csv.DictReader((tmp_path / "iocs.csv").read_text().splitlines()))
    row = next(r for r in rows if r["value"] == "evil.com")
    # empty role coerces to 'unknown'; the context's own colons must survive
    assert row["context"] == "unknown: :443 callback:"
