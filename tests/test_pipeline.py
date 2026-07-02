"""Tests for the shared orchestration layer."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import ctiforge.analyze as analyze_mod
from ctiforge import pipeline

FIXTURE = Path(__file__).parent / "fixtures" / "sample_advisory.txt"

_FAKE_LLM_JSON = {
    "summary": "Sample.",
    "threat_actors": ["FANCY EXAMPLE"],
    "malware_families": [],
    "targeting": {"sectors": [], "regions": []},
    "techniques": [
        {
            "technique_id": "T1566",
            "behavior": "phishing",
            "evidence": "The actors gained initial access through spearphishing emails "
            "containing malicious attachments.",
            "confidence": "high",
        }
    ],
    "indicator_context": [
        {"value": "evil-c2.net", "role": "c2", "context": "C2 domain."}
    ],
}


def _mock_client():
    block = MagicMock()
    block.type = "text"
    block.text = json.dumps(_FAKE_LLM_JSON)
    msg = MagicMock()
    msg.content = [block]
    msg.stop_reason = "end_turn"
    client = MagicMock()
    client.messages.create.return_value = msg
    return client


def test_analyze_text_runs_pipeline(fake_index):
    text = FIXTURE.read_text(encoding="utf-8")
    with patch.object(analyze_mod, "_client", return_value=_mock_client()):
        result = pipeline.analyze_text(text, title="t", index=fake_index)
    assert [t.technique_id for t in result.techniques] == ["T1566"]
    assert any(i.type == "domain" and i.value == "evil-c2.net" for i in result.indicators)
    assert result.title == "t"


def test_analyze_source_reads_file(fake_index):
    with patch.object(analyze_mod, "_client", return_value=_mock_client()):
        result = pipeline.analyze_source(str(FIXTURE), index=fake_index)
    assert result.source_url_or_path.endswith("sample_advisory.txt")
    assert result.retrieved_at is not None


def test_get_index_is_cached():
    sentinel = object()
    with patch("ctiforge.pipeline.AttackIndex.load", return_value=sentinel) as load:
        pipeline._INDEX = None
        a = pipeline.get_index()
        b = pipeline.get_index()
        assert a is b is sentinel
        assert load.call_count == 1
    pipeline._INDEX = None
