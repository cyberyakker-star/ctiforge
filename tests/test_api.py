"""Tests for the FastAPI REST API + web UI (no network / no API key)."""

import json
from unittest.mock import MagicMock, patch

import pytest

import ctiforge.analyze as analyze_mod

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from ctiforge.api import app  # noqa: E402


@pytest.fixture
def client(fake_index):
    with patch("ctiforge.api.get_index", return_value=fake_index):
        yield TestClient(app)


def test_index_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ctiforge" in r.text.lower()
    assert "IOC Triage Dashboard" in r.text


def test_demo_endpoint_renders_full_dashboard(client):
    """The bundled demo powers the dashboard with no API key."""
    r = client.get("/api/demo")
    assert r.status_code == 200
    d = r.json()
    a = d["analysis"]
    assert a["review_banner"]
    # rich enough to populate the matrix: multiple techniques across many tactics
    assert len(a["techniques"]) >= 8
    tactics = {t for x in a["techniques"] for t in x["tactics"]}
    assert len(tactics) >= 8
    # every demo technique is a real ATT&CK ID with a name and evidence
    for t in a["techniques"]:
        assert t["technique_id"].startswith("T")
        assert t["name"] and t["evidence"]
    # guards are demonstrated
    assert a["rejected_mappings"] and a["dropped_indicators"]
    # download artifacts bundled
    assert "review_banner" in d["json"]
    assert "value,type,context,confidence" in d["csv"]
    assert "REQUIRES HUMAN REVIEW" in d["markdown"]


def test_demo_indicator_context_values_are_in_indicators(client):
    """Guard invariant holds in the sample: no context value is invented."""
    a = client.get("/api/demo").json()["analysis"]
    values = {i["value"].lower() for i in a["indicators"]}
    for c in a["indicator_context"]:
        assert c["value"].lower() in values


def test_extract_endpoint(client):
    r = client.post("/api/extract", json={"text": "Contact evil[.]com and 8.8.8.8 now."})
    assert r.status_code == 200
    values = {i["value"] for i in r.json()["indicators"]}
    assert {"evil.com", "8.8.8.8"} <= values


def test_attack_endpoint(client):
    assert client.get("/api/attack/T1566").json()["valid"] is True
    assert client.get("/api/attack/T9999").json()["valid"] is False


def test_analyze_requires_exactly_one_input(client):
    assert client.post("/api/analyze", json={}).status_code == 422
    assert client.post("/api/analyze", json={"source": "a", "text": "b"}).status_code == 422


def test_analyze_text_endpoint(client):
    fake = {
        "summary": "s",
        "threat_actors": [],
        "malware_families": [],
        "targeting": {"sectors": [], "regions": []},
        "techniques": [
            {
                "technique_id": "T1566",
                "behavior": "phishing",
                "evidence": "The actors sent spearphishing emails.",
                "confidence": "high",
            }
        ],
        "indicator_context": [],
    }
    block = MagicMock()
    block.type = "text"
    block.text = json.dumps(fake)
    msg = MagicMock()
    msg.content = [block]
    msg.stop_reason = "end_turn"
    llm = MagicMock()
    llm.messages.create.return_value = msg
    body = {"text": "The actors sent spearphishing emails. Beacon to evil.com. " + "x " * 100}
    with patch.object(analyze_mod, "_client", return_value=llm):
        r = client.post("/api/analyze", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["analysis"]["review_banner"]
    assert [t["technique_id"] for t in data["analysis"]["techniques"]] == ["T1566"]
    # rendered artifacts are bundled for downloads
    assert "review_banner" in data["json"]
    assert "value,type,context,confidence" in data["csv"]
    assert "REQUIRES HUMAN REVIEW" in data["markdown"]


def test_analyze_bad_source_returns_422(client):
    r = client.post("/api/analyze", json={"source": "/no/such/file.txt"})
    assert r.status_code == 422
