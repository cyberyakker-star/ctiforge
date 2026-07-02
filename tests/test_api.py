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
