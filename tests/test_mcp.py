"""Tests for the MCP server tools (no network / no API key)."""

import json
from unittest.mock import MagicMock, patch

import pytest

import ctiforge.analyze as analyze_mod

mcp_server = pytest.importorskip("ctiforge.mcp_server")


def _mock_client(fake_json: dict) -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = json.dumps(fake_json)
    msg = MagicMock()
    msg.content = [block]
    msg.stop_reason = "end_turn"
    client = MagicMock()
    client.messages.create.return_value = msg
    return client


@pytest.fixture(autouse=True)
def _use_fake_index(fake_index):
    """Point the MCP tools at the synthetic ATT&CK index."""
    with patch("ctiforge.mcp_server.get_index", return_value=fake_index):
        yield


def test_extract_iocs_deterministic():
    result = mcp_server.extract_iocs("Beacon to evil[.]com and 8.8.8.8 observed.")
    values = {i["value"] for i in result["indicators"]}
    assert "evil.com" in values
    assert "8.8.8.8" in values
    assert result["count"] == len(result["indicators"])


def test_validate_attack_technique_valid():
    r = mcp_server.validate_attack_technique("T1566")
    assert r["valid"] is True
    assert r["name"] == "Phishing"


def test_validate_attack_technique_invalid():
    r = mcp_server.validate_attack_technique("T9999")
    assert r["valid"] is False
    assert "unknown" in r["reason"]


def test_analyze_report_wraps_pipeline(tmp_path):
    report = tmp_path / "r.txt"
    report.write_text(
        "The actors sent spearphishing emails. Beacon to evil.com seen. " + "filler " * 100,
        encoding="utf-8",
    )
    fake = {
        "summary": "s",
        "threat_actors": [],
        "malware_families": [],
        "targeting": {"sectors": [], "regions": []},
        "techniques": [],
        "indicator_context": [],
    }
    client = _mock_client(fake)
    with patch.object(analyze_mod, "_client", return_value=client):
        result = mcp_server.analyze_report(str(report))
    assert "review_banner" in result
    assert result["source_url_or_path"].endswith("r.txt")


def test_analyze_report_surfaces_ingest_error():
    with pytest.raises(ValueError, match="near-empty|reachable URL|existing file"):
        mcp_server.analyze_report("/nonexistent/path/to/nothing.txt")
