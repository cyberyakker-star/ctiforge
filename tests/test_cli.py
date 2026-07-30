"""Tests for the CLI surface — especially the paths that need no API key."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

import ctiforge.analyze as analyze_mod
from ctiforge.cli import app

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample_advisory.txt")
runner = CliRunner()


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    """Default to a keyless environment — the state most users start in."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def _fake_index(fake_index):
    with patch("ctiforge.pipeline.get_index", return_value=fake_index):
        yield fake_index


def _llm(payload: dict) -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = json.dumps(payload)
    msg = MagicMock()
    msg.content = [block]
    msg.stop_reason = "end_turn"
    client = MagicMock()
    client.messages.create.return_value = msg
    return client


# --- extract: works with no key at all ------------------------------------

def test_extract_needs_no_api_key():
    r = runner.invoke(app, ["extract", FIXTURE])
    assert r.exit_code == 0, r.output
    assert "evil-c2.net" in r.output
    assert "6 indicators" in r.output


def test_extract_shows_rule_and_offset_for_every_row():
    r = runner.invoke(app, ["extract", FIXTURE, "--json"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert data["count"] == len(data["indicators"]) == 6
    for i in data["indicators"]:
        assert i["rule"], f"{i['value']} has no rule"
        assert isinstance(i["offset"], int), f"{i['value']} has no offset"


def test_extract_json_is_pure_json_no_banner():
    """The machine path must be parseable without stripping decoration."""
    r = runner.invoke(app, ["extract", FIXTURE, "--json"])
    json.loads(r.output)  # would raise if a banner leaked into stdout


def test_extract_writes_csv(tmp_path):
    r = runner.invoke(app, ["extract", FIXTURE, "-o", str(tmp_path)])
    assert r.exit_code == 0
    csv_path = tmp_path / "iocs.csv"
    assert csv_path.exists()
    assert "evil-c2.net" in csv_path.read_text()


def test_extract_bad_source_gives_actionable_hint():
    r = runner.invoke(app, ["extract", "/no/such/file.txt"])
    assert r.exit_code == 1
    assert "→" in r.output  # a next step, not just a complaint


# --- attack: keyless validation with scriptable exit codes ----------------

def test_attack_valid_id_exits_zero(_fake_index):
    r = runner.invoke(app, ["attack", "T1566"])
    assert r.exit_code == 0
    assert "Phishing" in r.output


def test_attack_invalid_id_exits_two(_fake_index):
    r = runner.invoke(app, ["attack", "T9999"])
    assert r.exit_code == 2
    assert "unknown technique" in r.output


def test_attack_json_shape(_fake_index):
    r = runner.invoke(app, ["attack", "T1566", "--json"])
    payload = json.loads(r.output)
    assert payload == {
        "technique_id": "T1566", "valid": True,
        "name": "Phishing", "tactics": ["initial-access"],
    }


# --- doctor ---------------------------------------------------------------

def test_doctor_runs_and_reports_missing_key():
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 0
    assert "Anthropic API key" in r.output
    assert "not set" in r.output
    assert "ANTHROPIC_API_KEY" in r.output  # tells you how to fix it


def test_doctor_sees_a_present_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    r = runner.invoke(app, ["doctor"])
    assert "set in the environment" in r.output


# --- analyze: never discards completed deterministic work -----------------

def test_analyze_without_key_keeps_deterministic_results(tmp_path, _fake_index):
    """The cardinal rule: work already done is never thrown away."""
    r = runner.invoke(app, ["analyze", FIXTURE, "-o", str(tmp_path),
                            "--report", str(tmp_path / "run.json")])
    assert r.exit_code == 0, r.output
    assert "deterministic results kept" in r.output
    # every artifact still written
    assert (tmp_path / "iocs.csv").exists()
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "run.json").exists()
    run = json.loads((tmp_path / "run.json").read_text())
    assert len(run["indicators"]) == 6
    assert all(i["rule"] and i["offset"] is not None for i in run["indicators"])
    # and it points the user at what the key would add
    assert "ANTHROPIC_API_KEY" in r.output


def test_analyze_with_key_reports_guard_verdict(tmp_path, monkeypatch, _fake_index):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    payload = {
        "summary": "s", "threat_actors": [], "malware_families": [],
        "targeting": {"sectors": [], "regions": []},
        "techniques": [
            {"technique_id": "T1566", "behavior": "phish",
             "evidence": "The actors gained initial access through spearphishing "
                         "emails containing malicious attachments.",
             "confidence": "high"},
            {"technique_id": "T9999", "behavior": "bogus",
             "evidence": "The malware communicated with command-and-control "
                         "infrastructure over HTTPS.", "confidence": "low"},
        ],
        "indicator_context": [],
    }
    with patch.object(analyze_mod, "_client", return_value=_llm(payload)):
        r = runner.invoke(app, ["analyze", FIXTURE, "-o", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert "1 validated" in r.output
    assert "1 rejected" in r.output


def test_analyze_rejects_unknown_format_with_usage_error(tmp_path):
    r = runner.invoke(app, ["analyze", FIXTURE, "--format", "xml"])
    assert r.exit_code == 2  # click usage error, not a generic failure


def test_decisions_requires_report(tmp_path):
    r = runner.invoke(app, ["analyze", FIXTURE, "--decisions", "d.json"])
    assert r.exit_code == 2
    assert "requires --report" in r.output


# --- help surface ---------------------------------------------------------

def test_bare_invocation_shows_help_not_an_error():
    r = runner.invoke(app, [])
    assert "extract" in r.output
    assert "Usage" in r.output


def test_extract_is_listed_before_analyze():
    """The keyless command should be the first one a newcomer sees."""
    out = runner.invoke(app, ["--help"]).output
    assert out.index("extract") < out.index("analyze")


# --- run-report viewer ----------------------------------------------------

def test_dashboard_path_points_at_a_packaged_file():
    r = runner.invoke(app, ["dashboard", "--path"])
    assert r.exit_code == 0
    page = Path(r.output.strip())
    assert page.is_file(), "run.html must ship inside the package"
    assert page.name == "run.html"


def test_run_viewer_makes_no_external_requests():
    """A report holds incident data: opening it must not phone anywhere."""
    page = Path(runner.invoke(app, ["dashboard", "--path"]).output.strip())
    html = page.read_text(encoding="utf-8")
    for offender in ("http://", "https://fonts.", "cdn.", "<script src="):
        if offender == "http://":
            continue
        assert offender not in html, f"external reference found: {offender}"
    # the only permitted absolute URL is the project link in the masthead
    externals = [
        line for line in html.splitlines()
        if "https://" in line and "github.com/cyberyakker-star" not in line
    ]
    assert not externals, f"unexpected external URLs: {externals}"


def test_non_verbose_run_has_no_raw_log_lines(tmp_path, monkeypatch, _fake_index):
    """The summary reports the guard results; raw log lines must not double up."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    payload = {
        "summary": "s", "threat_actors": [], "malware_families": [],
        "targeting": {"sectors": [], "regions": []},
        "techniques": [
            {"technique_id": "T9999", "behavior": "bogus",
             "evidence": "The malware communicated with command-and-control "
                         "infrastructure over HTTPS.", "confidence": "low"},
        ],
        "indicator_context": [
            {"value": "ghost.example", "role": "c2", "context": "invented"},
        ],
    }
    with patch.object(analyze_mod, "_client", return_value=_llm(payload)):
        r = runner.invoke(app, ["analyze", FIXTURE, "-o", str(tmp_path)])
    assert "WARNING ctiforge" not in r.output
    # but the facts are still reported, in the product's own voice
    assert "1 rejected" in r.output
    assert "dropped" in r.output
