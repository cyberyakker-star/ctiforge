"""Tests for the ATT&CK index and technique validation (no network required)."""

from ctiforge.attack import AttackIndex

# A tiny synthetic STIX-shaped bundle so tests never hit the network.
_FAKE_STIX = {
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Phishing",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Spearphishing Attachment",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.001"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Deprecated Thing",
            "x_mitre_deprecated": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1000"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Thing",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1001"}
            ],
        },
    ]
}


def _index():
    return AttackIndex(AttackIndex._build_index(_FAKE_STIX))


def test_valid_technique():
    r = _index().validate("T1566")
    assert r.valid
    assert r.name == "Phishing"
    assert "initial-access" in r.tactics


def test_valid_subtechnique():
    r = _index().validate("T1566.001")
    assert r.valid
    assert r.name == "Spearphishing Attachment"


def test_unknown_technique_rejected():
    r = _index().validate("T9999")
    assert not r.valid
    assert "unknown" in r.reason


def test_malformed_rejected():
    for bad in ["", "1566", "TXXXX", "T156", "T1566.1"]:
        assert not _index().validate(bad).valid


def test_deprecated_rejected():
    r = _index().validate("T1000")
    assert not r.valid
    assert "deprecated" in r.reason


def test_revoked_rejected():
    r = _index().validate("T1001")
    assert not r.valid
    assert "revoked" in r.reason


def test_case_normalized():
    assert _index().validate("t1566").valid
