"""Tests for the ATT&CK index and technique validation (no network required)."""


def test_valid_technique(fake_index):
    r = fake_index.validate("T1566")
    assert r.valid
    assert r.name == "Phishing"
    assert "initial-access" in r.tactics


def test_valid_subtechnique(fake_index):
    r = fake_index.validate("T1566.001")
    assert r.valid
    assert r.name == "Spearphishing Attachment"


def test_unknown_technique_rejected(fake_index):
    r = fake_index.validate("T9999")
    assert not r.valid
    assert "unknown" in r.reason


def test_malformed_rejected(fake_index):
    for bad in ["", "1566", "TXXXX", "T156", "T1566.1"]:
        assert not fake_index.validate(bad).valid


def test_deprecated_rejected(fake_index):
    r = fake_index.validate("T1000")
    assert not r.valid
    assert "deprecated" in r.reason


def test_revoked_rejected(fake_index):
    r = fake_index.validate("T1001")
    assert not r.valid
    assert "revoked" in r.reason


def test_case_normalized(fake_index):
    assert fake_index.validate("t1566").valid


def test_valid_flag_not_constructor_settable():
    """The valid discriminant is locked to the type."""
    import pytest

    from ctiforge.attack import Invalid, ValidResult

    with pytest.raises(TypeError):
        ValidResult("T1", "x", valid=False)
    with pytest.raises(TypeError):
        Invalid("T1", "reason", valid=True)
