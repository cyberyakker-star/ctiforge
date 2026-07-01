"""Shared test fixtures."""

import pytest

from ctiforge.attack import AttackIndex

# A tiny synthetic STIX-shaped bundle so tests never hit the network.
FAKE_STIX = {
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


@pytest.fixture
def fake_index() -> AttackIndex:
    return AttackIndex(AttackIndex._build_index(FAKE_STIX))
