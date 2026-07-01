"""Stage 3 — ATT&CK dataset download/cache/index and technique-ID validation.

A slim loader over the official MITRE enterprise-attack STIX JSON. No heavyweight
ATT&CK libraries. Every technique ID the LLM proposes is checked here; invalid,
unknown, deprecated or revoked IDs are rejected — never silently passed through.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import ATTACK_URL, CACHE_MAX_AGE_DAYS, cache_dir

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CACHE_FILE = "enterprise-attack.json"


@dataclass
class ValidResult:
    technique_id: str
    name: str
    tactics: list[str] = field(default_factory=list)
    valid: bool = True


@dataclass
class Invalid:
    technique_id: str
    reason: str
    valid: bool = False


class AttackError(Exception):
    """Raised when the ATT&CK dataset cannot be obtained."""


def _cache_path() -> Path:
    return cache_dir() / _CACHE_FILE


def _is_stale(path: Path) -> bool:
    if not path.exists():
        return True
    age_days = (time.time() - path.stat().st_mtime) / 86_400
    return age_days > CACHE_MAX_AGE_DAYS


def _download(path: Path) -> None:
    import httpx

    try:
        with httpx.stream("GET", ATTACK_URL, follow_redirects=True, timeout=120.0) as resp:
            resp.raise_for_status()
            tmp = path.with_suffix(".tmp")
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_bytes():
                    fh.write(chunk)
            tmp.replace(path)
    except httpx.HTTPError as exc:
        raise AttackError(f"Failed to download ATT&CK dataset: {exc}") from exc


def ensure_dataset(force: bool = False) -> Path:
    """Ensure a fresh-enough enterprise-attack.json is cached; return its path."""
    path = _cache_path()
    if force or _is_stale(path):
        _download(path)
    return path


class AttackIndex:
    """Index of technique ID -> {name, tactics, is_deprecated/revoked}."""

    def __init__(self, index: dict[str, dict]) -> None:
        self._index = index

    @classmethod
    def load(cls, force_refresh: bool = False) -> AttackIndex:
        path = ensure_dataset(force=force_refresh)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AttackError(f"Corrupt ATT&CK cache at {path}: {exc}") from exc
        return cls(cls._build_index(data))

    @staticmethod
    def _build_index(data: dict) -> dict[str, dict]:
        index: dict[str, dict] = {}
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            if not ext_id:
                continue
            tactics = [
                ph.get("phase_name")
                for ph in obj.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            ]
            index[ext_id] = {
                "name": obj.get("name", ""),
                "tactics": [t for t in tactics if t],
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "revoked": bool(obj.get("revoked", False)),
            }
        return index

    def __len__(self) -> int:
        return len(self._index)

    def validate(self, technique_id: str) -> ValidResult | Invalid:
        """Validate a technique ID against the loaded dataset."""
        tid = (technique_id or "").strip().upper()
        if not _TECHNIQUE_RE.match(tid):
            return Invalid(tid, "malformed technique ID (expected T#### or T####.###)")
        entry = self._index.get(tid)
        if entry is None:
            return Invalid(tid, "unknown technique ID (not present in ATT&CK enterprise)")
        if entry["revoked"]:
            return Invalid(tid, "revoked technique")
        if entry["deprecated"]:
            return Invalid(tid, "deprecated technique")
        return ValidResult(tid, entry["name"], entry["tactics"])
