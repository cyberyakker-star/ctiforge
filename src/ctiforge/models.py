"""Pydantic schemas for ctiforge."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

IndicatorType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]
Confidence = Literal["high", "medium", "low"]
IndicatorRole = Literal[
    "c2", "payload_delivery", "phishing", "exfiltration", "scanning", "unknown"
]


class IngestedReport(BaseModel):
    """Cleaned text plus source metadata produced by the ingest stage."""

    text: str
    title: str
    source_url_or_path: str
    retrieved_at: datetime


class Indicator(BaseModel):
    """A deterministically extracted, validated indicator of compromise."""

    value: str
    type: IndicatorType
    defanged_original: str | None = None


class TechniqueMapping(BaseModel):
    """An ATT&CK technique mapping validated against the real dataset."""

    technique_id: str
    name: str = ""
    tactics: list[str] = Field(default_factory=list)
    behavior: str = ""
    evidence: str = ""
    confidence: Confidence = "low"


class RejectedMapping(BaseModel):
    """A technique the LLM proposed that failed validation."""

    technique_id: str
    reason: str
    behavior: str = ""
    evidence: str = ""


class IndicatorContext(BaseModel):
    """LLM-supplied context for an indicator that exists in the extracted list."""

    value: str
    role: IndicatorRole = "unknown"
    context: str = ""


class Targeting(BaseModel):
    sectors: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)


class ReportAnalysis(BaseModel):
    """The full, post-processed analysis result rendered to output files."""

    summary: str = ""
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    targeting: Targeting = Field(default_factory=Targeting)
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    indicator_context: list[IndicatorContext] = Field(default_factory=list)
    rejected_mappings: list[RejectedMapping] = Field(default_factory=list)
    dropped_indicators: list[str] = Field(default_factory=list)

    # Provenance / metadata.
    source_url_or_path: str = ""
    title: str = ""
    retrieved_at: datetime | None = None
    model: str = ""
    indicators: list[Indicator] = Field(default_factory=list)
