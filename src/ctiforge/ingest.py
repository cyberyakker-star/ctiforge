"""Stage 1 — ingest a source (URL, PDF, or text file) into clean report text."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from .config import MIN_TEXT_CHARS
from .models import IngestedReport


class IngestError(Exception):
    """Raised when a source cannot be ingested into usable report text."""


def _is_url(source: str) -> bool:
    parsed = urlparse(source)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _ingest_url(source: str) -> tuple[str, str]:
    import httpx
    import trafilatura

    try:
        resp = httpx.get(
            source,
            follow_redirects=True,
            timeout=30.0,
            headers={"User-Agent": "ctiforge/0.1 (+threat-intel extraction)"},
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise IngestError(f"Failed to fetch URL {source!r}: {exc}") from exc

    downloaded = resp.text
    text = trafilatura.extract(
        downloaded, include_comments=False, include_tables=True, favor_recall=True
    )
    if not text:
        raise IngestError(
            f"Could not extract readable text from {source!r}. "
            "The page may be JavaScript-rendered or not an article."
        )
    title = ""
    meta = trafilatura.extract_metadata(downloaded)
    if meta and meta.title:
        title = meta.title
    return text, title or source


def _ingest_pdf(path: Path) -> tuple[str, str]:
    import fitz  # pymupdf

    try:
        doc = fitz.open(path)
    except Exception as exc:  # noqa: BLE001 - pymupdf raises broad errors
        raise IngestError(f"Failed to open PDF {path}: {exc}") from exc

    parts = [page.get_text() for page in doc]
    title = (doc.metadata or {}).get("title") or path.name
    doc.close()
    return "\n".join(parts), title


def _ingest_text_file(path: Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise IngestError(f"Failed to read file {path}: {exc}") from exc
    return text, path.name


def ingest(source: str) -> IngestedReport:
    """Detect the source type and return cleaned text plus metadata.

    Rejects empty or near-empty extractions (< MIN_TEXT_CHARS) loudly.
    """
    if _is_url(source):
        text, title = _ingest_url(source)
    else:
        path = Path(source)
        if not path.exists():
            raise IngestError(
                f"Source {source!r} is neither a reachable URL nor an existing file."
            )
        if path.suffix.lower() == ".pdf":
            text, title = _ingest_pdf(path)
        else:
            text, title = _ingest_text_file(path)
        source = str(path.resolve())

    text = (text or "").strip()
    if len(text) < MIN_TEXT_CHARS:
        raise IngestError(
            f"Extracted only {len(text)} characters from {source!r} "
            f"(minimum {MIN_TEXT_CHARS}). Refusing to analyze a near-empty report."
        )

    return IngestedReport(
        text=text,
        title=title.strip() or source,
        source_url_or_path=source,
        retrieved_at=datetime.now(UTC),
    )
