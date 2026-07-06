"""FastAPI service: REST endpoints plus the local web UI.

Reuses the shared pipeline and the render string helpers, so it produces
exactly the same intelligence and file contents as the CLI. Intended to run
locally (``ctiforge serve``); it uses the *server's* ANTHROPIC_API_KEY and
binds to localhost by default — do not expose it publicly without adding auth.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, model_validator

from . import __version__
from .analyze import AnalyzeError
from .attack import AttackError
from .config import REVIEW_BANNER
from .extract import extract_indicators
from .ingest import IngestError
from .models import ReportAnalysis
from .pipeline import analyze_source, analyze_text, get_index
from .render import analysis_to_csv, analysis_to_json, analysis_to_markdown

_WEB_DIR = Path(__file__).parent / "web"
_SAMPLE_PATH = _WEB_DIR / "sample_analysis.json"


def _load_demo() -> ReportAnalysis:
    """Load the bundled sample analysis (lets the dashboard render with no key)."""
    return ReportAnalysis.model_validate_json(_SAMPLE_PATH.read_text(encoding="utf-8"))


class ExtractRequest(BaseModel):
    text: str
    include_private: bool = False


class AnalyzeRequest(BaseModel):
    source: str | None = None
    text: str | None = None
    include_private: bool = False
    model: str | None = None

    @model_validator(mode="after")
    def _one_of(self) -> AnalyzeRequest:
        if bool(self.source) == bool(self.text):
            raise ValueError("provide exactly one of 'source' or 'text'")
        return self


def _analysis_payload(analysis) -> dict[str, Any]:
    """Bundle the structured analysis with rendered MD/CSV for the UI/downloads."""
    return {
        "analysis": {"review_banner": REVIEW_BANNER, **analysis.model_dump(mode="json")},
        "markdown": analysis_to_markdown(analysis),
        "csv": analysis_to_csv(analysis),
        "json": analysis_to_json(analysis),
    }


def create_app() -> FastAPI:
    app = FastAPI(
        title="ctiforge",
        description="Report-to-structured-intel conversion with hallucination guards.",
        version=__version__,
    )

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (_WEB_DIR / "index.html").read_text(encoding="utf-8")

    @app.get("/api/demo")
    def api_demo() -> dict[str, Any]:
        """Return the bundled sample analysis so the dashboard renders with no key."""
        return _analysis_payload(_load_demo())

    @app.post("/api/extract")
    def api_extract(req: ExtractRequest) -> dict[str, Any]:
        """Deterministic IOC extraction — no API key, no cost."""
        indicators = extract_indicators(req.text, include_private=req.include_private)
        return {"count": len(indicators), "indicators": [i.model_dump() for i in indicators]}

    @app.get("/api/attack/{technique_id}")
    def api_attack(technique_id: str) -> dict[str, Any]:
        """Validate a MITRE ATT&CK technique ID."""
        result = get_index().validate(technique_id)
        if result.valid:
            return {
                "valid": True,
                "technique_id": result.technique_id,
                "name": result.name,
                "tactics": result.tactics,
            }
        return {"valid": False, "technique_id": result.technique_id, "reason": result.reason}

    @app.post("/api/analyze")
    def api_analyze(req: AnalyzeRequest) -> dict[str, Any]:
        """Full analysis of a URL/path (source) or raw report text."""
        try:
            if req.source:
                analysis = analyze_source(
                    req.source, include_private=req.include_private, model=req.model,
                    index=get_index(),
                )
            else:
                analysis = analyze_text(
                    req.text, include_private=req.include_private, model=req.model,
                    index=get_index(),
                )
        except IngestError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except AnalyzeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except AttackError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return _analysis_payload(analysis)

    @app.post("/api/upload")
    async def api_upload(
        file: UploadFile = File(...), include_private: bool = False
    ) -> dict[str, Any]:
        """Analyze an uploaded PDF (or text) report."""
        suffix = Path(file.filename or "upload").suffix or ".bin"
        data = await file.read()
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            try:
                analysis = analyze_source(
                    tmp.name, include_private=include_private, index=get_index()
                )
            except IngestError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            except AnalyzeError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except AttackError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        analysis.source_url_or_path = file.filename or "uploaded file"
        analysis.title = file.filename or analysis.title
        return _analysis_payload(analysis)

    return app


app = create_app()


def main() -> None:  # pragma: no cover - thin launcher
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":  # pragma: no cover
    main()
