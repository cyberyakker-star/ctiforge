"""Typer CLI entrypoint for ctiforge."""

from __future__ import annotations

import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import typer

from . import __version__

app = typer.Typer(
    add_completion=False,
    help="Turn threat reports into structured, validated intelligence.",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"ctiforge {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """ctiforge — report-to-structured-intel conversion with hallucination guards."""


@app.command()
def analyze(
    source: str = typer.Argument(..., help="URL, PDF path, or text/markdown file."),
    output: Path = typer.Option(
        None, "-o", "--output", help="Output directory (default: ./ctiforge-output-<ts>/)."
    ),
    fmt: str = typer.Option(
        "json,md,csv", "--format", help="Comma-separated subset of json,md,csv."
    ),
    model: str = typer.Option(
        None, "--model", help="Anthropic model (overrides CTIFORGE_MODEL / default)."
    ),
    include_private: bool = typer.Option(
        False, "--include-private", help="Keep private/reserved IP indicators."
    ),
    report: Path = typer.Option(
        None, "--report",
        help="Also write a run.json artifact (ctiforge.run/1) for the run dashboard.",
    ),
    decisions: Path = typer.Option(
        None, "--decisions",
        help="Apply verdicts from a ctiforge.decisions/1 file to the review queue.",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging."),
) -> None:
    """Analyze a threat report and write JSON / Markdown / CSV outputs."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Imported here so `--version` / `--help` stay fast and dependency-light.
    from .analyze import AnalyzeError
    from .attack import AttackError
    from .extract import extract_indicators
    from .ingest import IngestError, ingest
    from .pipeline import analyze_text, get_index
    from .render import render_all
    from .report import (
        RunRecorder,
        apply_decisions,
        build_run_report,
        load_decisions,
        write_run_report,
    )

    # Validate parameters BEFORE the pipeline try-block so click's usage-error
    # handling (exit code 2, usage text) applies instead of the generic handler.
    formats = [f.strip().lower() for f in fmt.split(",") if f.strip()]
    bad = set(formats) - {"json", "md", "csv"}
    if bad:
        raise typer.BadParameter(f"Unknown format(s): {', '.join(sorted(bad))}")
    if decisions and not report:
        raise typer.BadParameter("--decisions requires --report.")

    rec = RunRecorder()
    t0 = time.perf_counter()

    def _tick() -> float:
        """Milliseconds since the previous stage boundary."""
        nonlocal t0
        now = time.perf_counter()
        ms = (now - t0) * 1000
        t0 = now
        return ms

    try:
        typer.echo(f"[1/5] Ingesting {source} ...")
        report_in = ingest(source)
        src_path = Path(source)
        rec.set_source(
            src_path.name if src_path.is_file() else source,
            path=src_path if src_path.is_file() else None,
            text=report_in.text,
        )
        rec.log_line("ingest", f"source {rec.source_sha256 or '(no hash)'} ingested")
        rec.stage("ingest", _tick(), f"{len(report_in.text):,} chars")

        typer.echo("[2/5] Extracting indicators ...")
        indicators = extract_indicators(report_in.text, include_private=include_private)
        typer.echo(f"      {len(indicators)} indicator(s) extracted.")
        rules = {i.rule for i in indicators if i.rule}
        rec.log_line("extract", f"{len(indicators)} indicators, 0 model calls")
        rec.stage("extract", _tick(), f"{len(indicators)} indicators · {len(rules)} rules")

        typer.echo("[3/5] Loading ATT&CK dataset ...")
        attack_index = get_index()
        rec.log_line(
            "validate",
            f"loaded {attack_index.dataset} "
            f"v{attack_index.version or '?'} ({attack_index.retrieved or '?'})",
        )
        rec.stage("map", _tick(), f"{len(attack_index)} techniques indexed")

        typer.echo("[4/5] Running LLM analysis ...")
        analysis = analyze_text(
            report_in.text,
            title=report_in.title,
            source_url_or_path=report_in.source_url_or_path,
            include_private=include_private,
            model=model,
            index=attack_index,
            indicators=indicators,
        )
        analysis.retrieved_at = report_in.retrieved_at
        n_ok, n_bad = len(analysis.techniques), len(analysis.rejected_mappings)
        for r in analysis.rejected_mappings:
            rec.log_line("validate", f"{r.technique_id} rejected — {r.reason}", "err")
        for v in analysis.dropped_indicators:
            rec.log_line("validate", f"dropped invented indicator {v}", "warn")
        rec.log_line("validate", f"{n_ok} of {n_ok + n_bad} mappings validated")
        rec.stage(
            "validate", _tick(), f"{n_ok} pass · {n_bad} reject",
            status="warn" if n_bad else "ok",
        )

        out_dir = output or Path(
            f"./ctiforge-output-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
        )
        typer.echo(f"[5/5] Writing outputs to {out_dir} ...")
        written = render_all(analysis, out_dir, formats)
        for p in written:
            typer.echo(f"      wrote {p}")

        if report:
            payload = build_run_report(
                analysis,
                text=report_in.text,
                recorder=rec,
                attack_dataset=attack_index.dataset,
                attack_version=attack_index.version,
                attack_retrieved=attack_index.retrieved,
            )
            if decisions:
                verdicts = load_decisions(decisions)
                payload = apply_decisions(payload, verdicts)
                typer.echo(f"      applied {len(verdicts)} decision(s) from {decisions}")
            n_review = len(payload["review"])
            rec.log_line("emit", f"run.json written ({n_review} review items)")
            payload["log"] = [entry.to_json() for entry in rec.log]
            payload["stages"].append(
                {
                    "id": "emit", "label": "Emit", "status": "ok",
                    "duration_ms": round(_tick()), "note": "run.json",
                }
            )
            write_run_report(payload, report)
            typer.echo(f"      wrote {report}  ({n_review} review item(s))")

        if analysis.rejected_mappings:
            typer.echo(f"      ⚠ {len(analysis.rejected_mappings)} ATT&CK mapping(s) rejected.")
        if analysis.dropped_indicators:
            typer.echo(
                f"      ⚠ {len(analysis.dropped_indicators)} LLM indicator reference(s) dropped."
            )
        typer.echo("Done. Review the machine-drafted analysis before use.")

    except (IngestError, AttackError, AnalyzeError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001 - top-level guard: fail loudly, non-zero exit
        typer.secho(f"unexpected error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (localhost by default)."),
    port: int = typer.Option(8000, "--port", help="Port to listen on."),
) -> None:
    """Launch the web UI + REST API (requires the 'server' extra)."""
    try:
        import uvicorn

        from .api import app as api_app
    except ImportError as exc:
        typer.secho(
            "The web UI / API requires extra dependencies. Install with:\n"
            '  pip install "ctiforge[server]"',
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc
    typer.echo(f"ctiforge serving on http://{host}:{port}  (Ctrl-C to stop)")
    uvicorn.run(api_app, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
