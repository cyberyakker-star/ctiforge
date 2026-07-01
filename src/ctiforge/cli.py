"""Typer CLI entrypoint for ctiforge."""

from __future__ import annotations

import logging
import sys
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
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging."),
) -> None:
    """Analyze a threat report and write JSON / Markdown / CSV outputs."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Imported here so `--version` / `--help` stay fast and dependency-light.
    from .analyze import AnalyzeError
    from .analyze import analyze as run_analysis
    from .attack import AttackError, AttackIndex
    from .extract import extract_indicators
    from .ingest import IngestError, ingest
    from .render import render_all

    # Validate parameters BEFORE the pipeline try-block so click's usage-error
    # handling (exit code 2, usage text) applies instead of the generic handler.
    formats = [f.strip().lower() for f in fmt.split(",") if f.strip()]
    bad = set(formats) - {"json", "md", "csv"}
    if bad:
        raise typer.BadParameter(f"Unknown format(s): {', '.join(sorted(bad))}")

    try:
        typer.echo(f"[1/5] Ingesting {source} ...")
        report = ingest(source)

        typer.echo("[2/5] Extracting indicators ...")
        indicators = extract_indicators(report.text, include_private=include_private)
        typer.echo(f"      {len(indicators)} indicator(s) extracted.")

        typer.echo("[3/5] Loading ATT&CK dataset ...")
        attack_index = AttackIndex.load()

        typer.echo("[4/5] Running LLM analysis ...")
        analysis = run_analysis(
            report.text, indicators, model=model, attack_index=attack_index
        )
        analysis.title = report.title
        analysis.source_url_or_path = report.source_url_or_path
        analysis.retrieved_at = report.retrieved_at

        out_dir = output or Path(
            f"./ctiforge-output-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
        )
        typer.echo(f"[5/5] Writing outputs to {out_dir} ...")
        written = render_all(analysis, out_dir, formats)
        for p in written:
            typer.echo(f"      wrote {p}")

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


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
