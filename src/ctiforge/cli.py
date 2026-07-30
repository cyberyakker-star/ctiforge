"""Typer CLI entrypoint for ctiforge."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.table import Table
from rich.text import Text

from . import __version__, config
from . import console as ui

app = typer.Typer(
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        "Turn a threat report into structured, validated intelligence.\n\n"
        "[bold]extract[/bold] runs with no API key and cannot hallucinate — start there.\n"
        "[bold]analyze[/bold] adds ATT&CK mapping, with every ID validated and every "
        "mapping required to quote its evidence."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"ctiforge {__version__}")
        raise typer.Exit()


def _ingest_hints(source: str) -> tuple[str, ...]:
    """Concrete next steps for a source that could not be read."""
    if source.startswith(("http://", "https://")):
        return (
            "check the URL opens in a browser — some vendor pages are "
            "JavaScript-rendered and have no extractable article text",
            "save the page as PDF and pass that file instead",
        )
    if not Path(source).exists():
        return (f"no file at {source!r} — check the path",)
    return ("if this is a scanned PDF it has no text layer; OCR it first",)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """ctiforge — report-to-structured-intel conversion with hallucination guards."""


@app.command()
def extract(
    source: str = typer.Argument(..., help="URL, PDF path, or text/markdown file."),
    output: Path = typer.Option(
        None, "-o", "--output", help="Write iocs.csv to this directory."
    ),
    include_private: bool = typer.Option(
        False, "--include-private", help="Keep private/reserved IP indicators."
    ),
    show_context: bool = typer.Option(
        False, "--context", help="Show the source snippet each rule matched."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON on stdout instead."),
) -> None:
    """Extract IOCs deterministically. No API key, no cost, cannot hallucinate."""
    from .extract import extract_indicators
    from .ingest import IngestError, ingest

    try:
        report_in = ingest(source)
        indicators = extract_indicators(report_in.text, include_private=include_private)
    except IngestError as exc:
        ui.fail(str(exc), *_ingest_hints(source))
        raise typer.Exit(code=1) from exc

    if as_json:
        # Machine path: no banner, no colour, just the data.
        typer.echo(json.dumps(
            {
                "source": report_in.source_url_or_path,
                "count": len(indicators),
                "indicators": [i.model_dump() for i in indicators],
            },
            indent=2, ensure_ascii=False,
        ))
        return

    ui.banner("extract  ·  deterministic, keyless")
    ui.console.print()
    if indicators:
        ui.console.print(ui.indicator_table(indicators, show_context=show_context))
    else:
        ui.note("No indicators found in this source.")

    by_type: dict[str, int] = {}
    for i in indicators:
        by_type[i.type] = by_type.get(i.type, 0) + 1
    breakdown = "  ".join(f"{n} {t}" for t, n in sorted(by_type.items()))
    ui.console.print()
    ui.console.print(ui.counts_line([("indicators", len(indicators), "ok")]))
    if breakdown:
        ui.note(breakdown)

    if output:
        from .models import ReportAnalysis
        from .render import write_csv

        output.mkdir(parents=True, exist_ok=True)
        path = write_csv(ReportAnalysis(indicators=indicators), output)
        ui.console.print()
        ui.success(f"wrote {path}")

    ui.console.print()
    ui.note("Every value above was found by a named rule at a byte offset — "
            "no model was involved.")
    if not config.get_api_key():
        ui.hint("set ANTHROPIC_API_KEY and run `ctiforge analyze` to add "
                "ATT&CK mapping and context")
    ui.console.print()


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
    # Quiet by default: every guard result the library logs (dropped indicators,
    # rejected mappings) is already reported in the closing summary and in
    # run.json. Letting raw log lines interleave with that would show the same
    # fact twice, in two different voices. --verbose opts into the log stream.
    logging.basicConfig(
        level=logging.INFO if verbose else logging.ERROR,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Imported here so `--version` / `--help` stay fast and dependency-light.
    from .analyze import AnalyzeError
    from .attack import AttackError
    from .extract import extract_indicators
    from .ingest import IngestError, ingest
    from .models import ReportAnalysis
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

    ui.banner(f"analyze  ·  {source}")
    degraded = ""

    try:
        with ui.stage_progress() as step:
            step("ingesting source")
            report_in = ingest(source)
            src_path = Path(source)
            rec.set_source(
                src_path.name if src_path.is_file() else source,
                path=src_path if src_path.is_file() else None,
                text=report_in.text,
            )
            rec.log_line("ingest", f"source {rec.source_sha256 or '(no hash)'} ingested")
            rec.stage("ingest", _tick(), f"{len(report_in.text):,} chars")

            step("extracting indicators (deterministic)")
            indicators = extract_indicators(report_in.text, include_private=include_private)
            rules = {i.rule for i in indicators if i.rule}
            rec.log_line("extract", f"{len(indicators)} indicators, 0 model calls")
            rec.stage("extract", _tick(),
                      f"{len(indicators)} indicators · {len(rules)} rules")

            step("loading ATT&CK dataset")
            attack_index = get_index()
            rec.log_line(
                "validate",
                f"loaded {attack_index.dataset} "
                f"v{attack_index.version or '?'} ({attack_index.retrieved or '?'})",
            )
            rec.stage("map", _tick(), f"{len(attack_index)} techniques indexed")

            step("mapping TTPs and applying guards")
            try:
                analysis = analyze_text(
                    report_in.text,
                    title=report_in.title,
                    source_url_or_path=report_in.source_url_or_path,
                    include_private=include_private,
                    model=model,
                    index=attack_index,
                    indicators=indicators,
                )
            except AnalyzeError as exc:
                # Never discard work already completed. The deterministic
                # indicators are valid on their own, so write those and say
                # plainly what is missing and why.
                degraded = str(exc)
                analysis = ReportAnalysis(
                    summary="",
                    indicators=indicators,
                    title=report_in.title,
                    source_url_or_path=report_in.source_url_or_path,
                )
                rec.log_line("validate", f"LLM stage unavailable: {exc}", "warn")
                rec.stage("validate", _tick(), "skipped — no LLM analysis", status="warn")
            analysis.retrieved_at = report_in.retrieved_at

            if not degraded:
                n_ok = len(analysis.techniques)
                n_bad = len(analysis.rejected_mappings)
                for r in analysis.rejected_mappings:
                    rec.log_line("validate",
                                 f"{r.technique_id} rejected — {r.reason}", "err")
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
            step("writing outputs")
            written = render_all(analysis, out_dir, formats)

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

        # ---- the closing report -------------------------------------------
        ui.console.print()
        if degraded:
            ui.warn("Analysis stage unavailable — deterministic results kept.")
            ui.note(degraded)
            ui.console.print()
            ui.console.print(ui.counts_line([("indicators extracted", len(indicators), "ok")]))
            ui.hint("set ANTHROPIC_API_KEY to add ATT&CK mapping, actor/malware "
                    "attribution and indicator context")
        else:
            ui.console.print(ui.counts_line([
                ("indicators", len(analysis.indicators), "ok"),
                ("techniques", len(analysis.techniques), "ok"),
                ("needs review",
                 len(analysis.rejected_mappings) + len(analysis.dropped_indicators),
                 "warn" if (analysis.rejected_mappings or analysis.dropped_indicators)
                 else "muted"),
            ]))
            ui.console.print(ui.guard_verdict(
                len(analysis.techniques), len(analysis.rejected_mappings),
                len(analysis.dropped_indicators),
            ))
            if analysis.rejected_mappings and verbose:
                ui.console.print()
                ui.console.print(ui.rejected_table(analysis.rejected_mappings))

        ui.console.print()
        for p in written:
            ui.success(f"{p}")
        if report:
            ui.success(f"{report}   ({n_review} review item(s))")

        ui.console.print()
        if degraded:
            ui.note("The indicators above are deterministic and complete — "
                    "nothing was inferred.")
        else:
            ui.note("Machine-drafted analysis. Review before acting on it.")
            if analysis.rejected_mappings and not verbose:
                ui.hint("re-run with --verbose to see why each mapping was refused")
        if report:
            ui.hint("run `ctiforge dashboard` to open the run-report viewer")
        ui.console.print()

    except IngestError as exc:
        ui.fail(str(exc), *_ingest_hints(source))
        raise typer.Exit(code=1) from exc
    except AttackError as exc:
        ui.fail(str(exc),
                "check your network — the dataset is cached after the first "
                "successful download, so this only blocks the first run")
        raise typer.Exit(code=1) from exc
    except AnalyzeError as exc:
        ui.fail(str(exc), "run `ctiforge doctor` to check your setup")
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001 - top-level guard: fail loudly, non-zero exit
        typer.secho(f"unexpected error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc



@app.command()
def attack(
    technique_id: str = typer.Argument(..., help='Technique ID, e.g. "T1566.001".'),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON on stdout instead."),
) -> None:
    """Validate an ATT&CK technique ID against the real dataset. No API key."""
    from .attack import AttackError
    from .pipeline import get_index

    try:
        index = get_index()
    except AttackError as exc:
        ui.fail(str(exc), "check your network, then retry — the dataset is cached "
                          "after the first successful download")
        raise typer.Exit(code=1) from exc

    result = index.validate(technique_id)
    if as_json:
        payload = {"technique_id": result.technique_id, "valid": result.valid}
        if result.valid:
            payload |= {"name": result.name, "tactics": result.tactics}
        else:
            payload |= {"reason": result.reason}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(code=0 if result.valid else 2)

    ui.banner(f"attack  ·  {index.dataset} retrieved {index.retrieved or '?'}")
    ui.console.print()
    if result.valid:
        ui.success(f"{result.technique_id}  {result.name}")
        ui.note(f"tactics: {', '.join(result.tactics) or '—'}")
    else:
        ui.fail(f"{result.technique_id or '(empty)'} — {result.reason}")
        ui.hint("ctiforge would refuse this ID rather than pass it through")
    ui.console.print()
    raise typer.Exit(code=0 if result.valid else 2)


@app.command()
def doctor() -> None:
    """Check that everything ctiforge needs is in place."""
    from .attack import _cache_path

    ui.banner("doctor  ·  environment check")
    ui.console.print()

    rows: list[tuple[bool | None, str, str, str]] = []

    # 1. API key — only needed for the LLM analysis stage.
    if config.get_api_key():
        rows.append((True, "Anthropic API key", "set in the environment", ""))
    else:
        rows.append((None, "Anthropic API key", "not set",
                     "export ANTHROPIC_API_KEY=sk-ant-…  (only needed for `analyze`)"))

    # 2. ATT&CK dataset cache.
    path = _cache_path()
    if path.exists():
        age_days = (time.time() - path.stat().st_mtime) / 86_400
        size_mb = path.stat().st_size / 1e6
        stale = age_days > config.CACHE_MAX_AGE_DAYS
        rows.append((
            not stale, "ATT&CK dataset",
            f"cached, {size_mb:.0f} MB, {age_days:.0f} day(s) old",
            "run any command to refresh it automatically" if stale else "",
        ))
    else:
        rows.append((None, "ATT&CK dataset", "not downloaded yet",
                     "first run fetches it (~45 MB), then it is cached"))

    # 3. Optional extras.
    for extra, module, what in (
        ("server", "fastapi", "web UI + REST API"),
        ("mcp", "mcp", "MCP server for AI agents"),
    ):
        ok = importlib.util.find_spec(module) is not None
        rows.append((
            ok if ok else None, f"{what}",
            "installed" if ok else "not installed",
            "" if ok else f'pip install "ctiforge[{extra}]"',
        ))

    t = Table(box=None, pad_edge=False, show_header=False)
    t.add_column(width=3)
    t.add_column(style="value", width=26)
    t.add_column(style="muted")
    for ok, label, state, fix in rows:
        mark = ("✓", "ok") if ok else (("·", "faint") if ok is None else ("!", "warn"))
        t.add_row(Text(mark[0], style=mark[1]), label, state)
        if fix:
            t.add_row("", "", Text(f"→ {fix}", style="accent"))
    ui.console.print(t)

    blocking = [r for r in rows if r[0] is False]
    ui.console.print()
    if blocking:
        ui.warn(f"{len(blocking)} item(s) need attention.")
    else:
        ui.success("Ready. `ctiforge extract <source>` works right now, no key needed.")
    ui.console.print()


@app.command()
def dashboard(
    print_path: bool = typer.Option(
        False, "--path", help="Print the file path instead of opening a browser."
    ),
) -> None:
    """Open the run-report viewer. Needs no server and no API key."""
    import webbrowser

    page = Path(__file__).parent / "web" / "run.html"
    if not page.exists():  # pragma: no cover - packaging guard
        ui.fail("The dashboard file is missing from this installation.",
                "reinstall ctiforge")
        raise typer.Exit(code=1)

    if print_path:
        typer.echo(str(page))
        return

    ui.banner("dashboard  ·  run-report viewer")
    ui.console.print()
    opened = webbrowser.open(page.as_uri())
    if opened:
        ui.success("opened in your browser")
    else:
        ui.note("Could not launch a browser. Open this file:")
        ui.console.print(Text(f"  {page}", style="accent"))
    ui.note("Click “Load run.json” and pick a file written by "
            "`ctiforge analyze --report run.json`.")
    ui.note("It makes no network requests — safe for incident data and air-gapped use.")
    ui.console.print()


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
        ui.fail(
            "The web UI / API needs extra dependencies.",
            'pip install "ctiforge[server]"',
        )
        raise typer.Exit(code=1) from exc

    ui.banner("serve  ·  web UI + REST API")
    ui.console.print()
    ui.success(f"http://{host}:{port}")
    ui.note(f"API docs at http://{host}:{port}/docs")
    ui.note("Loads a bundled demo on open — no API key required to look around.")
    ui.console.print()
    ui.note("Ctrl-C to stop.")
    ui.console.print()
    uvicorn.run(api_app, host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
