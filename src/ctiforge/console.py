"""Presentation layer — one visual language for every ctiforge command.

Everything the CLI prints goes through here so `extract`, `analyze`, `doctor`
and `attack` look like the same product. Uses rich, which typer already
depends on, so this adds no dependency.

Design rules
------------
* One accent colour, used only for things the user acts on.
* Guard results are always visible, never buried: validated is green,
  rejected is red, needs-review is amber, and the counts are always shown.
* Every error ends with a concrete next step. An error the user can't act on
  is a bug in the message.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from rich.box import SIMPLE_HEAD
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

THEME = Theme(
    {
        "brand": "bold #5b9dff",
        "accent": "#5b9dff",
        "muted": "#8896ad",
        "faint": "#5a6b8c",
        "ok": "bold #2ea043",
        "warn": "bold #bb8009",
        "bad": "bold #ff6b6b",
        "value": "#e8edf6",
        "rule": "#7c5cff",
    }
)

console = Console(theme=THEME, highlight=False)
err_console = Console(theme=THEME, stderr=True, highlight=False)

# Type badge colours, matched to the web dashboard so the two surfaces agree.
TYPE_STYLE = {
    "ipv4": "#5b9dff", "ipv6": "#5b9dff", "domain": "#3fb950", "url": "#e3a008",
    "md5": "#a371f7", "sha1": "#a371f7", "sha256": "#a371f7", "email": "#ff7b72",
}


def banner(subtitle: str) -> None:
    """The product wordmark plus what this invocation is doing."""
    console.print()
    console.print(
        Text.assemble(("cti", "brand"), ("forge", "bold #7c5cff"), ("  ", ""),
                      (subtitle, "muted"))
    )


def rule_line() -> None:
    console.print(Text("─" * min(console.width, 78), style="faint"))


def hint(text: str) -> None:
    """A concrete next step. Always phrased as something to do."""
    console.print(Text.assemble(("  → ", "accent"), (text, "muted")))


def fail(message: str, *hints: str) -> None:
    """Report an error the user can act on."""
    err_console.print(Text.assemble(("error  ", "bad"), (message, "value")))
    for h in hints:
        err_console.print(Text.assemble(("  → ", "accent"), (h, "muted")))


def note(message: str) -> None:
    console.print(Text.assemble(("  ", ""), (message, "muted")))


def success(message: str) -> None:
    console.print(Text.assemble(("  ✓ ", "ok"), (message, "value")))


def warn(message: str) -> None:
    console.print(Text.assemble(("  ! ", "warn"), (message, "value")))


@contextmanager
def stage_progress(enabled: bool = True):
    """A live spinner for the pipeline stages.

    Yields a callable ``step(label)`` that advances the description. Falls back
    to plain lines when output is not a terminal, so logs stay readable.
    """
    if not enabled or not console.is_terminal:
        def plain(label: str) -> None:
            console.print(Text.assemble(("  · ", "faint"), (label, "muted")))
        yield plain
        return

    progress = Progress(
        SpinnerColumn(style="accent"),
        TextColumn("[muted]{task.description}"),
        console=console,
        transient=True,
    )
    with progress:
        task = progress.add_task("starting", total=None)

        def step(label: str) -> None:
            progress.update(task, description=label)

        yield step


@contextmanager
def download_progress(description: str, total: int | None):
    """Progress bar for a large download, so a 45 MB fetch never looks hung."""
    if not console.is_terminal:
        console.print(Text.assemble(("  · ", "faint"), (description, "muted")))
        yield lambda _n: None
        return
    progress = Progress(
        SpinnerColumn(style="accent"),
        TextColumn("[muted]{task.description}"),
        BarColumn(complete_style="accent", finished_style="ok"),
        TextColumn("[faint]{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    )
    with progress:
        task = progress.add_task(description, total=total)
        yield lambda n: progress.advance(task, n)


def indicator_table(indicators: list[Any], show_context: bool = False) -> Table:
    """Indicators with their provenance — the rule that fired and where.

    One indicator per line, always. A table you have to unpick is not a table;
    long values are truncated with an ellipsis rather than folded, because the
    scannable shape matters more than showing every character (the full values
    are in the JSON/CSV, and `--json` prints them untouched).
    """
    t = Table(box=SIMPLE_HEAD, header_style="faint", expand=False, pad_edge=False)
    # Explicit widths: rich shrinks flexible columns first, which would clip the
    # short, load-bearing ones (TYPE, RULE) before the long value.
    t.add_column("TYPE", style="muted", no_wrap=True, width=7)
    t.add_column("VALUE", style="value", no_wrap=True, overflow="ellipsis", width=38)
    t.add_column("AS WRITTEN", style="faint", no_wrap=True, overflow="ellipsis",
                 width=20)
    t.add_column("RULE", style="rule", no_wrap=True, width=20)
    t.add_column("AT", style="faint", justify="right", no_wrap=True, width=5)
    if show_context:
        t.add_column("CONTEXT", style="muted", no_wrap=True, overflow="ellipsis",
                     max_width=40)

    for i in indicators:
        style = TYPE_STYLE.get(i.type, "muted")
        row = [
            Text(i.type, style=style),
            i.value,
            i.defanged_original or "",
            i.rule or "—",
            str(i.offset) if i.offset is not None else "—",
        ]
        if show_context:
            row.append(" ".join((i.context or "").split()))
        t.add_row(*row)
    return t


def technique_table(techniques: list[Any]) -> Table:
    t = Table(box=SIMPLE_HEAD, header_style="faint", expand=False, pad_edge=False)
    t.add_column("ID", style="value", no_wrap=True)
    t.add_column("TECHNIQUE", style="value", overflow="fold")
    t.add_column("TACTIC", style="muted", overflow="fold")
    t.add_column("CONF", style="muted", no_wrap=True)
    t.add_column("EVIDENCE", style="faint", overflow="ellipsis", max_width=52)
    for x in techniques:
        t.add_row(
            x.technique_id, x.name, ", ".join(x.tactics), x.confidence,
            f"“{x.evidence}”" if x.evidence else "—",
        )
    return t


def rejected_table(rejected: list[Any]) -> Table:
    t = Table(box=SIMPLE_HEAD, header_style="faint", expand=False, pad_edge=False)
    t.add_column("PROPOSED", style="bad", no_wrap=True)
    t.add_column("WHY IT WAS REFUSED", style="muted", overflow="fold")
    for r in rejected:
        t.add_row(r.technique_id, r.reason)
    return t


def counts_line(pairs: list[tuple[str, int, str]]) -> Text:
    """A single line of labelled counts, e.g. 20 indicators · 5 techniques."""
    out = Text("  ")
    for idx, (label, n, style) in enumerate(pairs):
        if idx:
            out.append("  ·  ", style="faint")
        out.append(str(n), style=style)
        out.append(f" {label}", style="muted")
    return out


def summary_panel(title: str, body: Group | Text | Table, footer: str = "") -> None:
    """The closing panel every command ends with."""
    console.print()
    console.print(Panel(body, title=f"[muted]{title}", title_align="left",
                        border_style="faint", padding=(1, 2)))
    if footer:
        console.print(Text(f"  {footer}", style="faint"))
    console.print()


def guard_verdict(n_validated: int, n_rejected: int, n_dropped: int) -> Text:
    """The guards' result, stated plainly. This is the product's whole point."""
    out = Text("  ")
    out.append(f"{n_validated}", style="ok")
    out.append(" validated", style="muted")
    if n_rejected:
        out.append("   ")
        out.append(f"{n_rejected}", style="bad")
        out.append(" rejected", style="muted")
    if n_dropped:
        out.append("   ")
        out.append(f"{n_dropped}", style="warn")
        out.append(" indicator(s) dropped", style="muted")
    if not (n_rejected or n_dropped):
        out.append("   nothing refused — every mapping and indicator held up",
                   style="faint")
    return out
