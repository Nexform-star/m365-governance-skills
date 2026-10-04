#!/usr/bin/env python3
"""Render docs/demo.svg, the README demo, from the real output of this repository's own commands.

Runs the commands listed in STEPS (at the bottom of this file) against the committed fixtures, captures what they
print, and draws it as a terminal window in SVG: dark background, monospace text, lines folded at 100 columns,
colour codes removed. The output is deterministic: fixed dates, no timestamps, and paths relative to where the
command ran. Long outputs keep their first and last lines, with a marker saying how many lines were left out.

    python3 scripts/render_demo.py                  rewrite docs/demo.svg
    python3 scripts/render_demo.py --output x.svg   write the SVG somewhere else

Standard library only. Run it again whenever a command's output changes, and commit the new SVG.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "demo.svg"

COLUMNS = 100
FONT_SIZE = 14
CHAR_WIDTH = 8.7  # advance of a 14px monospace glyph, rounded up
LINE_HEIGHT = 20
PAD_X = 24
PAD_Y = 18
TITLE_BAR = 36
WIDTH = 920  # 2 * PAD_X + COLUMNS * CHAR_WIDTH, rounded up

BACKGROUND = "#0A1628"
TITLE_BG = "#13233D"
FOREGROUND = "#D7DEE8"
DIM = "#7D8BA1"
PROMPT = "#7FD1AE"
RED = "#FF7B72"
AMBER = "#E3B341"
GREEN = "#7EE787"
FONT_FAMILY = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")
NBSP = "\u00a0"
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass
class Step:
    display: str  # the command as a reader types it
    argv: list[str] | None = None  # what actually runs (None: a shell step shown for context, done by `action`)
    action: Callable[[Path], None] | None = None
    head: int = 0  # keep only the first `head` and last `tail` output lines (0: keep everything)
    tail: int = 0


def clean(text: str, cwd: Path) -> list[str]:
    """Strip colour codes and control characters, and make paths relative to where the command ran."""
    text = ANSI_RE.sub("", text).replace("\r\n", "\n")
    for base in {str(cwd), str(cwd.resolve())}:
        text = text.replace(base + "/", "").replace(base, ".")
    lines = [CONTROL_RE.sub("", line.expandtabs(8)).rstrip() for line in text.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return lines


def elide(lines: list[str], head: int, tail: int) -> list[tuple[str, str | None]]:
    if not head or len(lines) <= head + tail + 1:
        return [(line, None) for line in lines]
    hidden = len(lines) - head - tail
    kept = [(line, None) for line in lines[:head]]
    kept.append((f"[... {hidden} more lines; run the command to see them all ...]", DIM))
    kept += [(line, None) for line in lines[len(lines) - tail :]] if tail else []
    return kept


def transcript() -> list[tuple[str, str | None]]:
    """Run every step and return (line, colour) pairs, colour None meaning keyword highlighting."""
    out: list[tuple[str, str | None]] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = prepare(Path(tmp))
        environ = dict(os.environ, NO_COLOR="1", TERM="dumb", COLUMNS=str(COLUMNS), PYTHONIOENCODING="utf-8", **EXTRA_ENV)
        for i, step in enumerate(STEPS):
            if i:
                out.append(("", None))
            out.append((f"$ {step.display}", PROMPT))
            if step.action is not None:
                step.action(work)
            if step.argv is None:
                continue
            proc = subprocess.run(step.argv, cwd=work, env=environ, capture_output=True, text=True, encoding="utf-8", timeout=300)
            out += elide(clean(proc.stdout + proc.stderr, work), step.head, step.tail)
            if proc.returncode:
                out.append((f"[exit {proc.returncode}]", DIM))
    return out


def wrap(line: str) -> list[str]:
    """Fold a line at COLUMNS, breaking after a space when one is near the end (like `fold -s`)."""
    rows = []
    while len(line) > COLUMNS:
        cut = line.rfind(" ", COLUMNS // 2, COLUMNS) + 1 or COLUMNS
        rows.append(line[:cut].rstrip())
        line = line[cut:]
    rows.append(line)
    return rows


def text(part: str) -> str:
    """XML-escape, and turn leading spaces and runs of spaces into no-break spaces so no renderer collapses them."""
    part = escape(part)
    part = re.sub(r"^ +| {2,}", lambda m: NBSP * len(m.group(0)), part)
    return part


def tspans(line: str, colour: str | None) -> str:
    if colour is not None:
        return f'<tspan fill="{colour}">{text(line)}</tspan>'
    marks: list[tuple[int, int, str]] = []
    for words, col in HIGHLIGHT:
        marks += [(m.start(), m.end(), col) for m in re.finditer(rf"\b(?:{words})\b", line)]
    marks.sort()
    parts, pos = [], 0
    for start, end, col in marks:
        if start < pos:
            continue
        parts.append(text(line[pos:start]))
        parts.append(f'<tspan fill="{col}">{text(line[start:end])}</tspan>')
        pos = end
    parts.append(text(line[pos:]))
    return "".join(parts)


def render(lines: list[tuple[str, str | None]]) -> str:
    rows = [(part, colour) for line, colour in lines for part in wrap(line)]
    height = TITLE_BAR + 2 * PAD_Y + LINE_HEIGHT * len(rows)
    title = TITLE if len(TITLE) <= 96 else TITLE[:93] + "..."
    label = escape(TITLE, {'"': "&quot;"})
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}" '
        f'role="img" aria-label="{label}">',
        f"<title>{escape(TITLE)}</title>",
        f'<rect width="{WIDTH}" height="{height}" rx="8" fill="{BACKGROUND}"/>',
        f'<path d="M0 8a8 8 0 0 1 8-8h{WIDTH - 16}a8 8 0 0 1 8 8v{TITLE_BAR - 8}h-{WIDTH}z" fill="{TITLE_BG}"/>',
        f'<circle cx="20" cy="18" r="6" fill="{RED}"/><circle cx="40" cy="18" r="6" fill="{AMBER}"/>'
        f'<circle cx="60" cy="18" r="6" fill="{GREEN}"/>',
        f'<text x="{WIDTH // 2}" y="23" fill="{DIM}" font-family="{FONT_FAMILY}" font-size="13" text-anchor="middle" '
        f'xml:space="preserve">{escape(title)}</text>',
        f'<g font-family="{FONT_FAMILY}" font-size="{FONT_SIZE}" fill="{FOREGROUND}" xml:space="preserve" style="white-space:pre">',
    ]
    y = TITLE_BAR + PAD_Y + FONT_SIZE
    for row, colour in rows:
        if row:
            svg.append(f'<text x="{PAD_X}" y="{y}" xml:space="preserve">{tspans(row, colour)}</text>')
        y += LINE_HEIGHT
    svg += ["</g>", "</svg>", ""]
    return "\n".join(svg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the SVG (default: docs/demo.svg)")
    args = parser.parse_args(argv)
    svg = render(transcript())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(svg, encoding="utf-8")
    print(f"wrote {args.output} ({len(svg.encode('utf-8'))} bytes)")
    return 0


# What the demo shows. `display` is the command as a reader types it (the container image's entrypoint is
# `m365-governance`); `argv` is the same command run through scripts/cli.py, so no install is needed.
TITLE = "m365-governance ca-gaps on the committed Conditional Access fixture"
HIGHLIGHT = [("CRITICAL|HIGH", RED), ("MEDIUM", AMBER)]
EXTRA_ENV: dict[str, str] = {}
CLI = [sys.executable, "scripts/cli.py"]
CA_GAPS = ["ca-gaps", "tests/fixtures/ca-gaps/gaps", "--config", "tests/fixtures/ca-gaps/config.yaml"]
CA_GAPS += ["--as-of", "2026-10-01", "--min-severity", "HIGH"]
STEPS = [
    Step("m365-governance " + " ".join(CA_GAPS), CLI + CA_GAPS, head=22, tail=9),
]


def prepare(tmp: Path) -> Path:
    """Where the commands run: the repository root, so every path in the output is relative to it."""
    return ROOT


if __name__ == "__main__":
    sys.exit(main())
