"""Shared helpers for the m365-governance scripts, standard library only.

Every skill folder carries an identical copy of this file so that each skill stays self-contained when copied on
its own. tests/test_shared_helpers.py fails when the copies drift apart.

What it provides:
  * Export: reads a folder of saved Microsoft Graph JSON. Accepts the Graph collection envelope
    {"value": [...]}, a bare list, or a single object. Records a warning when a file still carries
    "@odata.nextLink" (the export stopped after the first page) and lists files that were not found.
  * parse_dt / as_of_datetime / days_since: tolerant ISO 8601 parsing (Graph uses up to 7 fractional digits).
  * finding(): the one finding shape every script emits.
  * redact(): replaces user principal names, e-mail addresses and known display names with stable tokens, so a
    report can be shared without naming people. Tokens are the first 8 hex characters of a SHA-256 of the
    lower-cased value: the same person gets the same token across one report.
  * load_config(): YAML (via _miniyaml) or JSON config with a key allow-list.
  * render_findings() and cell(): Markdown output that keeps untrusted tenant text inside its table cell.

Nothing here opens a socket, runs a subprocess or calls Microsoft Graph.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from _miniyaml import YAMLError
from _miniyaml import load as yaml_load

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


class InputError(Exception):
    """Bad or unreadable input. Scripts exit 2."""


def load_json(path: Path):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc


def items_of(data, where: str = "input") -> list[dict]:
    """Return the list of objects in a Graph response, a bare list or a single object."""
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        data = data["value"]
    elif isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise InputError(f"{where}: expected a JSON object, a list, or {{\"value\": [...]}}")
    out = [x for x in data if isinstance(x, dict)]
    if len(out) != len(data):
        raise InputError(f"{where}: every entry must be a JSON object")
    return out


class Export:
    """A folder of saved Graph exports. Missing optional files are recorded, not fatal."""

    def __init__(self, folder: str | Path):
        self.folder = Path(folder)
        if not self.folder.is_dir():
            raise InputError(f"{self.folder}: not a folder")
        self.warnings: list[str] = []
        self.missing: list[str] = []
        self.used: list[str] = []

    def _note_paging(self, data, name: str) -> None:
        if isinstance(data, dict) and data.get("@odata.nextLink"):
            self.warnings.append(f"{name} contains @odata.nextLink: only the first page was exported; re-export with --all "
                                 "or follow the link, otherwise results are incomplete")

    def path(self, *names: str) -> Path | None:
        for name in names:
            p = self.folder / name
            if p.is_file():
                return p
        return None

    def list(self, *names: str, required: bool = False) -> list[dict] | None:
        p = self.path(*names)
        if p is None:
            if required:
                raise InputError(f"{self.folder}: required export {names[0]} not found")
            self.missing.append(names[0])
            return None
        data = load_json(p)
        self._note_paging(data, p.name)
        self.used.append(p.name)
        return items_of(data, p.name)

    def obj(self, *names: str) -> dict | None:
        p = self.path(*names)
        if p is None:
            self.missing.append(names[0])
            return None
        data = load_json(p)
        self.used.append(p.name)
        if isinstance(data, dict) and isinstance(data.get("value"), list):
            return data["value"][0] if data["value"] and isinstance(data["value"][0], dict) else {}
        if not isinstance(data, dict):
            raise InputError(f"{p.name}: expected a JSON object")
        return data

    def dir_lists(self, dirname: str) -> dict[str, list[dict]] | None:
        """Read <folder>/<dirname>/<id>.json files into {id: [objects]}."""
        d = self.folder / dirname
        if not d.is_dir():
            self.missing.append(dirname + "/")
            return None
        out: dict[str, list[dict]] = {}
        for p in sorted(d.glob("*.json")):
            data = load_json(p)
            self._note_paging(data, f"{dirname}/{p.name}")
            out[p.stem] = items_of(data, f"{dirname}/{p.name}")
        self.used.append(dirname + "/")
        return out

    def csv_rows(self, *names: str) -> list[dict] | None:
        p = self.path(*names)
        if p is None:
            self.missing.append(names[0])
            return None
        try:
            with p.open(encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
        except (OSError, csv.Error) as exc:
            raise InputError(f"{p.name}: cannot read CSV: {exc}") from exc
        self.used.append(p.name)
        return rows


def parse_dt(value) -> datetime | None:
    """Parse a Graph timestamp. Returns an aware UTC datetime, or None for empty or unparseable values."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = _FRACTION_RE.sub(r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if dt.year <= 1:  # Graph uses 0001-01-01 for "never"
        return None
    return dt.astimezone(UTC)


def as_of_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    dt = parse_dt(value if "T" in value else value + "T00:00:00Z")
    if dt is None:
        raise InputError(f"--as-of: cannot parse {value!r}; use YYYY-MM-DD")
    return dt


def days_since(value, now: datetime) -> int | None:
    dt = parse_dt(value) if not isinstance(value, datetime) else value
    if dt is None:
        return None
    return (now - dt).days


def iso_day(value) -> str:
    dt = parse_dt(value) if not isinstance(value, datetime) else value
    return dt.strftime("%Y-%m-%d") if dt else "never"


def finding(check: str, severity: str, subject: str, title: str, evidence: str, portal: str = "", graph: str = "") -> dict:
    """One finding. `graph` is a Graph call shown for review; no script ever runs it."""
    if severity not in RANK:
        raise ValueError(f"unknown severity {severity}")
    return {"check": check, "severity": severity, "subject": subject, "finding": title, "evidence": evidence,
            "fix": {"portal": portal, "graph": graph}}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (RANK[f["severity"]], f["check"], f["subject"]))


def counts(findings: list[dict]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}


def exit_code(findings: list[dict], fail_on: str) -> int:
    if fail_on == "NONE":
        return 0
    return 1 if any(RANK[f["severity"]] <= RANK[fail_on] for f in findings) else 0


def token(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:8]


def redact(obj, names: set[str] | None = None):
    """Return a copy of obj with e-mail shaped strings and the given display names replaced by stable tokens."""
    ordered = sorted((n for n in (names or set()) if n and len(n.strip()) > 2), key=len, reverse=True)
    patterns = [(re.compile(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])"), f"person-{token(n)}") for n in ordered]

    def _s(s: str) -> str:
        s = EMAIL_RE.sub(lambda m: f"user-{token(m.group(0))}@redacted.invalid", s)
        for rx, tok in patterns:
            s = rx.sub(tok, s)
        return s

    def _walk(o):
        if isinstance(o, str):
            return _s(o)
        if isinstance(o, list):
            return [_walk(x) for x in o]
        if isinstance(o, dict):
            return {k: _walk(v) for k, v in o.items()}
        return o

    return _walk(obj)


def person_names(users: list[dict] | None) -> set[str]:
    """Display names of user objects, for redact()."""
    return {u.get("displayName", "") for u in users or [] if u.get("displayName")}


def load_config(path: str | None, allowed: set[str]) -> dict:
    if not path:
        return {}
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"{p}: cannot read: {exc}") from exc
    try:
        cfg = json.loads(text) if p.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise InputError(f"{p}: cannot parse: {exc}") from exc
    if cfg is None:
        return {}
    if not isinstance(cfg, dict):
        raise InputError(f"{p}: config must be a mapping")
    unknown = set(cfg) - allowed
    if unknown:
        raise InputError(f"{p}: unknown config keys: {', '.join(sorted(unknown))}")
    return cfg


def cfg_int(cfg: dict, key: str, default: int) -> int:
    value = cfg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InputError(f"config {key} must be a non-negative integer")
    return value


def cell(value) -> str:
    """Tenant text is untrusted: keep it inside its Markdown table cell."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "'")


def render_findings(findings: list[dict]) -> list[str]:
    if not findings:
        return ["No findings at or above the selected severity."]
    lines = ["| # | Severity | Check | Subject | Finding | Evidence |", "|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f['severity']} | {f['check']} | {cell(f['subject'])} | {cell(f['finding'])} | {cell(f['evidence'])} |")
    lines += ["", "### Fix guidance (shown for review, never run by the script)", ""]
    for i, f in enumerate(findings, 1):
        parts = []
        if f["fix"].get("portal"):
            parts.append(f"portal: {cell(f['fix']['portal'])}")
        if f["fix"].get("graph"):
            parts.append(f"Graph: `{cell(f['fix']['graph'])}`")
        if parts:
            lines.append(f"{i}. {'; '.join(parts)}")
    return lines


def render_header(title: str, export: Export | None, as_of: datetime) -> list[str]:
    lines = [f"# {title}", "", f"Evaluated as of {as_of.strftime('%Y-%m-%d')}."]
    if export is not None:
        if export.used:
            lines.append(f"Read: {', '.join(sorted(set(export.used)))}.")
        if export.missing:
            lines.append(f"Not found (checks that need them were skipped): {', '.join(sorted(set(export.missing)))}.")
        for w in export.warnings:
            lines.append(f"Warning: {w}.")
    lines.append("")
    return lines


def add_common_args(ap, fail_on_default: str | None = "HIGH", config: bool = True) -> None:
    if config:
        ap.add_argument("--config", help="thresholds and options (YAML or JSON)")
    ap.add_argument("--as-of", help="evaluate dates as of this day (YYYY-MM-DD); default today")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="replace user principal names, e-mail addresses and person names with tokens")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="INFO", help="hide findings below this severity (default INFO)")
    if fail_on_default is not None:
        ap.add_argument("--fail-on", choices=SEVERITIES + ["NONE"], default=fail_on_default,
                        help=f"exit 1 when a finding is at or above this severity (default {fail_on_default})")


def filter_min(findings: list[dict], min_severity: str) -> list[dict]:
    return [f for f in findings if RANK[f["severity"]] <= RANK[min_severity]]


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=False, default=str)
