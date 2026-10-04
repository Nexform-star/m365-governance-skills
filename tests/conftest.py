"""Shared helpers for the script tests.

Every skill script lives at plugins/m365-governance/skills/<skill>/scripts/<name>.py and is a standalone program, not a
package. Tests load one by path with load_script() and call its main(argv) function, capturing stdout. Nothing here
calls Microsoft Graph or the network: every input is a hand-written fixture under tests/fixtures/ with example ids
(00000000-0000-0000-0000-...) and example.com users.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "plugins" / "m365-governance" / "skills"
FIXTURES = ROOT / "tests" / "fixtures"


def script_path(skill: str, name: str) -> Path:
    return SKILLS / skill / "scripts" / name


def load_script(skill: str, name: str):
    """Import a skill script by path under a unique module name."""
    path = script_path(skill, name)
    module_name = f"skill_{skill}_{path.stem}".replace("-", "_")
    if module_name in sys.modules:
        return sys.modules[module_name]
    # Each skill carries its own copy of _graphio and _miniyaml; drop any copy loaded for another skill.
    for helper in ("_graphio", "_miniyaml"):
        sys.modules.pop(helper, None)
    scripts_dir = str(path.parent)
    if scripts_dir in sys.path:
        sys.path.remove(scripts_dir)
    sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def run_main(module, argv: list[str]) -> tuple[int, str, str]:
    """Run module.main(argv) and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = module.main(argv)
        except SystemExit as exc:  # argparse errors and --help
            rc = int(exc.code or 0)
    return rc, out.getvalue(), err.getvalue()


def run_json(module, argv: list[str]):
    rc, out, err = run_main(module, argv)
    try:
        return rc, json.loads(out)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"not JSON (rc={rc}): {out!r} stderr={err!r}") from exc


@pytest.fixture
def write(tmp_path: Path):
    def _write(rel: str, content: str) -> Path:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p
    return _write
