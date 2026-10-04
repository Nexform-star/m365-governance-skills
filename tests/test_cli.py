"""Tests for scripts/cli.py, the m365-governance dispatcher used as the container entrypoint."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "cli.py"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, timeout=60, cwd=ROOT)


def load_cli():
    import importlib.util

    spec = importlib.util.spec_from_file_location("m365_governance_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_help_lists_every_subcommand():
    cli = load_cli()
    result = run("--help")
    assert result.returncode == 0
    assert result.stdout.startswith("usage: m365-governance <subcommand>")
    for name, (_, script, _) in cli.COMMANDS.items():
        assert f"  {name} " in result.stdout
        assert script in result.stdout


def test_every_subcommand_points_at_an_existing_script_and_answers_help():
    cli = load_cli()
    for name in cli.COMMANDS:
        assert cli.script_path(name).is_file(), name
        result = run(name, "--help")
        assert result.returncode == 0, (name, result.stderr)
        assert result.stdout.startswith("usage: "), name


def test_every_skill_script_has_a_subcommand():
    cli = load_cli()
    covered = {cli.script_path(n).resolve() for n in cli.COMMANDS}
    scripts = {p.resolve() for p in cli.SKILLS.glob("*/scripts/[a-z]*.py")}
    assert scripts == covered


def test_help_subcommand_shows_the_script_help():
    result = run("help", "preflight")
    assert result.returncode == 0
    assert "permission_preflight.py" in result.stdout


def test_unknown_subcommand_and_no_arguments_exit_2():
    result = run("no-such-command")
    assert result.returncode == 2
    assert "unknown subcommand" in result.stderr
    assert run().returncode == 2


def test_exit_code_and_arguments_pass_through():
    result = run("preflight", "--definitely-not-an-option")
    assert result.returncode == 2
    assert "usage: " in result.stderr


@pytest.mark.parametrize("name,fixture,expected", [
    ("ca-gaps", "ca-gaps/gaps", "CA-EXCLUSION-HAS-ADMIN"),
    ("pim-review", "pim-review/tenant", "PIM-PERMANENT-PRIVILEGED"),
    ("external-sharing", "external-sharing/tenant", "GUEST-BLOCKED-DOMAIN"),
    ("license-audit", "license-audit/tenant", "LIC-DISABLED-ACCOUNT"),
])
def test_new_subcommands_run_on_their_fixtures(name, fixture, expected):
    folder = ROOT / "tests" / "fixtures" / fixture
    config = folder.parent / "config.yaml"
    result = run(name, str(folder), "--config", str(config), "--as-of", "2026-10-04", "--json")
    assert result.returncode == 1, result.stderr
    assert expected in {f["check"] for f in json.loads(result.stdout)["findings"]}


def test_version_matches_the_project_version():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    plugin_json = ROOT / "plugins" / "m365-governance" / ".claude-plugin" / "plugin.json"
    plugin = json.loads(plugin_json.read_text(encoding="utf-8"))
    expected = pyproject.get("project", {}).get("version", plugin["version"])
    assert plugin["version"] == expected
    result = run("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == f"m365-governance {expected}"


def test_cli_is_executable_with_a_shebang():
    assert CLI.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3")
    if os.name == "posix":
        assert os.access(CLI, os.X_OK)
