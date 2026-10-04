"""Checks that cover every skill: identical helper copies, no network code, --help, and the shared helpers."""
import re

import pytest
from conftest import SKILLS, load_script, run_main

SCRIPTS = {
    "graph-permission-preflight": "permission_preflight.py",
    "entra-posture-review": "entra_posture.py",
    "intune-baseline-check": "intune_baseline.py",
    "teams-and-groups-sprawl": "groups_sprawl.py",
    "access-review-pack": "access_review_pack.py",
    "conditional-access-gap-analysis": "ca_gaps.py",
    "privileged-access-review": "pim_review.py",
    "guest-and-external-sharing-review": "external_sharing.py",
    "license-and-service-plan-audit": "license_audit.py",
}
gio = load_script("entra-posture-review", "_graphio.py")


@pytest.mark.parametrize("helper", ["_graphio.py", "_miniyaml.py"])
def test_helper_copies_are_identical(helper):
    copies = {skill: (SKILLS / skill / "scripts" / helper).read_text() for skill in SCRIPTS}
    assert len(set(copies.values())) == 1, f"{helper} differs between skills: copy one version to every skill"


@pytest.mark.parametrize("skill", sorted(SCRIPTS))
def test_scripts_have_no_network_or_subprocess_code(skill):
    for path in (SKILLS / skill / "scripts").glob("*.py"):
        text = path.read_text()
        assert not re.search(r"^\s*(import|from)\s+(socket|subprocess|urllib|http|requests|ssl|ftplib|smtplib)\b", text, re.M), path


@pytest.mark.parametrize("skill,script", sorted(SCRIPTS.items()))
def test_help_and_redact_flag(skill, script):
    mod = load_script(skill, script)
    rc, out, _ = run_main(mod, ["--help"])
    assert rc == 0
    assert "--redact" in out and "--json" in out and "Exit codes" in out


def test_parse_dt_handles_graph_formats():
    assert gio.parse_dt("2026-01-10T08:00:00.1234567Z").isoformat() == "2026-01-10T08:00:00.123456+00:00"
    assert gio.parse_dt("2026-01-10T08:00:00Z").day == 10
    assert gio.parse_dt("0001-01-01T00:00:00Z") is None
    assert gio.parse_dt("") is None and gio.parse_dt("not a date") is None


def test_items_of_accepts_envelope_list_and_object():
    assert gio.items_of({"value": [{"id": 1}]}) == [{"id": 1}]
    assert gio.items_of([{"id": 2}]) == [{"id": 2}]
    assert gio.items_of({"id": 3}) == [{"id": 3}]
    with pytest.raises(gio.InputError):
        gio.items_of([1, 2])


def test_redact_is_stable_and_covers_guest_upns():
    data = {"a": "owner jane.doe@example.com and partner_example.net#EXT#@example.com", "b": ["Jane Doe signed in"]}
    out = gio.redact(data, {"Jane Doe"})
    assert "@example.com" not in out["a"] and "Jane Doe" not in out["b"][0]
    assert gio.redact(data, {"Jane Doe"}) == out
    assert out["a"].count("@redacted.invalid") == 2


def test_cell_keeps_untrusted_text_in_its_cell():
    assert gio.cell("a|b\nc`d") == "a\\|b c'd"


@pytest.mark.parametrize("skill,script,ref", [
    ("entra-posture-review", "entra_posture.py", "example-config.yaml"),
    ("intune-baseline-check", "intune_baseline.py", "example-config.yaml"),
    ("teams-and-groups-sprawl", "groups_sprawl.py", "example-config.yaml"),
    ("access-review-pack", "access_review_pack.py", "example-config.yaml"),
    ("conditional-access-gap-analysis", "ca_gaps.py", "example-config.yaml"),
    ("privileged-access-review", "pim_review.py", "example-config.yaml"),
    ("guest-and-external-sharing-review", "external_sharing.py", "example-config.yaml"),
    ("license-and-service-plan-audit", "license_audit.py", "example-config.yaml"),
])
def test_reference_configs_load(skill, script, ref):
    mod = load_script(skill, script)
    cfg = mod.load_config(str(SKILLS / skill / "references" / ref), mod.CONFIG_KEYS)
    assert cfg


def test_reference_needs_manifest_loads():
    mod = load_script("graph-permission-preflight", "permission_preflight.py")
    manifest = mod.load_needs(str(SKILLS / "graph-permission-preflight" / "references" / "example-needs.yaml"))
    assert [(n["name"], n["type"]) for n in manifest["needs"]] == [("Calendars.Read", "Application"), ("User.Read", "Delegated")]
