import csv
import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("teams-and-groups-sprawl", "groups_sprawl.py")
T = str(FIXTURES / "groups" / "tenant")
CFG = str(FIXTURES / "groups" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def by(rep, check):
    return {f["subject"].split(" (")[0]: f["severity"] for f in rep["findings"] if f["check"] == check}


def test_ownerless_severity_by_kind():
    rc, rep = run_json(mod, [T, *BASE])
    assert rc == 1
    assert by(rep, "GRP-OWNERLESS") == {"Finance Team": "HIGH", "TMP-old-project": "MEDIUM", "VPN Users": "LOW"}
    assert by(rep, "GRP-SINGLE-OWNER") == {"PRJ-Apollo": "LOW"}


def test_guests_public_inactive_naming_expiration():
    _, rep = run_json(mod, [T, *BASE])
    assert by(rep, "GRP-GUESTS") == {"Finance Team": "MEDIUM", "PRJ-Apollo": "LOW"}
    assert by(rep, "TEAM-PUBLIC") == {"Finance Team": "MEDIUM"}
    assert by(rep, "GRP-PUBLIC") == {"DEP-Marketing": "LOW"}
    assert by(rep, "TEAM-INACTIVE") == {"Finance Team": "LOW"}
    assert by(rep, "GRP-NAMING") == {"Finance Team": "LOW"}  # VPN Users is a security group, outside naming_applies_to
    assert by(rep, "GRP-NO-EXPIRATION") == {"Finance Team": "LOW"}
    assert by(rep, "GRP-EMPTY") == {"TMP-old-project": "LOW"}
    assert "PRJ-Zeus: not in teams-activity.csv" in rep["not_evaluated"]


def test_proposed_owner_is_most_common_manager():
    _, rep = run_json(mod, [T, *BASE])
    rows = {r["name"]: r for r in rep["cleanup"]}
    assert rows["Finance Team"]["proposed_owner"].startswith("dana@example.com (manager of 2")
    assert rows["TMP-old-project"]["proposed_owner"] == ""
    assert rows["DEP-Marketing"]["proposed_owner"] == ""  # has two owners
    assert "PRJ-Zeus" not in rows


def test_cleanup_csv(tmp_path):
    out = tmp_path / "cleanup.csv"
    rc, _, _ = run_main(mod, [T, "--config", CFG, "--as-of", "2026-10-04", "--csv", str(out)])
    assert rc == 1
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["name"] == "Finance Team" and rows[0]["decision"] == ""
    assert len(rows) == 5


def test_no_lifecycle_policy(write):
    write("groups.json", json.dumps({"value": [{"id": "g", "displayName": "X", "groupTypes": ["Unified"], "expirationDateTime": None}]}))
    write("group-lifecycle-policies.json", json.dumps({"value": []}))
    _, rep = run_json(mod, [str(write("x", "").parent), "--json"])
    assert by(rep, "EXP-NO-POLICY") == {"tenant": "MEDIUM"}
    assert any("group-owners" in s for s in rep["not_evaluated"])


def test_default_config_flags_no_naming():
    _, rep = run_json(mod, [T, "--as-of", "2026-10-04", "--json"])
    assert by(rep, "GRP-NAMING") == {}


def test_redact_hides_people():
    rc, out, _ = run_main(mod, [T, *BASE, "--redact"])
    assert rc == 1
    assert "@example.com" not in out and "Dana Example" not in out


def test_bad_config(write):
    rc, _, err = run_main(mod, [T, "--config", str(write("c.yaml", "naming_pattern: \"([\"\n"))])
    assert rc == 2 and "regular expression" in err
    rc, _, err = run_main(mod, [T, "--config", str(write("c2.yaml", "naming_applies_to: [teams]\n"))])
    assert rc == 2 and "unknown kinds" in err
