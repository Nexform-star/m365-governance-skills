import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("graph-permission-preflight", "permission_preflight.py")
PF = FIXTURES / "preflight"


def run(folder, needs, *extra):
    return run_json(mod, [str(PF / folder), "--needs", str(PF / folder / needs), "--as-of", "2026-10-04", "--json", *extra])


def by(rep, check):
    return {f["subject"].split(" ")[0]: f["severity"] for f in rep["findings"] if f["check"] == check}


def test_over_broad_app_flags():
    rc, rep = run("over-broad", "needs.yaml")
    assert rc == 1
    assert by(rep, "PERM-BROADER") == {"Mail.ReadWrite": "HIGH"}
    assert by(rep, "PERM-UNUSED") == {"Directory.ReadWrite.All": "HIGH", "Sites.FullControl.All": "HIGH",
                                      "Files.Read.All": "MEDIUM", "Mail.Send": "MEDIUM"}
    assert by(rep, "PERM-HIGH-RISK")["Directory.ReadWrite.All"] == "CRITICAL"


def test_delegated_risk_is_one_level_lower():
    _, rep = run("over-broad", "needs.yaml")
    risk = by(rep, "PERM-HIGH-RISK")
    assert risk["Mail.Send"] == "MEDIUM"  # HIGH as application, delegated here
    assert risk["Files.Read.All"] == "LOW"


def test_consent_types():
    _, rep = run("over-broad", "needs.yaml")
    assert by(rep, "CONSENT-USER") == {"Mail.Send": "MEDIUM"}
    assert set(by(rep, "CONSENT-ADMIN-ALL")) == {"Files.Read.All", "User.Read"}
    assert set(by(rep, "CONSENT-PENDING")) == {"Sites.FullControl.All"}
    status = {p["permission"]: p["status"] for p in rep["permissions"]}
    assert status["Sites.FullControl.All"] == "requested, not consented"


def test_grants_of_other_apps_are_ignored():
    _, rep = run("over-broad", "needs.yaml")
    perms = {(p["permission"], p["type"]) for p in rep["permissions"]}
    assert ("Mail.Read", "Application") not in perms
    assert ("Directory.ReadWrite.All", "Delegated") not in perms


def test_unresolved_ids_reported():
    _, rep = run("over-broad", "needs.yaml")
    assert any(f["check"] == "PERM-UNRESOLVED" for f in rep["findings"])


def test_least_privilege_set_is_the_needs_list():
    _, rep = run("over-broad", "needs.yaml")
    assert [(r["permission"], r["type"]) for r in rep["least_privilege_set"]] == [
        ("Calendars.Read", "Application"), ("Mail.Read", "Application"), ("User.Read", "Delegated")]


def test_connector_application_where_delegated_suffices():
    rc, rep = run("connector", "needs.json")
    assert rc == 1
    assert by(rep, "PERM-APP-NOT-DELEGATED") == {"Mail.ReadWrite": "HIGH", "User.Read.All": "HIGH"}
    assert by(rep, "PERM-UNUSED") == {"Chat.Read.All": "HIGH"}
    assert set(by(rep, "PERM-MISSING")) == {"Mail.Read", "User.ReadBasic.All"}


def test_minimal_app_passes():
    rc, rep = run("minimal", "needs.yaml", "--fail-on", "LOW")
    assert rc == 0
    assert {f["check"] for f in rep["findings"]} == {"CONSENT-ADMIN-ALL"}


def test_covers_ladder():
    assert mod.covers("Mail.ReadWrite", "Mail.Read")
    assert mod.covers("Sites.FullControl.All", "Sites.Read.All")
    assert mod.covers("Directory.Read.All", "User.Read.All")
    assert mod.covers("User.Read.All", "User.ReadBasic.All")
    assert not mod.covers("Mail.Read", "Mail.ReadWrite")
    assert not mod.covers("Mail.Read", "Mail.Read.Shared")
    assert not mod.covers("Mail.Send", "Mail.Read")


def test_markdown_and_redact():
    rc, out, _ = run_main(mod, [str(PF / "over-broad"), "--needs", str(PF / "over-broad" / "needs.yaml"), "--redact"])
    assert rc == 1
    assert "## Least-privilege replacement set" in out and "| Mail.Read | Application |" in out


def test_bad_needs(write, tmp_path):
    rc, _, err = run_main(mod, [str(PF / "minimal"), "--needs", str(write("n.yaml", "needs: []\n"))])
    assert rc == 2 and "empty" in err
    rc, _, err = run_main(mod, [str(PF / "minimal"), "--needs", str(write("n2.json", json.dumps({"needs": [{"permission": "X", "type": "Weird"}]})))])
    assert rc == 2 and "unknown permission type" in err
    empty = tmp_path / "empty"
    empty.mkdir()
    rc, _, err = run_main(mod, [str(empty), "--needs", str(PF / "minimal" / "needs.yaml")])
    assert rc == 2 and "no permission source" in err
