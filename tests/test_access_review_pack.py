import csv

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("access-review-pack", "access_review_pack.py")
T = str(FIXTURES / "access-review" / "tenant")
CFG = str(FIXTURES / "access-review" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04"]


def section(rep, name):
    return [(r["item"], r["principal"]) for r in rep["rows"] if r["section"] == name]


def test_counts_per_section():
    rc, rep = run_json(mod, [T, *BASE, "--json"])
    assert rc == 0
    assert rep["counts"] == {"privileged-roles": 4, "app-owners": 3, "sensitive-group-owners": 3, "guests-per-group": 2,
                             "expiring-credentials": 3}


def test_role_holders_include_eligible_guest_and_service_principal():
    _, rep = run_json(mod, [T, *BASE, "--json"])
    rows = {r["principal"]: r for r in rep["rows"] if r["section"] == "privileged-roles"}
    assert rows["ben@example.com"]["detail"] == "eligible, user"
    assert rows["ben@example.com"]["last_sign_in"] == "2026-06-15"
    assert rows["guest_example.net#EXT#@example.com"]["detail"] == "active, guest"
    assert rows["Example HR Provisioning"]["detail"].startswith("active, service principal, scope /administrativeUnits/")
    assert rows["ana@example.com"]["reviewer"] == "security-lead@example.com"


def test_only_privileged_roles(write):
    cfg = write("c.yaml", "only_privileged_roles: true\n")
    _, rep = run_json(mod, [T, "--config", str(cfg), "--as-of", "2026-10-04", "--json"])
    assert {i for i, _ in section(rep, "privileged-roles")} == {"Global Administrator", "User Administrator"}


def test_app_owners_and_sensitive_groups():
    _, rep = run_json(mod, [T, *BASE, "--json"])
    apps = dict(section(rep, "app-owners"))
    assert apps["Example Legacy Portal (00000000-0000-0000-0000-000000000a42)"] == "NO OWNER"
    assert apps["Example Wiki (00000000-0000-0000-0000-000000000a43)"] == "owners not exported"
    assert section(rep, "sensitive-group-owners") == [("Finance Approvers", "ana@example.com"), ("Finance Approvers", "ben@example.com"),
                                                      ("Payroll Admins", "NO OWNER")]


def test_expiring_credentials_window():
    _, rep = run_json(mod, [T, *BASE, "--json"])
    details = sorted(r["detail"] for r in rep["rows"] if r["section"] == "expiring-credentials")
    assert details == ["expired 2026-08-01", "expires 2026-11-15 (42 days)", "expires 2026-12-20 (77 days)"]


def test_out_dir_writes_checklist_and_csv(tmp_path):
    rc, out, _ = run_main(mod, [T, *BASE, "--out-dir", str(tmp_path)])
    assert rc == 0 and "Wrote" in out
    md = (tmp_path / "access-review.md").read_text(encoding="utf-8")
    assert md.startswith("# Q4 2026 access review") and "- [ ] **Payroll Admins**: NO OWNER" in md
    rows = list(csv.DictReader((tmp_path / "access-review-signoff.csv").open(encoding="utf-8")))
    assert list(rows[0].keys()) == ["section", "item", "principal", "detail", "last_sign_in", "reviewer", "decision", "date"]
    assert len(rows) == 15 and all(r["decision"] == "" and r["date"] == "" for r in rows)


def test_redacted_pack_has_no_upns(tmp_path):
    rc, _, _ = run_main(mod, [T, *BASE, "--out-dir", str(tmp_path), "--redact"])
    assert rc == 0
    text = (tmp_path / "access-review.md").read_text(encoding="utf-8") + (tmp_path / "access-review-signoff.csv").read_text(encoding="utf-8")
    assert "@example.com" not in text and "Ana Example" not in text


def test_missing_sections_are_listed(tmp_path):
    rc, out, _ = run_main(mod, [str(tmp_path)])
    assert rc == 0 and "## Not included" in out


def test_bad_reviewers_config(write):
    rc, _, err = run_main(mod, [T, "--config", str(write("c.yaml", "reviewers: {everything: me@example.com}\n"))])
    assert rc == 2 and "reviewers" in err
