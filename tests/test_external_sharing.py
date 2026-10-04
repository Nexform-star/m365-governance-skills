import csv
import json
import shutil

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("guest-and-external-sharing-review", "external_sharing.py")
T = FIXTURES / "external-sharing" / "tenant"
RESTRICTED = str(FIXTURES / "external-sharing" / "restricted")
CFG = str(FIXTURES / "external-sharing" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]
PAT = "pat_example.net#EXT#@example.com"


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def test_planted_blocked_domain_guest_in_sensitive_group():
    rc, rep = run_json(mod, [str(T), *BASE])
    assert rc == 1
    [blocked] = checks(rep, "GUEST-BLOCKED-DOMAIN")
    assert (blocked["subject"], blocked["severity"]) == (PAT, "CRITICAL")
    assert blocked["evidence"] == "domain example.net; in sensitive groups: Finance Approvers"
    assert [f["subject"] for f in checks(rep, "GUEST-SENSITIVE-GROUP")] == [PAT]


def test_all_planted_checks():
    _, rep = run_json(mod, [str(T), *BASE])
    assert {f["check"] for f in rep["findings"]} == {
        "GUEST-BLOCKED-DOMAIN", "GUEST-SENSITIVE-GROUP", "GUEST-STALE", "GUEST-PENDING", "SHARING-ANYONE", "SHARING-ANYONE-ONEDRIVE",
        "SHARING-ANYONE-NO-EXPIRY", "SHARING-NO-DOMAIN-RESTRICTION", "SHARING-RESHARE", "TEAMS-ALL-EXTERNAL-DOMAINS", "TEAMS-CONSUMER"}
    assert rep["counts"] == {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 3, "LOW": 4, "INFO": 0}
    assert rep["guests"] == 4


def test_restricted_tenant_is_clean():
    rc, rep = run_json(mod, [RESTRICTED, *BASE])
    assert rc == 0 and rep["findings"] == [] and rep["removal_draft"] == []


def test_stale_and_pending_guests():
    _, rep = run_json(mod, [str(T), *BASE])
    assert [f["subject"] for f in checks(rep, "GUEST-STALE")] == ["old.vendor_example.org#EXT#@example.com"]
    [pending] = checks(rep, "GUEST-PENDING")
    assert pending["subject"] == "new.partner_example.org#EXT#@example.com" and "64 days" in pending["evidence"]


def test_access_map_and_inviters():
    _, rep = run_json(mod, [str(T), *BASE])
    rows = {r["guest"]: r for r in rep["access_map"]}
    assert set(rows) == {PAT, "old.vendor_example.org#EXT#@example.com", "new.partner_example.org#EXT#@example.com",
                         "good.partner_example.org#EXT#@example.com"}
    assert rows[PAT]["groups"] == ["Finance Approvers (sensitive)"] and rows[PAT]["inviter"] == "fay.finance@example.com"
    assert rows[PAT]["domain"] == "example.net"
    assert rows["old.vendor_example.org#EXT#@example.com"]["inviter"] == "not in audit export"


def test_removal_list_is_a_draft(tmp_path):
    path = tmp_path / "draft.csv"
    rc, out, _ = run_main(mod, [str(T), "--config", CFG, "--as-of", "2026-10-04", "--csv", str(path)])
    assert rc == 1 and "## Removal list (DRAFT" in out
    rows = list(csv.DictReader(path.open()))
    assert [r["guest"] for r in rows] == ["new.partner_example.org#EXT#@example.com", "old.vendor_example.org#EXT#@example.com", PAT]
    assert all(r["status"] == "DRAFT" and r["decision"] == "" for r in rows)
    assert rows[2]["reasons"] == "blocked domain"


def test_allow_list_mode_reports_other_domains(tmp_path):
    shutil.copytree(T, tmp_path / "t")
    settings = json.loads((T / "sharepoint-settings.json").read_text())
    settings.update({"sharingDomainRestrictionMode": "allowList", "sharingAllowedDomainList": ["example.org"]})
    (tmp_path / "t" / "sharepoint-settings.json").write_text(json.dumps(settings))
    _, rep = run_json(mod, [str(tmp_path / "t"), "--as-of", "2026-10-04", "--json"])
    [f] = checks(rep, "GUEST-BLOCKED-DOMAIN")
    assert f["finding"] == "Guest from a domain not on the allow list"
    assert not checks(rep, "SHARING-NO-DOMAIN-RESTRICTION")


def test_spo_numbers_and_names_are_both_read(tmp_path, write):
    write("u/users.json", '{"value": []}')
    write("u/spo-tenant.json", '{"SharingCapability": "ExternalUserAndGuestSharing", "OneDriveSharingCapability": 1, '
                               '"RequireAnonymousLinksExpireInDays": 14}')
    _, rep = run_json(mod, [str(tmp_path / "u"), "--json"])
    assert [f["check"] for f in rep["findings"]] == []
    write("u/spo-tenant.json", '{"SharingCapability": 0, "OneDriveSharingCapability": "ExternalUserAndGuestSharing"}')
    _, rep = run_json(mod, [str(tmp_path / "u"), "--json"])
    assert sorted(f["check"] for f in rep["findings"]) == ["SHARING-ANYONE-NO-EXPIRY", "SHARING-ANYONE-ONEDRIVE"]


def test_teams_allow_list_is_not_open():
    _, rep = run_json(mod, [RESTRICTED, *BASE])
    assert not checks(rep, "TEAMS-ALL-EXTERNAL-DOMAINS")
    assert mod.domain_list([{"Domain": "example.org"}, "example.net"]) == ["example.org", "example.net"]


def test_redact_keeps_domains_and_drops_people():
    _, out, _ = run_main(mod, [str(T), *BASE, "--redact"])
    assert "@example.com" not in out and "Pat Contractor" not in out and "Fay Finance" not in out
    assert '"domain": "example.net"' in out


def test_bad_input(tmp_path, write):
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "users.json" in err
    rc, _, err = run_main(mod, [str(T), "--config", str(write("c.yaml", 'sensitive_pattern: "(unclosed"\n'))])
    assert rc == 2 and "sensitive_pattern" in err
