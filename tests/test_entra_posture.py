import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("entra-posture-review", "entra_posture.py")
INSECURE = str(FIXTURES / "entra" / "insecure")
SECURE = str(FIXTURES / "entra" / "secure")
CFG = str(FIXTURES / "entra" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def test_disabled_users_with_active_and_eligible_roles_are_reported():
    data = json.loads((FIXTURES / "entra" / "disabled-role-holders.json").read_text())
    directory = mod.Directory(data["users"], [], [])
    findings, _ = mod.check_roles(data["assignments"], data["eligible"], None, {}, directory)
    disabled = [f for f in findings if f["check"] == "ROLE-DISABLED-HOLDER"]
    assert len(disabled) == 2
    assert all(f["subject"] == "disabled@example.com" and f["severity"] == "LOW" for f in disabled)
    assert any("active" in f["evidence"] for f in disabled)
    assert any("eligible" in f["evidence"] for f in disabled)


def test_disabled_role_holder_json_threshold_and_redaction(write):
    data = json.loads((FIXTURES / "entra" / "disabled-role-holders.json").read_text())
    write("users.json", json.dumps({"value": data["users"]}))
    root = write("role-assignments.json", json.dumps({"value": data["assignments"]})).parent
    rc, rep = run_json(mod, [str(root), "--json", "--redact", "--fail-on", "LOW"])
    assert rc == 1
    assert len(checks(rep, "ROLE-DISABLED-HOLDER")) == 1
    assert "disabled@example.com" not in json.dumps(rep)


def test_insecure_tenant_flags_planted_defects():
    rc, rep = run_json(mod, [INSECURE, *BASE])
    assert rc == 1
    found = {f["check"] for f in rep["findings"]}
    assert {"CA-NO-MFA-ALL", "CA-NO-MFA-ADMINS", "CA-LEGACY-AUTH", "CA-REPORT-ONLY", "CA-EXCLUSION", "CA-BREAKGLASS-NOT-EXCLUDED",
            "ROLE-GA-PERMANENT", "ROLE-GA-COUNT", "ROLE-GUEST-ADMIN", "ROLE-SP-PRIVILEGED", "GUEST-STALE", "APP-SECRET-EXPIRED",
            "APP-SECRET-EXPIRING", "APP-SECRET-LONG-LIVED", "SP-HIGH-PRIV-APPROLE", "CONSENT-USER-ALLOWED",
            "GUEST-INVITE-EVERYONE", "SIGNIN-LEGACY-USED", "AUDIT-CONSENT"} <= found
    assert rep["counts"]["CRITICAL"] == 2


def test_secure_tenant_is_clean():
    rc, rep = run_json(mod, [SECURE, *BASE])
    assert rc == 0
    assert rep["findings"] == []


def test_pim_activation_and_break_glass_are_not_standing_admins():
    _, rep = run_json(mod, [INSECURE, *BASE])
    standing = sorted(f["subject"] for f in checks(rep, "ROLE-GA-PERMANENT"))
    assert standing == ["admin.one@example.com", "admin.two@example.com", "old.admin@example.com",
                        "partner.admin_example.net#EXT#@example.com"]


def test_without_pim_export_every_active_admin_is_standing(tmp_path):
    for p in (FIXTURES / "entra" / "insecure").iterdir():
        if p.name != "role-assignment-schedule-instances.json":
            (tmp_path / p.name).write_text(p.read_text())
    _, rep = run_json(mod, [str(tmp_path), *BASE])
    assert len(checks(rep, "ROLE-GA-PERMANENT")) == 5
    assert any("schedule" in s for s in rep["skipped"])


def test_exclusions_and_break_glass_lockout():
    _, rep = run_json(mod, [INSECURE, *BASE])
    excl = checks(rep, "CA-EXCLUSION")[0]["evidence"]
    assert "legacy.user@example.com" in excl and "breakglass1" not in excl
    lockout = checks(rep, "CA-BREAKGLASS-NOT-EXCLUDED")
    assert [f["evidence"] for f in lockout] == ["breakglass2@example.com is covered by this all-users policy"]


def test_stale_guests_and_disabled_guest_ignored():
    _, rep = run_json(mod, [INSECURE, *BASE])
    stale = sorted(f["subject"] for f in checks(rep, "GUEST-STALE"))
    assert stale == ["never.signed_example.org#EXT#@example.com", "old.vendor_example.org#EXT#@example.com"]


def test_thresholds_from_config(write):
    cfg = write("cfg.json", json.dumps({"max_global_admins": 10, "stale_guest_days": 400, "max_secret_days": 2000}))
    _, rep = run_json(mod, [INSECURE, "--config", str(cfg), "--as-of", "2026-10-04", "--json"])
    assert not checks(rep, "ROLE-GA-COUNT") and not checks(rep, "GUEST-STALE") and not checks(rep, "APP-SECRET-LONG-LIVED")
    assert checks(rep, "CA-NO-BREAKGLASS")


def test_high_privilege_app_roles_resolved_by_name():
    _, rep = run_json(mod, [INSECURE, *BASE])
    sp = {(f["subject"], f["severity"]) for f in checks(rep, "SP-HIGH-PRIV-APPROLE")}
    assert sp == {("Example Sync Connector", "CRITICAL"), ("Example Reporting", "HIGH")}


def test_security_defaults_on_downgrades_ca_checks(write):
    write("security-defaults.json", json.dumps({"isEnabled": True}))
    write("conditional-access-policies.json", json.dumps({"value": []}))
    rc, rep = run_json(mod, [str(write("x", "").parent), "--json", "--fail-on", "HIGH"])
    assert rc == 0
    assert {f["check"]: f["severity"] for f in rep["findings"]}["CA-NO-MFA-ALL"] == "INFO"


def test_security_defaults_off_and_no_policies(write):
    write("security-defaults.json", json.dumps({"isEnabled": False}))
    write("conditional-access-policies.json", json.dumps({"value": []}))
    rc, rep = run_json(mod, [str(write("x", "").parent), "--json"])
    assert rc == 1 and checks(rep, "SECDEF-OFF-NO-CA")


def test_redact_hides_upns_and_names():
    rc, out, _ = run_main(mod, [INSECURE, *BASE, "--redact"])
    assert rc == 1
    assert "@example.com" not in out and "Legacy User" not in out
    assert "@redacted.invalid" in out


def test_markdown_output_and_paging_warning(write):
    write("users.json", json.dumps({"value": [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=x"}))
    rc, out, _ = run_main(mod, [str(write("x", "").parent), "--as-of", "2026-10-04"])
    assert rc == 0
    assert "# Entra ID posture review" in out and "only the first page" in out


def test_bad_input_exit_2(write, tmp_path):
    rc, _, err = run_main(mod, [str(tmp_path / "missing")])
    assert rc == 2 and "not a folder" in err
    write("conditional-access-policies.json", "{not json")
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "invalid JSON" in err
    cfg = write("c.yaml", "unknown_key: 1\n")
    rc, _, err = run_main(mod, [INSECURE, "--config", str(cfg)])
    assert rc == 2 and "unknown config keys" in err
