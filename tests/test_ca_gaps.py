import json
import shutil

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("conditional-access-gap-analysis", "ca_gaps.py")
GAPS = FIXTURES / "ca-gaps" / "gaps"
MET = str(FIXTURES / "ca-gaps" / "baseline-met")
CFG = str(FIXTURES / "ca-gaps" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def test_planted_gaps_are_found():
    rc, rep = run_json(mod, [str(GAPS), *BASE])
    assert rc == 1
    assert {f["check"] for f in rep["findings"]} == {
        "CA-GAP-MFA-ALL", "CA-GAP-MFA-ADMINS", "CA-GAP-LEGACY-AUTH", "CA-GAP-ADMIN-DEVICE", "CA-GAP-SIGNIN-RISK", "CA-GAP-USER-RISK",
        "CA-GAP-UNMANAGED-SESSION", "CA-BREAKGLASS-NOT-EXCLUDED", "CA-EXCLUSION-HAS-ADMIN", "CA-EXCLUSION-UNEXPLAINED",
        "CA-REPORT-ONLY-STALE", "CA-INCLUDE-EXCLUDE-CANCEL", "CA-ZERO-TARGET", "CA-OVERLAP", "CA-LOCATION-BROAD",
        "CA-TRUSTED-LOCATION-SKIP", "CA-DISABLED"}
    assert rep["counts"] == {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 9, "LOW": 3, "INFO": 2}


def test_baseline_met_is_clean():
    rc, rep = run_json(mod, [MET, *BASE])
    assert rc == 0
    assert rep["findings"] == []
    assert rep["personas"] == {"all users": 6, "admins": 2, "guests": 1, "break-glass": 2}


def test_exclusion_group_with_an_admin():
    _, rep = run_json(mod, [str(GAPS), *BASE])
    [f] = checks(rep, "CA-EXCLUSION-HAS-ADMIN")
    assert f["subject"] == "CA Exclusion - Service Accounts (group)"
    assert "admin.two@example.com" in f["evidence"] and "svc.scanner" not in f["evidence"]
    [mfa_admins] = checks(rep, "CA-GAP-MFA-ADMINS")
    assert mfa_admins["severity"] == "CRITICAL" and "1 of 2 not covered: admin.two@example.com" in mfa_admins["evidence"]


def test_report_only_policy_from_months_ago():
    _, rep = run_json(mod, [str(GAPS), *BASE])
    [f] = checks(rep, "CA-REPORT-ONLY-STALE")
    assert f["subject"] == "Block legacy authentication" and f["finding"] == "Report-only for 216 days"
    legacy = checks(rep, "CA-GAP-LEGACY-AUTH")[0]["evidence"]
    assert legacy.startswith("6 of 6 not covered") and "no qualifying enabled policy" in legacy


def test_report_only_age_threshold_is_configurable(write):
    cfg = write("c.yaml", "report_only_max_days: 365\nbreak_glass_groups: [00000000-0000-0000-0000-0000000009b0]\n")
    _, rep = run_json(mod, [str(GAPS), "--config", str(cfg), "--as-of", "2026-10-04", "--json"])
    assert not checks(rep, "CA-REPORT-ONLY-STALE")


def test_include_and_exclude_cancel_out():
    _, rep = run_json(mod, [str(GAPS), *BASE])
    [cancel] = checks(rep, "CA-INCLUDE-EXCLUDE-CANCEL")
    [zero] = checks(rep, "CA-ZERO-TARGET")
    assert cancel["subject"] == zero["subject"] == "Pilot - require compliant device"
    assert "Pilot Users (group)" in cancel["evidence"] and zero["evidence"].endswith("include and exclude cancel out")


def test_break_glass_lockout_only_for_the_one_not_excluded():
    _, rep = run_json(mod, [str(GAPS), *BASE])
    assert [f["subject"] for f in checks(rep, "CA-BREAKGLASS-NOT-EXCLUDED")] == ["breakglass2@example.com"]


def test_explained_exclusions_clear_the_finding(write):
    cfg = write("c.yaml", "break_glass: [breakglass1@example.com, breakglass2@example.com]\nexplained_exclusions:\n"
                "  00000000-0000-0000-0000-000000000901: Scanner accounts, change CHG-0001\n"
                "  00000000-0000-0000-0000-000000000902: Pilot\n  00000000-0000-0000-0000-0000000009b0: Break glass group\n")
    _, rep = run_json(mod, [str(GAPS), "--config", str(cfg), "--as-of", "2026-10-04", "--json"])
    assert not checks(rep, "CA-EXCLUSION-UNEXPLAINED")
    assert checks(rep, "CA-EXCLUSION-HAS-ADMIN"), "an explained exclusion that holds an admin is still reported"


def test_coverage_matrix():
    _, rep = run_json(mod, [str(GAPS), *BASE])
    rows = {r["policy"]: r for r in rep["matrix"]}
    assert "Old MFA policy for Office" not in rows
    assert rows["Require MFA for all users"] == {"policy": "Require MFA for all users", "state": "enabled", "controls": "mfa",
                                                 "all users": "4/6", "admins": "1/2", "guests": "1/1", "break-glass": "1/2"}
    assert rows["Block legacy authentication"]["state"] == "report-only"


def test_markdown_report_has_matrix_and_no_network_promise():
    rc, out, _ = run_main(mod, [str(GAPS), "--config", CFG, "--as-of", "2026-10-04"])
    assert rc == 1
    assert "## Coverage matrix" in out and "| Require MFA for all users | enabled | mfa | 4/6 | 1/2 | 1/1 | 1/2 |" in out


def test_missing_member_export_is_not_a_zero_target(tmp_path):
    shutil.copytree(GAPS, tmp_path / "t")
    (tmp_path / "t" / "group-members" / "00000000-0000-0000-0000-000000000902.json").unlink()
    _, rep = run_json(mod, [str(tmp_path / "t"), *BASE])
    assert not checks(rep, "CA-ZERO-TARGET")
    assert any("Pilot Users" in s for s in rep["not_evaluated"])


def test_without_users_gaps_are_checked_structurally(tmp_path):
    policies = (GAPS / "conditional-access-policies.json").read_text(encoding="utf-8")
    (tmp_path / "conditional-access-policies.json").write_text(policies, encoding="utf-8")
    rc, rep = run_json(mod, [str(tmp_path), *BASE])
    assert rc == 1 and rep["matrix"][0]["all users"] == "?"
    assert "structurally" in checks(rep, "CA-GAP-LEGACY-AUTH")[0]["evidence"]
    assert not checks(rep, "CA-GAP-MFA-ALL")


def test_redact_removes_user_names():
    _, out, _ = run_main(mod, [str(GAPS), *BASE, "--redact"])
    assert "@example.com" not in out and "Admin Two" not in out
    assert json.loads(out)["findings"]


def test_bad_input_exits_2(tmp_path, write):
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "conditional-access-policies.json" in err
    rc, _, err = run_main(mod, [str(GAPS), "--config", str(write("c.yaml", "explained_exclusions: [a, b]\n"))])
    assert rc == 2 and "explained_exclusions" in err
