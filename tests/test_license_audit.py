import csv

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("license-and-service-plan-audit", "license_audit.py")
T = str(FIXTURES / "license-audit" / "tenant")
TIDY = str(FIXTURES / "license-audit" / "tidy")
CFG = str(FIXTURES / "license-audit" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def test_planted_disabled_account_with_e5():
    rc, rep = run_json(mod, [T, *BASE])
    assert rc == 1
    [f] = checks(rep, "LIC-DISABLED-ACCOUNT")
    assert (f["subject"], f["evidence"]) == ("left.employee@example.com", "licences: SPE_E5; last sign-in 2026-06-01")
    assert {"user": "left.employee@example.com", "sku": "SPE_E5", "reasons": ["account disabled"], "assigned_by": "direct",
            "last_sign_in": "2026-06-01"} in rep["reclaim"]


def test_all_planted_checks():
    _, rep = run_json(mod, [T, *BASE])
    assert rep["counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 4, "INFO": 2}
    assert [f["subject"] for f in checks(rep, "LIC-NEVER-SIGNED-IN")] == ["never.used@example.com"]
    assert [f["subject"] for f in checks(rep, "LIC-INACTIVE")] == ["quiet.user@example.com"]
    assert all(f["subject"] != "left.employee@example.com" for f in checks(rep, "LIC-INACTIVE"))


def test_tidy_tenant_is_clean():
    rc, rep = run_json(mod, [TIDY, *BASE])
    assert rc == 0 and rep["findings"] == [] and rep["reclaim"] == []


def test_overlap_from_service_plans():
    _, rep = run_json(mod, [T, *BASE])
    [f] = checks(rep, "LIC-OVERLAP")
    assert f["subject"] == "double.licensed@example.com"
    assert f["evidence"] == "7 of 7 service plans of ENTERPRISEPACK are also in SPE_E5"
    reclaim = [(r["user"], r["sku"]) for r in rep["reclaim"] if r["user"] == "double.licensed@example.com"]
    assert reclaim == [("double.licensed@example.com", "ENTERPRISEPACK")]


def test_overlap_ratio_and_configured_pairs(write):
    strict = write("c.yaml", "overlap_ratio: 1.5\n")
    _, rep = run_json(mod, [T, "--config", str(strict), "--as-of", "2026-10-04", "--json"])
    assert not checks(rep, "LIC-OVERLAP")
    paired = write("p.yaml", "overlap_ratio: 1.5\noverlapping_skus: [[SPE_E5, ENTERPRISEPACK]]\n")
    _, rep = run_json(mod, [T, "--config", str(paired), "--as-of", "2026-10-04", "--json"])
    assert "listed under overlapping_skus" in checks(rep, "LIC-OVERLAP")[0]["evidence"]


def test_unwanted_plans_respect_disabled_plans():
    _, rep = run_json(mod, [T, *BASE])
    plans = {f["subject"]: f["evidence"] for f in checks(rep, "LIC-UNWANTED-PLAN")}
    assert plans == {"SWAY": "enabled for 4 user(s) through ENTERPRISEPACK, SPE_E5",
                     "YAMMER_ENTERPRISE": "enabled for 4 user(s) through ENTERPRISEPACK, SPE_E5"}


def test_group_based_licensing_error():
    _, rep = run_json(mod, [T, *BASE])
    [f] = checks(rep, "LIC-GROUP-ERROR")
    assert f["subject"] == "Licence - Microsoft 365 E5" and f["evidence"] == "1 user(s), errors: CountViolation"


def test_counts_per_sku_and_no_invented_prices():
    _, rep = run_json(mod, [T, *BASE])
    per = {e["sku"]: e for e in rep["per_sku"]}
    assert per["SPE_E5"] == {"sku": "SPE_E5", "purchased": 6, "assigned": 4, "spare": 2, "reclaimable": 1}
    assert per["ENTERPRISEPACK"]["reclaimable"] == 3
    assert all("unit_cost" not in e and "estimated_total" not in e for e in rep["per_sku"])


def test_totals_only_from_supplied_unit_costs(write):
    cfg = write("c.yaml", "unit_costs:\n  ENTERPRISEPACK: 2.5\ncost_label: example units\n")
    rc, out, _ = run_main(mod, [T, "--config", str(cfg), "--as-of", "2026-10-04"])
    assert "| ENTERPRISEPACK | 5 | 3 | 2 | 3 | 2.5 | 12.5 |" in out
    assert "| SPE_E5 | 6 | 4 | 2 | 1 | not supplied | - |" in out and "(example units)" in out


def test_reclaim_csv_and_redact(tmp_path):
    path = tmp_path / "reclaim.csv"
    rc, _, _ = run_main(mod, [T, *BASE, "--csv", str(path), "--redact"])
    rows = list(csv.DictReader(path.open()))
    assert rc == 1 and len(rows) == 4 and list(rows[0]) == ["user", "sku", "reasons", "assigned_by", "last_sign_in", "decision"]
    assert all("@example.com" not in r["user"] and r["decision"] == "" for r in rows)


def test_bad_config(write):
    rc, _, err = run_main(mod, [T, "--config", str(write("c.yaml", "unit_costs: {SPE_E5: lots}\n"))])
    assert rc == 2 and "unit_costs" in err
    rc, _, err = run_main(mod, [T, "--config", str(write("d.yaml", "overlapping_skus: [SPE_E5]\n"))])
    assert rc == 2 and "overlapping_skus" in err
