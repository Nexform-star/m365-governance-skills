import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("intune-baseline-check", "intune_baseline.py")
IN = FIXTURES / "intune"
BASE = ["--config", str(IN / "config.yaml"), "--as-of", "2026-10-04", "--json"]


def subjects(rep, check):
    return sorted(f["subject"] for f in rep["findings"] if f["check"] == check)


def test_estate_flags_planted_defects():
    rc, rep = run_json(mod, [str(IN / "estate"), *BASE])
    assert rc == 1
    assert {f["check"] for f in rep["findings"]} == {
        "DEV-NONCOMPLIANT", "DEV-STALE", "DEV-PERSONAL", "DEV-UNENCRYPTED", "DEV-JAILBROKEN", "DEV-OS-BELOW-MIN", "POL-UNASSIGNED",
        "BASE-NO-POLICY", "BASE-ENCRYPTION", "BASE-MIN-OS", "BASE-JAILBREAK", "BASE-DEFENDER", "PROF-ALL-DEVICES",
        "INTUNE-NOT-SECURE-DEFAULT"}


def test_baseline_gaps_per_platform():
    _, rep = run_json(mod, [str(IN / "estate"), *BASE])
    assert subjects(rep, "BASE-ENCRYPTION") == ["Windows"]
    assert subjects(rep, "BASE-JAILBREAK") == ["iOS"]
    assert subjects(rep, "BASE-NO-POLICY") == ["macOS"]  # its only policy is unassigned
    assert subjects(rep, "BASE-PASSWORD") == []


def test_profiles_with_exclusions_pass():
    _, rep = run_json(mod, [str(IN / "estate"), *BASE])
    assert subjects(rep, "PROF-ALL-DEVICES") == ["Edge baseline", "Wi-Fi corporate"]


def test_platform_summary_and_ignored_platform():
    _, rep = run_json(mod, [str(IN / "estate"), *BASE])
    rows = {r["platform"]: r for r in rep["platforms"]}
    assert set(rows) == {"Windows", "macOS", "iOS", "Android"}
    assert rows["Windows"]["devices"] == 2 and rows["Windows"]["stale"] == 1 and rows["Windows"]["unencrypted"] == 1
    assert rows["macOS"]["policies"] == []


def test_baseline_met_is_clean():
    rc, rep = run_json(mod, [str(IN / "baseline-met"), *BASE])
    assert rc == 0 and rep["findings"] == []
    assert {r["platform"] for r in rep["platforms"]} == {"Windows", "macOS", "iOS"}  # iPadOS counts as iOS


def test_personal_devices_allowed_without_corporate_only():
    _, rep = run_json(mod, [str(IN / "estate"), "--as-of", "2026-10-04", "--json"])
    assert subjects(rep, "DEV-PERSONAL") == []


def test_version_compare():
    assert mod.version_tuple("10.0.19041.1") < mod.version_tuple("10.0.19045")
    assert mod.version_tuple("14") >= mod.version_tuple("13")


def test_missing_assignments_expand_is_an_input_error(write):
    write("managed-devices.json", json.dumps({"value": []}))
    write("compliance-policies.json", json.dumps({"value": [{"@odata.type": "#microsoft.graph.iosCompliancePolicy", "id": "x"}]}))
    rc, _, err = run_main(mod, [str(write("x", "").parent)])
    assert rc == 2 and "$expand=assignments" in err


def test_required_devices_file(tmp_path):
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "managed-devices.json" in err


def test_redact_and_markdown():
    rc, out, _ = run_main(mod, [str(IN / "estate"), "--config", str(IN / "config.yaml"), "--as-of", "2026-10-04", "--redact"])
    assert rc == 1
    assert "## Platforms" in out and "@example.com" not in out


def test_min_severity_and_fail_on():
    rc, rep = run_json(mod, [str(IN / "estate"), *BASE, "--min-severity", "HIGH", "--fail-on", "CRITICAL"])
    assert rc == 0
    assert {f["severity"] for f in rep["findings"]} == {"HIGH"}
