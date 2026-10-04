import shutil

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("privileged-access-review", "pim_review.py")
T = FIXTURES / "pim-review" / "tenant"
CFG = str(FIXTURES / "pim-review" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def subjects(rep, check):
    return sorted(f["subject"] for f in checks(rep, check))


def copy_without(tmp_path, *names):
    shutil.copytree(T, tmp_path / "t")
    for n in names:
        p = tmp_path / "t" / n
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    return str(tmp_path / "t")


def test_planted_permanent_global_admin_with_mailbox_and_sms():
    rc, rep = run_json(mod, [str(T), *BASE])
    assert rc == 1
    [perm] = checks(rep, "PIM-PERMANENT-PRIVILEGED")
    assert (perm["subject"], perm["severity"]) == ("ga.daily@example.com", "CRITICAL")
    assert "ga.daily@example.com" in subjects(rep, "ADMIN-NO-PHISHING-RESISTANT")
    assert checks(rep, "ADMIN-NO-PHISHING-RESISTANT")[0]["evidence"] == "registered: mobilePhone"
    [daily] = checks(rep, "ADMIN-DAILY-USE-ACCOUNT")
    assert daily["evidence"] == "Exchange mailbox plan enabled; licences: SPE_E3"


def test_all_planted_checks_and_counts():
    _, rep = run_json(mod, [str(T), *BASE])
    assert rep["counts"] == {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 3, "INFO": 1}
    assert subjects(rep, "PIM-ELIGIBLE-NEVER-ACTIVATED") == ["sec.eligible@example.com"]
    assert subjects(rep, "ADMIN-STALE") == ["sec.eligible@example.com"]
    assert subjects(rep, "SP-PRIVILEGED-ROLE") == ["Example Provisioning App"]
    assert subjects(rep, "ROLE-SCOPED") == subjects(rep, "ADMIN-SYNCED") == ["helpdesk.scoped@example.com"]
    assert subjects(rep, "ROLE-GROUP-HOLDER") == ["Helpdesk Tier 2"]


def test_pim_activation_break_glass_and_non_privileged_roles_are_not_permanent():
    _, rep = run_json(mod, [str(T), *BASE])
    flagged = subjects(rep, "PIM-PERMANENT-PRIVILEGED")
    assert "helpdesk.scoped@example.com" not in flagged and "breakglass1@example.com" not in flagged
    assert all("reports.reader" not in f["subject"] for f in rep["findings"])


def test_hygiene_scores_and_evidence():
    _, rep = run_json(mod, [str(T), *BASE])
    scores = {a["account"]: a["score"] for a in rep["accounts"]}
    assert scores == {"ga.daily@example.com": 25, "sec.eligible@example.com": 55, "helpdesk.scoped@example.com": 90,
                      "breakglass1@example.com": 100, "ga.clean@example.com": 100}
    worst = rep["accounts"][0]
    assert worst["account"] == "ga.daily@example.com"
    assert worst["evidence"] == ["-35: permanent Global Administrator", "-25: no phishing-resistant method (registered: mobilePhone)",
                                 "-15: Exchange mailbox plan enabled; licences: SPE_E3"]


def test_without_schedules_every_active_privileged_assignment_is_permanent(tmp_path):
    _, rep = run_json(mod, [copy_without(tmp_path, "role-assignment-schedule-instances.json"), *BASE])
    assert subjects(rep, "PIM-PERMANENT-PRIVILEGED") == ["ga.daily@example.com", "helpdesk.scoped@example.com"]
    assert any("treated as permanent" in s for s in rep["not_evaluated"])


def test_without_activation_history_never_activated_is_skipped(tmp_path):
    _, rep = run_json(mod, [copy_without(tmp_path, "role-activations.json"), *BASE])
    assert not checks(rep, "PIM-ELIGIBLE-NEVER-ACTIVATED")
    assert any("role-activations.json" in s for s in rep["not_evaluated"])


def test_authentication_methods_fallback(tmp_path):
    folder = copy_without(tmp_path, "user-registration-details.json")
    _, rep = run_json(mod, [folder, *BASE])
    [f] = checks(rep, "ADMIN-NO-PHISHING-RESISTANT")
    assert f["subject"] == "ga.daily@example.com"
    assert f["evidence"] == "registered: passwordAuthenticationMethod, phoneAuthenticationMethod"


def test_password_only_admin_has_no_mfa_method(tmp_path, write):
    folder = copy_without(tmp_path, "user-registration-details.json", "authentication-methods")
    write("t/user-registration-details.json", '{"value": [{"id": "00000000-0000-0000-0000-000000000201", "methodsRegistered": []}]}')
    _, rep = run_json(mod, [folder, *BASE])
    [f] = checks(rep, "ADMIN-NO-MFA-METHOD")
    assert (f["subject"], f["severity"], f["evidence"]) == ("ga.daily@example.com", "CRITICAL", "registered: none")


def test_daily_use_exempt_and_break_glass_config(write):
    cfg = write("c.yaml", "break_glass: [breakglass1@example.com, ga.daily@example.com]\ndaily_use_exempt: [ga.daily@example.com]\n")
    _, rep = run_json(mod, [str(T), "--config", str(cfg), "--as-of", "2026-10-04", "--json"])
    assert not checks(rep, "PIM-PERMANENT-PRIVILEGED") and not checks(rep, "ADMIN-DAILY-USE-ACCOUNT")
    assert "ga.daily@example.com" in subjects(rep, "ADMIN-NO-PHISHING-RESISTANT")


def test_markdown_score_table_and_redact():
    rc, out, _ = run_main(mod, [str(T), "--config", CFG, "--as-of", "2026-10-04"])
    assert rc == 1 and "## Admin hygiene score" in out and "| ga.daily@example.com | 25 |" in out
    _, red, _ = run_main(mod, [str(T), *BASE, "--redact"])
    assert "@example.com" not in red and "Gary Daily" not in red


def test_required_inputs(tmp_path):
    rc, _, err = run_main(mod, [str(tmp_path)])
    assert rc == 2 and "role-definitions.json" in err
