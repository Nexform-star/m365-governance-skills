"""Tests for copilot_readiness.py. Every input is synthetic and built here, with example.com owners and example ids."""

from __future__ import annotations

import csv
import json
import re

import pytest
from conftest import load_script, run_json, run_main

mod = load_script("copilot-oversharing-readiness", "copilot_readiness.py")
LABEL = "00000000-0000-0000-0000-000000000501"
FIN = "https://example.sharepoint.com/sites/finance"
PROJ = "https://example.sharepoint.com/sites/project"
CLEAN = "https://example.sharepoint.com/sites/clean"
BASE = ["--as-of", "2026-10-05", "--json"]


def site(url, title, owner, sharing="ExternalUserSharingOnly", label=LABEL, changed="2026-09-01T00:00:00Z"):
    return {
        "Url": url,
        "Title": title,
        "OwnerEmail": owner,
        "SharingCapability": sharing,
        "SensitivityLabel": label,
        "LastContentModifiedDate": changed,
    }


def tenant_folder(tmp_path, *, dlp_mode="Enable", default_link="Direct", labels=True, extra_sites=()):
    d = tmp_path / "export"
    d.mkdir()
    sites = [
        site(FIN, "Finance", "fay@example.com", label="", changed="2025-01-01T00:00:00Z"),
        site(PROJ, "Project Falcon", "", sharing=2),
        site(CLEAN, "Clean site", "carl@example.com"),
        *extra_sites,
    ]
    (d / "sites.json").write_text(json.dumps(sites), encoding="utf-8")
    (d / "labels.json").write_text(json.dumps([{"Id": LABEL, "DisplayName": "General"}] if labels else []), encoding="utf-8")
    groups = [
        {
            "SiteUrl": FIN,
            "Title": "Finance Members",
            "Roles": ["Edit"],
            "Users": ["c:0-.f|rolemanager|spo-grid-all-users/00000000-0000-0000-0000-000000000001"],
        },
        {"SiteUrl": CLEAN, "Title": "Clean Members", "Roles": ["Edit"], "Users": ["i:0#.f|membership|carl@example.com"]},
    ]
    (d / "site-groups.json").write_text(json.dumps(groups), encoding="utf-8")
    links = [
        {"siteUrl": FIN, "link": {"scope": "anonymous", "webUrl": "https://example.sharepoint.com/:x:/g/abc?e=xyz"}},
        {"siteUrl": PROJ, "link": {"scope": "organization"}},
        {"siteUrl": PROJ, "link": {"scope": "users"}},
    ]
    (d / "sharing-links.json").write_text(json.dumps(links), encoding="utf-8")
    tenant = {"SharingCapability": "ExternalUserAndGuestSharing", "DefaultSharingLinkType": default_link, "RequireAnonymousLinksExpireInDays": 30}
    (d / "tenant.json").write_text(json.dumps(tenant), encoding="utf-8")
    dlp = [{"Name": "Baseline", "Mode": dlp_mode, "Enabled": True, "SharePointLocation": [{"Name": "All"}], "OneDriveLocation": []}]
    (d / "dlp-policies.json").write_text(json.dumps(dlp), encoding="utf-8")
    return d


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def test_planted_findings_and_rating(tmp_path):
    rc, rep = run_json(mod, [str(tenant_folder(tmp_path)), "--org-links", "1", *BASE])
    assert rc == 1
    assert rep["rating"] == "not ready"
    [grant] = checks(rep, "SITE-EVERYONE-GRANT")
    assert (grant["site"], grant["severity"], grant["owner"]) == (FIN, "CRITICAL", "fay@example.com")
    assert "Everyone except external users" in grant["evidence"]
    assert checks(rep, "SITE-ANYONE-LINKS")[0]["severity"] == "CRITICAL"
    assert [f["site"] for f in checks(rep, "SITE-ORG-LINKS")] == [PROJ]
    assert [f["site"] for f in checks(rep, "SITE-ANYONE-SHARING-ON")] == [PROJ]
    assert [f["site"] for f in checks(rep, "SITE-NO-LABEL")] == [FIN]
    assert [f["site"] for f in checks(rep, "SITE-NO-OWNER")] == [PROJ]
    assert [f["site"] for f in checks(rep, "SITE-INACTIVE-BROAD")] == [FIN]
    assert not [f for f in rep["findings"] if f["site"] == CLEAN]


def test_score_is_share_of_passing_checks(tmp_path):
    _, rep = run_json(mod, [str(tenant_folder(tmp_path)), *BASE])
    failed = len(rep["findings"])
    assert rep["checks_evaluated"] > failed
    assert rep["score"] == round(100 * (rep["checks_evaluated"] - failed) / rep["checks_evaluated"])
    assert {f["bucket"] for f in rep["findings"]} <= {"fix before rollout", "fix before broad rollout", "hygiene"}


def test_tenant_checks_default_link_and_dlp(tmp_path):
    _, rep = run_json(mod, [str(tenant_folder(tmp_path, dlp_mode="TestWithNotifications", default_link="AnonymousAccess", labels=False)), *BASE])
    assert checks(rep, "TENANT-DEFAULT-LINK-BROAD")[0]["severity"] == "HIGH"
    assert checks(rep, "TENANT-DLP-TEST-ONLY")[0]["owner"] == "Tenant administrators"
    assert checks(rep, "TENANT-NO-LABELS")
    assert not checks(rep, "TENANT-NO-DLP")


def test_clean_tenant_is_ready_and_exits_0(tmp_path):
    d = tmp_path / "clean"
    d.mkdir()
    (d / "sites.json").write_text(json.dumps([site(CLEAN, "Clean site", "carl@example.com")]), encoding="utf-8")
    (d / "site-groups.json").write_text(
        json.dumps([{"SiteUrl": CLEAN, "Title": "Members", "Users": ["i:0#.f|membership|carl@example.com"]}]), encoding="utf-8"
    )
    rc, rep = run_json(mod, [str(d), *BASE])
    assert rc == 0 and rep["rating"] == "ready" and rep["score"] == 100 and rep["findings"] == []
    assert any("dlp-policies.json not found" in s for s in rep["not_evaluated"])


def test_markdown_groups_by_owner_and_hides_link_urls(tmp_path):
    rc, out, _ = run_main(mod, [str(tenant_folder(tmp_path)), "--as-of", "2026-10-05"])
    assert rc == 1
    assert "## Remediation by owner" in out and "### fay@example.com" in out and "### No owner recorded" in out
    assert "?e=xyz" not in out and ":x:/g/" not in out


def test_redact_tokenises_owners_and_login_names(tmp_path):
    _, out, _ = run_main(mod, [str(tenant_folder(tmp_path)), *BASE, "--redact"])
    assert "fay@example.com" not in out and "carl@example.com" not in out
    assert re.search(r"user-[0-9a-f]{8}@redacted\.invalid", out)


def test_secret_shaped_strings_are_masked(tmp_path):
    key = "AKIA" + "IOSFODNN7EXAMPLE"  # split so the repository secret scan does not match the test itself
    d = tenant_folder(tmp_path, extra_sites=[site("https://example.sharepoint.com/sites/keys", f"{key} notes", "kim@example.com", sharing=2)])
    _, out, _ = run_main(mod, [str(d), *BASE])
    assert key not in out and "[redacted] notes" in out


def test_csv_and_out_files(tmp_path):
    d = tenant_folder(tmp_path)
    report, sheet = tmp_path / "report.md", tmp_path / "remediation.csv"
    rc, out, _ = run_main(mod, [str(d), "--as-of", "2026-10-05", "--out", str(report), "--csv", str(sheet)])
    assert rc == 1 and out == ""
    assert report.read_text(encoding="utf-8").startswith("# Copilot oversharing readiness")
    with sheet.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows and set(rows[0]) == {"owner", "site", "bucket", "severity", "check", "finding", "action"}


def test_aggregated_csv_links_are_read(tmp_path):
    d = tenant_folder(tmp_path)
    (d / "sharing-links.json").unlink()
    (d / "sharing-links.csv").write_text(f"site_url,anyone_links,organization_links,specific_people_links\n{CLEAN},2,0,4\n", encoding="utf-8")
    _, rep = run_json(mod, [str(d), *BASE])
    assert [f["site"] for f in checks(rep, "SITE-ANYONE-LINKS")] == [CLEAN]


@pytest.mark.parametrize(
    "files,argv",
    [
        ({}, []),
        ({"sites.json": "not json"}, []),
        ({"sites.json": "[1, 2]"}, []),
        ({"sites.json": "[]"}, ["--sensitive-pattern", "("]),
        ({"sites.json": '[{"Title": "no url"}]'}, []),
    ],
)
def test_bad_input_exits_2(tmp_path, files, argv):
    d = tmp_path / "bad"
    d.mkdir()
    for name, text in files.items():
        (d / name).write_text(text, encoding="utf-8")
    rc, _, err = run_main(mod, [str(d), *argv])
    assert rc == 2 and err.startswith("error:")


def test_help_lists_checks_and_exit_codes():
    rc, out, _ = run_main(mod, ["--help"])
    assert rc == 0
    for word in ("SITE-EVERYONE-GRANT", "TENANT-NO-DLP", "Exit codes", "--redact", "--json", "--out"):
        assert word in out
