#!/usr/bin/env python3
"""Build a quarterly access review package from exported Microsoft Entra ID data: a reviewer checklist and a sign-off CSV.

Input folder (file names the skill tells you to save; each section is built only when its inputs are present):
  role-definitions.json                    GET /roleManagement/directory/roleDefinitions
  role-assignments.json                    GET /roleManagement/directory/roleAssignments?$expand=principal
  role-eligibility-schedule-instances.json GET /roleManagement/directory/roleEligibilityScheduleInstances (PIM, optional)
  users.json                               GET /users?$select=id,displayName,userPrincipalName,userType,accountEnabled,signInActivity
  applications.json                        GET /applications?$select=id,appId,displayName,passwordCredentials,keyCredentials
  application-owners/<app-object-id>.json  GET /applications/{id}/owners
  service-principals.json                  GET /servicePrincipals?$select=id,appId,displayName,servicePrincipalType,
                                               passwordCredentials,keyCredentials
  groups.json                              GET /groups?$select=id,displayName,groupTypes,securityEnabled,mailEnabled
  group-owners/<group-id>.json             GET /groups/{id}/owners
  group-members/<group-id>.json            GET /groups/{id}/members

Sections (rows in the sign-off CSV):
  privileged-roles       every directory role holder, active or eligible, with last sign-in
  app-owners             every app registration with its owners (or NO OWNER)
  sensitive-group-owners owners of groups whose name matches sensitive_group_pattern
  guests-per-group       each guest member of each group, with last sign-in
  expiring-credentials   application and service principal secrets and certificates expiring within credential_window_days
                         (default 90), and ones already expired

Output: Markdown checklist and CSV with columns section, item, principal, detail, last_sign_in, reviewer, decision, date.
Without --out-dir the checklist is printed; with --out-dir both files are written there (access-review.md and
access-review-signoff.csv). The reviewer column is filled from config `reviewers` when set; decision and date are left
blank for the reviewer.

Config (YAML or JSON, optional):
  review_name: "Q4 2026 access review"
  credential_window_days: 90
  sensitive_group_pattern: "(?i)(admin|privileged|finance|payroll|hr|security)"
  only_privileged_roles: false            true limits the role section to the built-in privileged role list
  reviewers: {privileged-roles: security-lead@example.com, app-owners: app-platform@example.com}

Exit codes: 0 package built, 2 bad input. Nothing is changed in the tenant.
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _graphio import (  # noqa: E402
    Export,
    InputError,
    as_of_datetime,
    cell,
    cfg_int,
    dumps,
    iso_day,
    load_config,
    parse_dt,
    person_names,
    redact,
    render_header,
)

SECTIONS = ["privileged-roles", "app-owners", "sensitive-group-owners", "guests-per-group", "expiring-credentials"]
TITLES = {"privileged-roles": "Privileged role holders", "app-owners": "App registration owners",
          "sensitive-group-owners": "Owners of sensitive groups", "guests-per-group": "Guests per group",
          "expiring-credentials": "Credentials expiring or expired"}
QUESTIONS = {
    "privileged-roles": "Does this person or app still need this role, and should it be eligible (PIM) rather than active?",
    "app-owners": "Is this app still used, and is the listed owner still the right accountable person?",
    "sensitive-group-owners": "Is this owner still responsible for who joins this group?",
    "guests-per-group": "Does this guest still need access to this group?",
    "expiring-credentials": "Rotate, let expire, or remove? Who owns the rotation?",
}
CSV_COLUMNS = ["section", "item", "principal", "detail", "last_sign_in", "reviewer", "decision", "date"]
CONFIG_KEYS = {"review_name", "credential_window_days", "sensitive_group_pattern", "only_privileged_roles", "reviewers"}
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLE_NAMES = {
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Security Administrator", "Conditional Access Administrator", "Application Administrator",
    "Cloud Application Administrator", "User Administrator", "Authentication Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Intune Administrator", "Hybrid Identity Administrator",
    "Helpdesk Administrator", "Billing Administrator", "Teams Administrator", "Groups Administrator",
}
DEFAULT_SENSITIVE = r"(?i)(admin|privileged|finance|payroll|hr|security)"


def is_guest(o: dict) -> bool:
    return o.get("userType") == "Guest" or "#EXT#" in str(o.get("userPrincipalName", ""))


def last_sign_in(u: dict | None) -> str:
    if not u or "signInActivity" not in u:
        return "not exported"
    sia = u.get("signInActivity") or {}
    dates = [d for d in (parse_dt(sia.get("lastSignInDateTime")), parse_dt(sia.get("lastNonInteractiveSignInDateTime"))) if d]
    return iso_day(max(dates)) if dates else "never"

def last_service_principal_sign_in(activity: dict | None) -> str:
    if not activity:
        return "n/a"

    dates = []

    for name in (
        "lastSignInActivity",
        "delegatedClientSignInActivity",
        "delegatedResourceSignInActivity",
        "applicationClientSignInActivity",
        "applicationResourceSignInActivity",
    ):
        item = activity.get(name) or {}
        date = parse_dt(item.get("lastSignInDateTime"))
        if date:
            dates.append(date)

    if not dates:
        return "n/a"

    return iso_day(max(dates))

def label(o: dict) -> str:
    return o.get("userPrincipalName") or o.get("displayName") or o.get("appId") or o.get("id", "?")


def build(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    role_defs = ex.list("role-definitions.json")
    assignments = ex.list("role-assignments.json")
    eligible = ex.list("role-eligibility-schedule-instances.json")
    users = ex.list("users.json")
    apps = ex.list("applications.json")
    app_owners = ex.dir_lists("application-owners")
    sps = ex.list("service-principals.json")
    service_principal_sign_ins = ex.list("service-principal-sign-ins.json")
    groups = ex.list("groups.json")
    group_owners = ex.dir_lists("group-owners")
    group_members = ex.dir_lists("group-members")
    window = cfg_int(cfg, "credential_window_days", 90)
    reviewers = cfg.get("reviewers") or {}
    if not isinstance(reviewers, dict) or set(reviewers) - set(SECTIONS):
        raise InputError(f"config reviewers must map section names ({', '.join(SECTIONS)}) to a reviewer")
    try:
        sensitive = re.compile(str(cfg.get("sensitive_group_pattern", DEFAULT_SENSITIVE)))
    except re.error as exc:
        raise InputError(f"config sensitive_group_pattern is not a valid regular expression: {exc}") from exc
    by_id = {u.get("id"): u for u in users or []}
    sp_by_id = {s.get("id"): s for s in sps or []}
    sign_ins_by_app_id = {s.get("appId"): s for s in service_principal_sign_ins or []}
    roles = {GLOBAL_ADMIN_TEMPLATE: "Global Administrator"}
    for r in role_defs or []:
        roles[r.get("id", "")] = r.get("displayName", r.get("id", "?"))
        if r.get("templateId"):
            roles[r["templateId"]] = r.get("displayName", "?")
    rows: list[dict] = []
    skipped: list[str] = []

    def row(section, item, principal, detail, last=""):
        rows.append({"section": section, "item": item, "principal": principal, "detail": detail, "last_sign_in": last,
                     "reviewer": str(reviewers.get(section, "")), "decision": "", "date": ""})

    if assignments is None and eligible is None:
        skipped.append("privileged-roles: role-assignments.json not found")
    for state, items in (("active", assignments or []), ("eligible", eligible or [])):
        for a in items:
            role = roles.get(a.get("roleDefinitionId", ""), a.get("roleDefinitionId", "?"))
            if cfg.get("only_privileged_roles") and role not in PRIVILEGED_ROLE_NAMES:
                continue
            pid = a.get("principalId", "")
            principal = a.get("principal") or by_id.get(pid) or sp_by_id.get(pid) or {"id": pid}
            otype = str(principal.get("@odata.type", ""))
            kind = ("service principal" if pid in sp_by_id or otype.endswith("servicePrincipal")
                    else "group" if otype.endswith("group") else "guest" if is_guest(principal) else "user")
            if kind in {"user", "guest"}:
                last = last_sign_in(by_id.get(pid))
            elif kind == "service principal":
                sp = sp_by_id.get(pid)
                activity = sign_ins_by_app_id.get((sp or {}).get("appId"))
                last = last_service_principal_sign_in(activity)
            else:
                last = "n/a"
            scope = a.get("directoryScopeId", "/")
            row("privileged-roles", role, label(principal), f"{state}, {kind}" + ("" if scope in ("/", None) else f", scope {scope}"), last)
    if apps is None:
        skipped.append("app-owners: applications.json not found")
    for app in apps or []:
        owners = None if app_owners is None else app_owners.get(app.get("id", ""))
        item = f"{app.get('displayName', '?')} ({app.get('appId', '?')})"
        creds = len(app.get("passwordCredentials") or []) + len(app.get("keyCredentials") or [])

        if owners is None:
            row("app-owners", item, "owners not exported", f"{creds} credential(s)")
        elif not owners:
            row("app-owners", item, "NO OWNER", f"{creds} credential(s)")

        for o in owners or []:
            row("app-owners", item, label(o), f"{creds} credential(s)", last_sign_in(by_id.get(o.get("id"))))
    if groups is None:
        skipped.append("sensitive-group-owners and guests-per-group: groups.json not found")
    for g in sorted(groups or [], key=lambda x: x.get("displayName", "")):
        name = g.get("displayName", g.get("id", "?"))
        gid = g.get("id", "")
        members = (group_members or {}).get(gid)
        if sensitive.search(name):
            owners = (group_owners or {}).get(gid)
            detail = f"{len(members)} member(s)" if members is not None else "members not exported"
            if owners is None:
                row("sensitive-group-owners", name, "owners not exported", detail)
            elif not owners:
                row("sensitive-group-owners", name, "NO OWNER", detail)
            for o in owners or []:
                row("sensitive-group-owners", name, label(o), detail, last_sign_in(by_id.get(o.get("id"))))
        for m in members or []:
            if is_guest(m):
                u = by_id.get(m.get("id")) or m
                row("guests-per-group", name, label(m), "guest" + (", disabled" if u.get("accountEnabled") is False else ""), last_sign_in(u))
    if apps is None and sps is None:
        skipped.append("expiring-credentials: applications.json and service-principals.json not found")
    for kind, objs in (("application", apps or []), ("service principal", sps or [])):
        for o in objs:
            for ctype, creds in (("secret", o.get("passwordCredentials") or []), ("certificate", o.get("keyCredentials") or [])):
                for c in creds:
                    end = parse_dt(c.get("endDateTime"))
                    if not end:
                        continue
                    days = (end - now).days
                    if days <= window:
                        state = f"expired {iso_day(end)}" if end < now else f"expires {iso_day(end)} ({days} days)"
                        row("expiring-credentials", f"{o.get('displayName', '?')} ({kind}, {o.get('appId', '?')})",
                            f"{ctype} {c.get('displayName') or c.get('keyId', '?')}", state)
    order = {s: i for i, s in enumerate(SECTIONS)}
    rows.sort(key=lambda r: (order[r["section"]], r["item"].lower(), r["principal"].lower()))
    rep = {"tool": "access_review_pack", "review_name": str(cfg.get("review_name") or f"Access review {now.strftime('%Y-%m-%d')}"),
           "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)), "missing_inputs": sorted(set(ex.missing)),
           "warnings": ex.warnings, "skipped": skipped,
           "counts": {s: sum(1 for r in rows if r["section"] == s) for s in SECTIONS}, "rows": rows,
           "note": "Built from exported data; nothing was changed in the tenant. Reviewers record keep, remove or change in the "
                   "CSV; removals are carried out separately after sign-off."}
    names = person_names(users)
    for v in list((app_owners or {}).values()) + list((group_owners or {}).values()) + list((group_members or {}).values()):
        names |= person_names(v)
    return rep, ex, names


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r[k] for k in CSV_COLUMNS})
    return buf.getvalue()


def checklist(rep: dict, ex: Export, now) -> str:
    lines = render_header(cell(rep["review_name"]), ex, now)
    lines += ["Each line needs a decision: keep, remove or change. Record it in the sign-off CSV with your name and the date.", "",
              "| Section | Items |", "|---|---|"] + [f"| {TITLES[s]} | {n} |" for s, n in rep["counts"].items()]
    for s in SECTIONS:
        section_rows = [r for r in rep["rows"] if r["section"] == s]
        if not section_rows:
            continue
        lines += ["", f"## {TITLES[s]}", "", QUESTIONS[s], ""]
        for r in section_rows:
            last = f", last sign-in {r['last_sign_in']}" if r["last_sign_in"] and r["last_sign_in"] != "n/a" else ""
            who = f" (reviewer: {cell(r['reviewer'])})" if r["reviewer"] else ""
            lines.append(f"- [ ] **{cell(r['item'])}**: {cell(r['principal'])}; {cell(r['detail'])}{last}{who}")
    if rep["skipped"]:
        lines += ["", "## Not included", ""] + [f"- {s}" for s in rep["skipped"]]
    lines += ["", "## Sign-off", "", "Reviewer: ____________________  Date: ____________", "", rep["note"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved Graph JSON exports")
    ap.add_argument("--config", help="review name, window, sensitive group pattern, reviewers (YAML or JSON)")
    ap.add_argument("--as-of", help="evaluate dates as of this day (YYYY-MM-DD); default today")
    ap.add_argument("--out-dir", help="write access-review.md and access-review-signoff.csv into this folder")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the Markdown checklist")
    ap.add_argument("--redact", action="store_true", help="replace user principal names, e-mail addresses and person names with tokens")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config, CONFIG_KEYS)
        now = as_of_datetime(args.as_of)
        rep, ex, names = build(args.folder, cfg, now)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.redact:
        rep = redact(rep, names)
    md = checklist(rep, ex, now)
    if args.out_dir:
        out = Path(args.out_dir)
        try:
            out.mkdir(parents=True, exist_ok=True)
            (out / "access-review.md").write_text(md, encoding="utf-8")
            (out / "access-review-signoff.csv").write_text(to_csv(rep["rows"]), encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write to {out}: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(dumps(rep))
    elif args.out_dir:
        print(f"Wrote {Path(args.out_dir) / 'access-review.md'} and {Path(args.out_dir) / 'access-review-signoff.csv'} "
              f"({len(rep['rows'])} rows).")
    else:
        print(md, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
