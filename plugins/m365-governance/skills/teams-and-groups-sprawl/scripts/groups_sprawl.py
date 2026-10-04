#!/usr/bin/env python3
"""Report Microsoft 365 group and Teams sprawl from exported Graph data, and draft a cleanup list.

Input folder (file names the skill tells you to save; optional unless noted):
  groups.json                    GET /groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,visibility,
                                     resourceProvisioningOptions,createdDateTime,expirationDateTime,renewedDateTime (required)
  teams.json                     GET /teams (marks which groups are teams; resourceProvisioningOptions is used otherwise)
  group-owners/<group-id>.json   GET /groups/{id}/owners?$select=id,displayName,userPrincipalName,userType
  group-members/<group-id>.json  GET /groups/{id}/members?$select=id,displayName,userPrincipalName,userType
  users.json                     GET /users?$select=id,displayName,userPrincipalName,userType&$expand=manager($select=id,
                                     displayName,userPrincipalName)   (used only to propose owners)
  group-lifecycle-policies.json  GET /groupLifecyclePolicies
  teams-activity.csv             GET /reports/getTeamsTeamActivityDetail(period='D90') (CSV as downloaded)

Checks (id, default severity):
  GRP-OWNERLESS       HIGH (team) / MEDIUM (Microsoft 365 group) / LOW (other)  no owner
  GRP-SINGLE-OWNER    LOW      fewer owners than min_owners (default 2)
  GRP-GUESTS          MEDIUM when the name matches sensitive_pattern, else LOW   has guest members
  TEAM-PUBLIC         MEDIUM   team visibility is Public (anyone in the organization can join)
  GRP-PUBLIC          LOW      Microsoft 365 group (not a team) visibility is Public
  TEAM-INACTIVE       LOW      no team activity for inactive_days (default 90) in the activity report
  GRP-EMPTY           LOW      no members
  GRP-NAMING          LOW      display name does not match naming_pattern (Microsoft 365 groups and teams by default)
  EXP-NO-POLICY       MEDIUM   no group expiration (lifecycle) policy, or it applies to no groups
  GRP-NO-EXPIRATION   LOW      Microsoft 365 group with no expirationDateTime (not covered by expiration)

The cleanup list holds every group with a finding, its owners, member and guest counts, and for ownerless or
single-owner groups a proposed owner: the most common manager of its member users (from users.json). The proposal
is a draft for a person to confirm with the proposed owner, never an assignment.

Config (YAML or JSON, optional):
  min_owners: 2
  inactive_days: 90
  naming_pattern: "^(PRJ|DEP|TMP)-[A-Za-z0-9-]+$"
  naming_applies_to: [m365, team]          any of team, m365, security, distribution, mail-security
  sensitive_pattern: "(?i)(finance|payroll|hr|legal|security|board)"

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _graphio import (  # noqa: E402
    Export,
    InputError,
    add_common_args,
    as_of_datetime,
    cell,
    cfg_int,
    counts,
    days_since,
    dumps,
    exit_code,
    filter_min,
    finding,
    iso_day,
    load_config,
    person_names,
    redact,
    render_findings,
    render_header,
    sort_findings,
)

CONFIG_KEYS = {"min_owners", "inactive_days", "naming_pattern", "naming_applies_to", "sensitive_pattern"}
KINDS = {"team", "m365", "security", "distribution", "mail-security"}
KIND_LABEL = {"team": "Team", "m365": "Microsoft 365 group", "security": "Security group", "distribution": "Distribution list",
              "mail-security": "Mail-enabled security group"}
DEFAULT_SENSITIVE = r"(?i)(finance|payroll|hr|legal|security|board|exec)"
PORTAL_GROUP = "Entra admin center > Groups > All groups > (group)"
PORTAL_TEAM = "Teams admin center > Teams > Manage teams > (team)"


def is_guest(o: dict) -> bool:
    return o.get("userType") == "Guest" or "#EXT#" in str(o.get("userPrincipalName", ""))


def kind_of(g: dict, team_ids: set[str]) -> str:
    types = g.get("groupTypes") or []
    if g.get("id") in team_ids or "Team" in (g.get("resourceProvisioningOptions") or []):
        return "team"
    if "Unified" in types:
        return "m365"
    if g.get("securityEnabled") and not g.get("mailEnabled"):
        return "security"
    if g.get("mailEnabled") and not g.get("securityEnabled"):
        return "distribution"
    return "mail-security"


def compile_re(cfg: dict, key: str, default: str | None) -> re.Pattern | None:
    pattern = cfg.get(key, default)
    if pattern is None:
        return None
    try:
        return re.compile(str(pattern))
    except re.error as exc:
        raise InputError(f"config {key} is not a valid regular expression: {exc}") from exc


def activity_index(rows: list[dict] | None) -> dict[str, str]:
    """Map team id (and name, lower-cased) to the last activity date string ('' when none in the period)."""
    out: dict[str, str] = {}
    for r in rows or []:
        last = (r.get("Last Activity Date") or "").strip()
        if r.get("Team Id"):
            out[r["Team Id"].strip()] = last
        if r.get("Team Name"):
            out.setdefault("name:" + r["Team Name"].strip().lower(), last)
    return out


def propose_owner(members: list[dict], owners: list[dict], managers: dict[str, dict]) -> str:
    owner_ids = {o.get("id") for o in owners}
    tally = Counter()
    labels: dict[str, str] = {}
    for m in members:
        if is_guest(m):
            continue
        mgr = managers.get(m.get("id", ""))
        if mgr and mgr.get("id") not in owner_ids:
            tally[mgr["id"]] += 1
            labels[mgr["id"]] = mgr.get("userPrincipalName") or mgr.get("displayName") or mgr["id"]
    if not tally:
        return ""
    best = sorted(tally.items(), key=lambda kv: (-kv[1], labels[kv[0]]))[0]
    return f"{labels[best[0]]} (manager of {best[1]} member(s); draft, confirm first)"


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    groups = ex.list("groups.json", required=True)
    teams = ex.list("teams.json")
    owners_by = ex.dir_lists("group-owners")
    members_by = ex.dir_lists("group-members")
    users = ex.list("users.json")
    lifecycle = ex.list("group-lifecycle-policies.json")
    activity = activity_index(ex.csv_rows("teams-activity.csv"))
    have_activity = bool(activity)
    team_ids = {t.get("id") for t in teams or []}
    managers = {u.get("id"): u.get("manager") for u in users or [] if isinstance(u.get("manager"), dict)}
    min_owners = cfg_int(cfg, "min_owners", 2)
    inactive = cfg_int(cfg, "inactive_days", 90)
    naming = compile_re(cfg, "naming_pattern", None)
    sensitive = compile_re(cfg, "sensitive_pattern", DEFAULT_SENSITIVE)
    applies = {str(k) for k in cfg.get("naming_applies_to") or ["m365", "team"]}
    if applies - KINDS:
        raise InputError(f"config naming_applies_to: unknown kinds {', '.join(sorted(applies - KINDS))}")
    findings: list[dict] = []
    rows: list[dict] = []
    not_evaluated: list[str] = []
    policy_types = {str(p.get("managedGroupTypes", "None")) for p in lifecycle or []}
    if lifecycle is not None and (not lifecycle or policy_types <= {"None"}):
        findings.append(finding("EXP-NO-POLICY", "MEDIUM", "tenant", "No group expiration policy applies to any group",
                                f"{len(lifecycle)} lifecycle policies; managedGroupTypes {', '.join(sorted(policy_types)) or 'none'}",
                                "Entra admin center > Groups > Expiration",
                                "POST /groupLifecyclePolicies {\"groupLifetimeInDays\": 365, \"managedGroupTypes\": \"All\", "
                                "\"alternateNotificationEmails\": \"<admin mailbox>\"}"))
    for g in groups:
        gid, name = g.get("id", "?"), g.get("displayName") or g.get("id", "?")
        kind = kind_of(g, team_ids)
        portal = PORTAL_TEAM if kind == "team" else PORTAL_GROUP
        owners = (owners_by or {}).get(gid)
        members = (members_by or {}).get(gid)
        issues: list[str] = []

        def add(check, sev, title, evidence, portal=portal, graph="", _issues=issues, _subject=f"{name} ({gid})"):
            findings.append(finding(check, sev, _subject, title, evidence, portal, graph))
            _issues.append(check)

        if owners is None:
            if owners_by is not None:
                not_evaluated.append(f"{name}: no group-owners/{gid}.json")
        elif not owners:
            sev = {"team": "HIGH", "m365": "MEDIUM"}.get(kind, "LOW")
            add("GRP-OWNERLESS", sev, f"{KIND_LABEL[kind]} has no owner", f"created {iso_day(g.get('createdDateTime'))}",
                graph=f"POST /groups/{gid}/owners/$ref {{\"@odata.id\": \"https://graph.microsoft.com/v1.0/users/{{user-id}}\"}}")
        elif len(owners) < min_owners:
            add("GRP-SINGLE-OWNER", "LOW", f"{len(owners)} owner(s), fewer than {min_owners}",
                "owners: " + ", ".join(o.get("userPrincipalName") or o.get("displayName", "?") for o in owners),
                graph=f"POST /groups/{gid}/owners/$ref (add a second owner)")
        guests = [m for m in members or [] if is_guest(m)]
        if guests:
            sev = "MEDIUM" if sensitive and sensitive.search(name) else "LOW"
            add("GRP-GUESTS", sev, f"{len(guests)} guest member(s)" + (" in a sensitive group" if sev == "MEDIUM" else ""),
                "guests: " + ", ".join(sorted(m.get("userPrincipalName") or m.get("displayName", "?") for m in guests)),
                graph=f"DELETE /groups/{gid}/members/{{guest-id}}/$ref (after the owner confirms)")
        if members is not None and not members:
            add("GRP-EMPTY", "LOW", "Group has no members", f"created {iso_day(g.get('createdDateTime'))}")
        if str(g.get("visibility", "")).lower() == "public":
            if kind == "team":
                add("TEAM-PUBLIC", "MEDIUM", "Public team: anyone in the organization can join and read it", "visibility Public",
                    graph=f"PATCH /groups/{gid} {{\"visibility\": \"Private\"}} (after the owner agrees)")
            elif kind == "m365":
                add("GRP-PUBLIC", "LOW", "Public Microsoft 365 group", "visibility Public",
                    graph=f"PATCH /groups/{gid} {{\"visibility\": \"Private\"}} (after the owner agrees)")
        if kind == "team" and have_activity:
            last = activity.get(gid, activity.get("name:" + name.lower()))
            if last is None:
                not_evaluated.append(f"{name}: not in teams-activity.csv")
            else:
                age = days_since(last + "T00:00:00Z", now) if last else None
                if age is None or age > inactive:
                    add("TEAM-INACTIVE", "LOW", f"No team activity for more than {inactive} days",
                        f"last activity {last or 'none in the report period'}",
                        portal="Teams admin center > Teams > Manage teams > (team) > Archive")
        if naming and kind in applies and not naming.search(name):
            add("GRP-NAMING", "LOW", "Name does not match the naming convention", f"pattern {naming.pattern}",
                graph=f"PATCH /groups/{gid} {{\"displayName\": \"<conforming name>\"}}")
        if kind in {"m365", "team"} and not g.get("expirationDateTime") and "expirationDateTime" in g:
            add("GRP-NO-EXPIRATION", "LOW", "Not covered by group expiration", "expirationDateTime is empty",
                portal="Entra admin center > Groups > Expiration")
        if issues:
            rows.append({"group_id": gid, "name": name, "kind": kind, "issues": issues,
                         "owners": [o.get("userPrincipalName") or o.get("displayName", "?") for o in owners or []],
                         "owner_count": None if owners is None else len(owners),
                         "member_count": None if members is None else len(members), "guest_count": len(guests),
                         "proposed_owner": propose_owner(members or [], owners or [], managers)
                         if owners is not None and len(owners) < min_owners else ""})
    if owners_by is None:
        not_evaluated.append("GRP-OWNERLESS and GRP-SINGLE-OWNER: group-owners/ not found")
    if not have_activity:
        not_evaluated.append("TEAM-INACTIVE: teams-activity.csv not found or empty")
    rep = {"tool": "groups_sprawl", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)),
           "missing_inputs": sorted(set(ex.missing)), "warnings": ex.warnings, "not_evaluated": not_evaluated,
           "totals": dict(Counter(kind_of(g, team_ids) for g in groups)), "findings": sort_findings(findings),
           "cleanup": sorted(rows, key=lambda r: (-len(r["issues"]), r["name"])),
           "note": "A draft cleanup list from exported data. Proposed owners are suggestions to confirm with the people named; "
                   "nothing was changed in the tenant."}
    people = [o for v in list((owners_by or {}).values()) + list((members_by or {}).values()) for o in v
              if "user" in str(o.get("@odata.type", "user")).lower()]
    return rep, ex, person_names(users) | person_names(people)


def cleanup_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["group_id", "name", "kind", "issues", "owners", "member_count", "guest_count", "proposed_owner", "decision"])
    for r in rows:
        w.writerow([r["group_id"], r["name"], r["kind"], " ".join(r["issues"]), "; ".join(r["owners"]),
                    "" if r["member_count"] is None else r["member_count"], r["guest_count"], r["proposed_owner"], ""])
    return buf.getvalue()


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Teams and groups sprawl", ex, now)
    lines += ["| Kind | Groups |", "|---|---|"] + [f"| {k} | {n} |" for k, n in sorted(rep["totals"].items())] + [""]
    lines += ["## Findings", ""] + render_findings(rep["findings"])
    lines += ["", "## Cleanup list (draft)", "", "| Group | Kind | Issues | Owners | Members | Guests | Proposed owner |",
              "|---|---|---|---|---|---|---|"]
    for r in rep["cleanup"]:
        members = "?" if r["member_count"] is None else r["member_count"]
        lines.append(f"| {cell(r['name'])} | {r['kind']} | {' '.join(r['issues'])} | {cell(', '.join(r['owners']) or 'none')} | "
                     f"{members} | {r['guest_count']} | {cell(r['proposed_owner']) or '-'} |")
    if rep["not_evaluated"]:
        lines += ["", "## Not evaluated", ""] + [f"- {cell(s)}" for s in rep["not_evaluated"]]
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved Graph exports")
    ap.add_argument("--csv", help="also write the cleanup list as CSV to this path")
    add_common_args(ap, fail_on_default="MEDIUM")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config, CONFIG_KEYS)
        now = as_of_datetime(args.as_of)
        rep, ex, names = evaluate(args.folder, cfg, now)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rep["findings"] = filter_min(rep["findings"], args.min_severity)
    rep["counts"] = counts(rep["findings"])
    code = exit_code(rep["findings"], args.fail_on)
    if args.redact:
        rep = redact(rep, names)
    if args.csv:
        try:
            Path(args.csv).write_text(cleanup_csv(rep["cleanup"]), encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.csv}: {exc}", file=sys.stderr)
            return 2
    print(dumps(rep) if args.json else render(rep, ex, now))
    return code


if __name__ == "__main__":
    sys.exit(main())
