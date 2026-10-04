#!/usr/bin/env python3
"""Review guest accounts and external sharing settings from exported Microsoft 365 data, with a per-guest access map
and a draft removal list.

Input folder (file names the skill tells you to save; optional unless noted):
  users.json                     GET /users?$filter=userType eq 'Guest'&$select=id,displayName,mail,userPrincipalName,
                                     userType,accountEnabled,createdDateTime,externalUserState,signInActivity (required;
                                     members in the file are ignored)
  groups.json                    GET /groups?$select=id,displayName,visibility
  group-members/<group-id>.json  GET /groups/{id}/members?$select=id,displayName,userPrincipalName,userType
  directory-audits.json          GET /auditLogs/directoryAudits?$filter=activityDisplayName eq 'Invite external user'
                                     (names the inviter; the audit log keeps 30 days)
  sharepoint-settings.json       GET /admin/sharepoint/settings
  spo-tenant.json                Get-SPOTenant (SharePoint Online Management Shell) as JSON: OneDrive sharing and
                                     anyone-link expiry, which Graph does not publish
  teams-federation.json          Get-CsTenantFederationConfiguration (Microsoft Teams PowerShell) as JSON

Checks (id, default severity):
  GUEST-BLOCKED-DOMAIN          HIGH      a guest's domain is blocked (config blocked_domains, the SharePoint blocked
                                          list, Teams blocked domains) or outside the SharePoint allow list; CRITICAL
                                          when the guest is also in a sensitive group
  GUEST-SENSITIVE-GROUP         HIGH      a guest is a member of a group whose name matches sensitive_pattern
  GUEST-STALE                   MEDIUM    an enabled guest has not signed in for stale_days (default 90), or never has and
                                          was invited more than stale_days ago
  GUEST-PENDING                 LOW       an invitation has not been accepted for pending_days (default 30)
  SHARING-ANYONE                HIGH      SharePoint allows anyone links (sharingCapability externalUserAndGuestSharing)
  SHARING-ANYONE-ONEDRIVE       HIGH      OneDrive allows anyone links (spo-tenant.json)
  SHARING-ANYONE-NO-EXPIRY      MEDIUM    anyone links are allowed and do not expire (spo-tenant.json)
  SHARING-NO-DOMAIN-RESTRICTION LOW       external sharing is on with no allow or block list of domains
  SHARING-RESHARE               LOW       guests can share items they do not own
  TEAMS-ALL-EXTERNAL-DOMAINS    MEDIUM    Teams external access is open to all external domains
  TEAMS-CONSUMER                LOW       Teams users can chat with personal (consumer) Teams accounts

The access map lists every guest with domain, invitation state, invite date, last sign-in, inviter (when the audit
export covers it) and groups. The removal list is a DRAFT: guests with a stale, pending or blocked-domain finding, for a
person to confirm with the inviter or group owner. Nothing is removed by this script.

Config (YAML or JSON, optional):
  stale_days: 90
  pending_days: 30
  sensitive_pattern: "(?i)(finance|payroll|hr|legal|security|board|admin|privileged)"
  blocked_domains: [example.net]
  allowed_domains: [example.org]     when set, guests from any other domain are reported as GUEST-BLOCKED-DOMAIN

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
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
    parse_dt,
    person_names,
    redact,
    render_findings,
    render_header,
    sort_findings,
)

CONFIG_KEYS = {"stale_days", "pending_days", "sensitive_pattern", "blocked_domains", "allowed_domains"}
DEFAULT_SENSITIVE = r"(?i)(finance|payroll|hr|legal|security|board|admin|privileged)"
# SharePoint SharingCapabilities, as ConvertTo-Json writes the enum (number) or as Graph writes it (camelCase name).
SHARING = {0: "disabled", 1: "externalusersharingonly", 2: "externaluserandguestsharing", 3: "existingexternalusersharingonly"}
SPO_PORTAL = "SharePoint admin center > Policies > Sharing"
TEAMS_PORTAL = "Teams admin center > Users > External access"
CSV_COLUMNS = ["status", "guest", "domain", "reasons", "groups", "inviter", "invited", "last_sign_in", "decision"]


def sharing_level(value) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return SHARING.get(value, str(value))
    return str(value or "").lower()


def is_guest(u: dict) -> bool:
    return u.get("userType") == "Guest" or "#EXT#" in str(u.get("userPrincipalName", ""))


def guest_domain(u: dict) -> str:
    mail = str(u.get("mail") or "")
    if "@" in mail:
        return mail.rsplit("@", 1)[1].lower()
    upn = str(u.get("userPrincipalName", ""))
    if "#EXT#" in upn:
        local = upn.split("#EXT#", 1)[0]
        if "_" in local:
            return local.rsplit("_", 1)[1].lower()
    return "unknown"


def domain_list(value) -> list[str]:
    """Domains from a list of strings, a list of {"Domain": ...} objects, or a comma or space separated string."""
    if value is None:
        return []
    if isinstance(value, str):
        return [d.lower() for d in re.split(r"[\s,]+", value) if "." in d]
    if isinstance(value, dict):
        for key in ("AllowedDomain", "BlockedDomain", "Domains", "value"):
            if key in value:
                return domain_list(value[key])
        return []
    out = []
    for d in value:
        out += domain_list(d.get("Domain") or d.get("Name") if isinstance(d, dict) else d)
    return out


def teams_open(fed: dict) -> bool:
    """True when AllowedDomains is AllowAllKnownDomains, in any of the shapes PowerShell serialises it to."""
    return "AllowAllKnownDomains" in str(fed.get("AllowedDomains"))


def last_sign_in(u: dict):
    sia = u.get("signInActivity") or {}
    dates = [d for d in (parse_dt(sia.get("lastSignInDateTime")), parse_dt(sia.get("lastNonInteractiveSignInDateTime"))) if d]
    return max(dates) if dates else None


def check_settings(sp: dict | None, spo: dict | None, fed: dict | None) -> list[dict]:
    out: list[dict] = []
    anyone = False
    if sp is not None:
        level = sharing_level(sp.get("sharingCapability"))
        anyone = level == "externaluserandguestsharing"
        if anyone:
            out.append(finding("SHARING-ANYONE", "HIGH", "SharePoint", "Anyone links are allowed tenant-wide",
                               "sharingCapability is externalUserAndGuestSharing: files can be shared with a link that needs no sign-in",
                               f"{SPO_PORTAL}. Set SharePoint to New and existing guests or lower",
                               "PATCH /admin/sharepoint/settings {\"sharingCapability\": \"externalUserSharingOnly\"}"))
        mode = str(sp.get("sharingDomainRestrictionMode") or "none").lower()
        if level not in ("", "disabled") and mode == "none":
            out.append(finding("SHARING-NO-DOMAIN-RESTRICTION", "LOW", "SharePoint", "External sharing has no domain restriction",
                               f"sharingCapability {sp.get('sharingCapability')}, sharingDomainRestrictionMode none",
                               f"{SPO_PORTAL} > More external sharing settings > Limit external sharing by domain"))
        if sp.get("isResharingByExternalUsersEnabled"):
            out.append(finding("SHARING-RESHARE", "LOW", "SharePoint", "Guests can reshare items they do not own",
                               "isResharingByExternalUsersEnabled is true",
                               f"{SPO_PORTAL} > More external sharing settings > Allow guests to share items they don't own (clear)"))
    if spo is not None:
        od = sharing_level(spo.get("OneDriveSharingCapability"))
        if od == "externaluserandguestsharing":
            out.append(finding("SHARING-ANYONE-ONEDRIVE", "HIGH", "OneDrive", "Anyone links are allowed in OneDrive",
                               f"OneDriveSharingCapability is {spo.get('OneDriveSharingCapability')} (externalUserAndGuestSharing)",
                               f"{SPO_PORTAL}. Set OneDrive to New and existing guests or lower"))
        anyone = anyone or od == "externaluserandguestsharing" or sharing_level(spo.get("SharingCapability")) == "externaluserandguestsharing"
        expiry = spo.get("RequireAnonymousLinksExpireInDays")
        if anyone and (not isinstance(expiry, int) or expiry <= 0):
            out.append(finding("SHARING-ANYONE-NO-EXPIRY", "MEDIUM", "SharePoint and OneDrive", "Anyone links never expire",
                               f"RequireAnonymousLinksExpireInDays is {expiry}",
                               f"{SPO_PORTAL} > Choose expiration and permissions options for Anyone links"))
    if fed is not None:
        if fed.get("AllowFederatedUsers") and teams_open(fed):
            blocked = domain_list(fed.get("BlockedDomains"))
            out.append(finding("TEAMS-ALL-EXTERNAL-DOMAINS", "MEDIUM", "Teams", "Teams external access is open to all domains",
                               "AllowFederatedUsers is true and AllowedDomains allows all known domains"
                               + (f"; blocked: {', '.join(blocked)}" if blocked else ""),
                               f"{TEAMS_PORTAL}. Allow only specific external domains"))
        if fed.get("AllowTeamsConsumer"):
            out.append(finding("TEAMS-CONSUMER", "LOW", "Teams", "Chat with personal Teams accounts is allowed",
                               "AllowTeamsConsumer is true", f"{TEAMS_PORTAL}. Turn off communication with unmanaged Teams accounts"))
    return out


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    users = ex.list("users.json", required=True)
    groups = ex.list("groups.json")
    members = ex.dir_lists("group-members")
    audits = ex.list("directory-audits.json")
    sp = ex.obj("sharepoint-settings.json")
    spo = ex.obj("spo-tenant.json")
    fed = ex.obj("teams-federation.json")
    stale_days = cfg_int(cfg, "stale_days", 90)
    pending_days = cfg_int(cfg, "pending_days", 30)
    try:
        sensitive = re.compile(str(cfg.get("sensitive_pattern", DEFAULT_SENSITIVE)))
    except re.error as exc:
        raise InputError(f"config sensitive_pattern is not a valid regular expression: {exc}") from exc
    blocked = {str(d).lower() for d in cfg.get("blocked_domains") or []}
    allowed = {str(d).lower() for d in cfg.get("allowed_domains") or []}
    if sp is not None:
        mode = str(sp.get("sharingDomainRestrictionMode") or "none").lower()
        if mode == "blocklist":
            blocked |= set(domain_list(sp.get("sharingBlockedDomainList")))
        elif mode == "allowlist":
            allowed |= set(domain_list(sp.get("sharingAllowedDomainList")))
    if fed is not None:
        blocked |= set(domain_list(fed.get("BlockedDomains")))
    guests = [u for u in users if is_guest(u)]
    group_names = {g.get("id"): g.get("displayName", g.get("id")) for g in groups or []}
    groups_of: dict[str, list[str]] = {}
    for gid, ms in (members or {}).items():
        for m in ms:
            groups_of.setdefault(m.get("id"), []).append(group_names.get(gid, gid))
    inviter: dict[str, str] = {}
    for a in audits or []:
        if a.get("activityDisplayName") != "Invite external user":
            continue
        by = ((a.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName") or \
            ((a.get("initiatedBy") or {}).get("app") or {}).get("displayName") or "?"
        for t in a.get("targetResources") or []:
            for key in (t.get("id"), str(t.get("userPrincipalName") or "").lower()):
                if key:
                    inviter[key] = by
    findings = check_settings(sp, spo, fed)
    access_map, removal = [], []
    for g in sorted(guests, key=lambda x: str(x.get("userPrincipalName", "")).lower()):
        gid, who, dom = g.get("id"), g.get("userPrincipalName") or g.get("mail") or g.get("id"), guest_domain(g)
        names = sorted(groups_of.get(gid, []), key=str.lower)
        sens = [n for n in names if sensitive.search(n)]
        last = last_sign_in(g)
        invited_age = days_since(g.get("createdDateTime"), now)
        by = inviter.get(gid) or inviter.get(str(g.get("userPrincipalName", "")).lower()) or "not in audit export"
        reasons = []
        if dom in blocked or (allowed and dom not in allowed):
            why = "blocked domain" if dom in blocked else "domain not on the allow list"
            findings.append(finding("GUEST-BLOCKED-DOMAIN", "CRITICAL" if sens else "HIGH", who, f"Guest from a {why}",
                                    f"domain {dom}" + (f"; in sensitive groups: {', '.join(sens)}" if sens else ""),
                                    "Entra admin center > Users > (guest). Confirm with the inviter, then remove the guest or "
                                    "record an exception"))
            reasons.append(why)
        if sens:
            findings.append(finding("GUEST-SENSITIVE-GROUP", "HIGH", who, "Guest in a sensitive group",
                                    f"groups: {', '.join(sens)}", "Entra admin center > Groups > (group) > Members. Confirm the "
                                    "guest still needs this group with its owner"))
        if g.get("accountEnabled") is not False and "signInActivity" in g:
            if (last and (now - last).days > stale_days) or (last is None and (invited_age or 0) > stale_days):
                findings.append(finding("GUEST-STALE", "MEDIUM", who, "Stale guest", f"last sign-in {iso_day(last)}; invited "
                                        f"{iso_day(g.get('createdDateTime'))}", "Entra admin center > Users > (guest). Disable, then "
                                        "remove after confirmation; or use an access review for guests"))
                reasons.append(f"no sign-in for more than {stale_days} days")
        if str(g.get("externalUserState", "")).lower() == "pendingacceptance" and (invited_age or 0) > pending_days:
            findings.append(finding("GUEST-PENDING", "LOW", who, "Invitation not accepted",
                                    f"pending since {iso_day(g.get('createdDateTime'))} ({invited_age} days)",
                                    "Entra admin center > Users > (guest). Resend the invitation or remove the guest"))
            reasons.append(f"invitation pending for more than {pending_days} days")
        row = {"guest": who, "domain": dom, "state": g.get("externalUserState") or "unknown",
               "enabled": g.get("accountEnabled") is not False, "invited": iso_day(g.get("createdDateTime")),
               "last_sign_in": iso_day(last) if "signInActivity" in g else "not exported", "inviter": by,
               "groups": [n + (" (sensitive)" if n in sens else "") for n in names]}
        access_map.append(row)
        if reasons:
            removal.append({"status": "DRAFT", "guest": who, "domain": dom, "reasons": reasons, "groups": names, "inviter": by,
                            "invited": row["invited"], "last_sign_in": row["last_sign_in"]})
    not_evaluated = []
    if members is None:
        not_evaluated.append("GUEST-SENSITIVE-GROUP and group columns: group-members/ not found")
    if not any("signInActivity" in g for g in guests):
        not_evaluated.append("GUEST-STALE: users.json has no signInActivity (needs AuditLog.Read.All and Entra ID P1)")
    for name, obj in (("sharepoint-settings.json", sp), ("spo-tenant.json", spo), ("teams-federation.json", fed)):
        if obj is None:
            not_evaluated.append(f"{name} not found: its settings checks were skipped")
    rep = {"tool": "external_sharing", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)),
           "missing_inputs": sorted(set(ex.missing)), "warnings": ex.warnings, "not_evaluated": not_evaluated,
           "guests": len(guests), "findings": sort_findings(findings), "access_map": access_map, "removal_draft": removal,
           "note": "The removal list is a draft built from exported data. Confirm each guest with the inviter or group owner before "
                   "anything is disabled or removed; the script changed nothing."}
    names_ = person_names(users) | {m.get("displayName", "") for ms in (members or {}).values() for m in ms if m.get("displayName")}
    return rep, ex, names_


def removal_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([r["status"], r["guest"], r["domain"], "; ".join(r["reasons"]), "; ".join(r["groups"]), r["inviter"], r["invited"],
                    r["last_sign_in"], ""])
    return buf.getvalue()


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Guest and external sharing review", ex, now)
    lines += [f"Guests in the export: {rep['guests']}.", "", "| Severity | Findings |", "|---|---|"]
    lines += [f"| {s} | {n} |" for s, n in rep["counts"].items()] + [""]
    lines += ["## Findings", ""] + render_findings(rep["findings"])
    if rep["access_map"]:
        lines += ["", "## Guest access map", "", "| Guest | Domain | State | Invited | Last sign-in | Inviter | Groups |",
                  "|---|---|---|---|---|---|---|"]
        for r in rep["access_map"]:
            state = r["state"] + ("" if r["enabled"] else ", disabled")
            lines.append(f"| {cell(r['guest'])} | {cell(r['domain'])} | {cell(state)} | {r['invited']} | {r['last_sign_in']} | "
                         f"{cell(r['inviter'])} | {cell(', '.join(r['groups']) or '-')} |")
    lines += ["", "## Removal list (DRAFT: confirm each line before any change)", ""]
    if rep["removal_draft"]:
        lines += ["| Guest | Domain | Reasons | Groups | Inviter |", "|---|---|---|---|---|"]
        for r in rep["removal_draft"]:
            lines.append(f"| {cell(r['guest'])} | {cell(r['domain'])} | {cell('; '.join(r['reasons']))} | "
                         f"{cell(', '.join(r['groups']) or '-')} | {cell(r['inviter'])} |")
    else:
        lines.append("No guest meets a removal reason.")
    if rep["not_evaluated"]:
        lines += ["", "## Not fully evaluated", ""] + [f"- {cell(s)}" for s in rep["not_evaluated"]]
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved exports")
    ap.add_argument("--csv", help="also write the draft removal list as CSV to this path")
    add_common_args(ap)
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
            Path(args.csv).write_text(removal_csv(rep["removal_draft"]), encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.csv}: {exc}", file=sys.stderr)
            return 2
    print(dumps(rep) if args.json else render(rep, ex, now))
    return code


if __name__ == "__main__":
    sys.exit(main())
