#!/usr/bin/env python3
"""Review privileged directory role holders from exported Microsoft Entra ID data, with an admin hygiene score per account.

Input folder (file names the skill tells you to save; optional unless noted):
  role-definitions.json                    GET /roleManagement/directory/roleDefinitions (required)
  role-assignments.json                    GET /roleManagement/directory/roleAssignments?$expand=principal (required)
  role-assignment-schedule-instances.json  GET /roleManagement/directory/roleAssignmentScheduleInstances (PIM: tells
                                               permanent assignments apart from activations)
  role-eligibility-schedule-instances.json GET /roleManagement/directory/roleEligibilityScheduleInstances (PIM)
  role-activations.json                    GET /roleManagement/directory/roleAssignmentScheduleRequests?$filter=action eq
                                               'selfActivate' (PIM activation history)
  users.json                               GET /users?$select=id,displayName,userPrincipalName,userType,accountEnabled,
                                               mail,assignedLicenses,assignedPlans,onPremisesSyncEnabled,signInActivity
  user-registration-details.json           GET /reports/authenticationMethods/userRegistrationDetails
  authentication-methods/<user-id>.json    GET /users/{id}/authentication/methods (used when the report above is missing)
  service-principals.json                  GET /servicePrincipals?$select=id,appId,displayName,servicePrincipalType
  subscribed-skus.json                     GET /subscribedSkus (only to name licences)

Checks (id, default severity):
  PIM-PERMANENT-PRIVILEGED   HIGH      a privileged role is held permanently (active, no end date, not a PIM
                                       activation); CRITICAL for Global Administrator; break-glass accounts are exempt
  PIM-ELIGIBLE-NEVER-ACTIVATED LOW     an eligible assignment older than unused_eligible_days (default 90) with no
                                       activation in role-activations.json
  ADMIN-NO-MFA-METHOD        CRITICAL  an admin has no MFA method registered at all
  ADMIN-NO-PHISHING-RESISTANT HIGH     an admin has no phishing-resistant method (FIDO2 security key or passkey, Windows
                                       Hello for Business, platform credential, certificate-based authentication)
  ADMIN-DAILY-USE-ACCOUNT    MEDIUM    an admin account has an Exchange mailbox plan or licences, which suggests it is also
                                       the person's daily-use account
  ADMIN-STALE                MEDIUM    an admin has not signed in for stale_days (default 90), or never has
  ADMIN-SYNCED               LOW       an admin account is synchronised from on-premises Active Directory
  SP-PRIVILEGED-ROLE         HIGH      a service principal holds a privileged role (active or eligible)
  ROLE-SCOPED                LOW       a privileged role is assigned at a scope other than the tenant root ("/"), for
                                       example an administrative unit or one application; tenant-wide reviews often miss it
  ROLE-GROUP-HOLDER          INFO      a role is assigned to a group; its members hold the role but are not expanded

Admin hygiene score: every user who holds a privileged role starts at 100 and loses points per issue, each listed as
evidence: permanent Global Administrator 35, other permanent privileged role 25, no MFA method 40, no phishing-resistant
method 25, mailbox 15, licences without a mailbox 10, stale 15, synchronised from on-premises 10, eligible role never
activated 5, account disabled 5. The floor is 0. The weights are a fixed rubric for ranking accounts to review, not a
measured risk. Break-glass accounts are scored too, without the permanent-assignment and daily-use deductions.

Config (YAML or JSON, optional):
  break_glass: [00000000-0000-0000-0000-0000000000b1, breakglass2@example.com]   object ids or UPNs
  privileged_roles: [Global Administrator, ...]   role display names treated as privileged (built-in list by default)
  stale_days: 90
  unused_eligible_days: 90
  daily_use_exempt: [admin.shared@example.com]    accounts allowed a mailbox or licence, with a recorded reason elsewhere

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
"""
from __future__ import annotations

import argparse
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

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"  # built-in role template id, the same in every tenant
PRIVILEGED_ROLE_NAMES = {
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Security Administrator", "Conditional Access Administrator", "Application Administrator",
    "Cloud Application Administrator", "User Administrator", "Authentication Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Intune Administrator", "Hybrid Identity Administrator",
    "Helpdesk Administrator", "Billing Administrator", "Teams Administrator", "Groups Administrator",
}
# methodsRegistered values in userRegistrationDetails, and @odata.type suffixes of authentication methods.
PHISHING_RESISTANT = {"fido2", "passkeydevicebound", "passkeydeviceboundauthenticator", "passkeydeviceboundwindowshello",
                      "windowshelloforbusiness", "platformcredential", "macossecureenclavekey", "x509certificate",
                      "x509certificatemultifactor", "fido2authenticationmethod", "windowshelloforbusinessauthenticationmethod",
                      "platformcredentialauthenticationmethod", "x509certificateauthenticationmethod"}
NOT_MFA = {"password", "passwordauthenticationmethod", "email", "emailauthenticationmethod", "securityquestion"}
CONFIG_KEYS = {"break_glass", "privileged_roles", "stale_days", "unused_eligible_days", "daily_use_exempt"}
ROLES_PORTAL = "Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles"
WEIGHTS = {"permanent-ga": 35, "permanent": 25, "no-mfa": 40, "no-phishing-resistant": 25, "mailbox": 15, "licensed": 10,
           "stale": 15, "synced": 10, "never-activated": 5, "disabled": 5}


def method_names(reg: dict | None, methods: list[dict] | None) -> list[str] | None:
    if reg is not None:
        return [str(m) for m in reg.get("methodsRegistered") or []]
    if methods is not None:
        return [str(m.get("@odata.type", "")).rsplit(".", 1)[-1] for m in methods]
    return None


def has_mailbox(u: dict) -> bool:
    return any(str(p.get("service", "")).lower() == "exchange" and p.get("capabilityStatus") == "Enabled"
               for p in u.get("assignedPlans") or [])


def last_sign_in(u: dict):
    sia = u.get("signInActivity") or {}
    dates = [d for d in (parse_dt(sia.get("lastSignInDateTime")), parse_dt(sia.get("lastNonInteractiveSignInDateTime"))) if d]
    return max(dates) if dates else None


class Holders:
    def __init__(self, ex: Export, cfg: dict):
        self.role_defs = ex.list("role-definitions.json", required=True)
        self.active = ex.list("role-assignments.json", required=True)
        self.schedules = ex.list("role-assignment-schedule-instances.json")
        self.eligible = ex.list("role-eligibility-schedule-instances.json")
        self.activations = ex.list("role-activations.json", "role-assignment-schedule-requests.json")
        self.users_list = ex.list("users.json")
        self.registration = ex.list("user-registration-details.json")
        self.methods = ex.dir_lists("authentication-methods") if self.registration is None else None
        self.sps = {s.get("id"): s for s in ex.list("service-principals.json") or []}
        skus = ex.list("subscribed-skus.json")
        self.sku_names = {s.get("skuId"): s.get("skuPartNumber", s.get("skuId")) for s in skus or []}
        self.users = {u.get("id"): u for u in self.users_list or []}
        self.by_upn = {str(u.get("userPrincipalName", "")).lower(): u for u in self.users_list or []}
        self.reg = {r.get("id"): r for r in self.registration or []}
        self.roles = {GLOBAL_ADMIN_TEMPLATE: "Global Administrator"}
        for r in self.role_defs:
            for key in ("id", "templateId"):
                if r.get(key):
                    self.roles[r[key]] = r.get("displayName", r[key])
        self.privileged = set(cfg.get("privileged_roles") or PRIVILEGED_ROLE_NAMES)
        self.break_glass = self.ids(cfg.get("break_glass") or [])
        self.exempt = self.ids(cfg.get("daily_use_exempt") or [])

    def ids(self, entries) -> set[str]:
        out = set()
        for e in entries:
            e = str(e)
            u = self.by_upn.get(e.lower()) if "@" in e else None
            out.add(u.get("id") if u else e)
        return out

    def kind(self, a: dict) -> str:
        pid = a.get("principalId", "")
        otype = str((a.get("principal") or {}).get("@odata.type", "")).lower()
        if pid in self.sps or otype.endswith("serviceprincipal"):
            return "servicePrincipal"
        if otype.endswith("group"):
            return "group"
        return "user"

    def label(self, a_or_id) -> str:
        pid = a_or_id if isinstance(a_or_id, str) else a_or_id.get("principalId", "")
        p = self.users.get(pid) or self.sps.get(pid) or ({} if isinstance(a_or_id, str) else a_or_id.get("principal") or {})
        return p.get("userPrincipalName") or p.get("displayName") or pid

    def is_privileged(self, rid: str) -> bool:
        return self.roles.get(rid, rid) in self.privileged

    def permanent(self, a: dict) -> bool | None:
        """True for a standing assignment, False for a PIM activation or time-bound one, None when unknown."""
        if self.schedules is None:
            return None
        for s in self.schedules:
            if s.get("principalId") == a.get("principalId") and s.get("roleDefinitionId") == a.get("roleDefinitionId") and \
                    (s.get("directoryScopeId") or "/") == (a.get("directoryScopeId") or "/"):
                return s.get("assignmentType") == "Assigned" and not parse_dt(s.get("endDateTime"))
        return True


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    h = Holders(ex, cfg)
    stale_days = cfg_int(cfg, "stale_days", 90)
    unused_days = cfg_int(cfg, "unused_eligible_days", 90)
    findings: list[dict] = []
    issues: dict[str, list[tuple[str, str]]] = {}   # user id -> [(weight key, evidence)]
    roles_of: dict[str, list[str]] = {}

    def note(uid, key, text):
        issues.setdefault(uid, [])
        if (key, text) not in issues[uid]:
            issues[uid].append((key, text))

    activated = {(a.get("principalId"), a.get("roleDefinitionId")) for a in h.activations or []
                 if str(a.get("action", "selfActivate")).lower() == "selfactivate"}
    for state, items in (("active", h.active), ("eligible", h.eligible or [])):
        for a in items:
            rid, pid = a.get("roleDefinitionId", ""), a.get("principalId", "")
            role, kind, who = h.roles.get(rid, rid), h.kind(a), h.label(a)
            scope = a.get("directoryScopeId") or "/"
            if kind == "group":
                findings.append(finding("ROLE-GROUP-HOLDER", "INFO", who, f"{role} is assigned to a group ({state})",
                                        "members of the group hold the role; review the group's membership as part of this review",
                                        f"{ROLES_PORTAL} > {role} > Assignments"))
                continue
            if not h.is_privileged(rid):
                continue
            if kind == "user":
                roles_of.setdefault(pid, []).append(f"{role} ({state}{'' if scope == '/' else ', scope ' + scope})")
                issues.setdefault(pid, [])
            if scope != "/":
                findings.append(finding("ROLE-SCOPED", "LOW", who, f"{role} assigned at scope {scope}",
                                        f"{state} assignment scoped to {scope}, not the tenant root",
                                        f"{ROLES_PORTAL} > {role} > Assignments (filter by scope)"))
            if kind == "servicePrincipal":
                findings.append(finding("SP-PRIVILEGED-ROLE", "HIGH", who, f"Service principal holds {role}",
                                        f"{state} assignment; an app credential can use this role with no MFA",
                                        "Entra admin center > Roles and administrators > " + role,
                                        f"DELETE /roleManagement/directory/roleAssignments/{a.get('id', '{id}')} (only after the "
                                        "owner confirms a narrower Graph permission works)"))
                continue
            if state == "active" and pid not in h.break_glass:
                perm = h.permanent(a)
                if perm or perm is None:
                    ga = role == "Global Administrator"
                    basis = "no end date and not a PIM activation" if perm else "PIM schedules not exported, treated as permanent"
                    findings.append(finding("PIM-PERMANENT-PRIVILEGED", "CRITICAL" if ga else "HIGH", who, f"Permanent {role}",
                                            basis, f"{ROLES_PORTAL} > {role} > Assignments > Active",
                                            "Convert to an eligible assignment in PIM, then remove the active one"))
                    note(pid, "permanent-ga" if ga else "permanent", f"permanent {role}")
            if state == "eligible" and h.activations is not None and (pid, rid) not in activated:
                age = days_since(a.get("startDateTime"), now)
                if age is None or age > unused_days:
                    findings.append(finding("PIM-ELIGIBLE-NEVER-ACTIVATED", "LOW", who, f"Eligible for {role}, never activated",
                                            f"eligible since {iso_day(a.get('startDateTime'))}; no activation in role-activations.json",
                                            f"{ROLES_PORTAL} > {role} > Assignments > Eligible. Remove the eligibility if not needed"))
                    note(pid, "never-activated", f"eligible for {role}, never activated")
    accounts = []
    for uid in sorted(roles_of, key=lambda x: h.label(x).lower()):
        u = h.users.get(uid)
        who = h.label(uid)
        bg = uid in h.break_glass
        names = method_names(h.reg.get(uid), (h.methods or {}).get(uid))
        if names is not None:
            low = {n.lower() for n in names}
            shown = ", ".join(names) or "none"
            if not low - NOT_MFA:
                findings.append(finding("ADMIN-NO-MFA-METHOD", "CRITICAL", who, "Admin has no MFA method registered",
                                        f"registered: {shown}", "My Security Info, or Entra admin center > Users > (user) > "
                                        "Authentication methods. Register a FIDO2 key or passkey"))
                note(uid, "no-mfa", f"no MFA method (registered: {shown})")
            elif not low & PHISHING_RESISTANT:
                findings.append(finding("ADMIN-NO-PHISHING-RESISTANT", "HIGH", who, "Admin has no phishing-resistant method",
                                        f"registered: {shown}", "Entra admin center > Protection > Authentication methods. Register "
                                        "a FIDO2 key, passkey or Windows Hello for Business, then require a phishing-resistant "
                                        "authentication strength for admin roles"))
                note(uid, "no-phishing-resistant", f"no phishing-resistant method (registered: {shown})")
        if u is not None:
            licences = [h.sku_names.get(x.get("skuId"), x.get("skuId", "?")) for x in u.get("assignedLicenses") or []]
            mailbox = has_mailbox(u)
            if (mailbox or licences) and uid not in h.exempt and not bg:
                parts = (["Exchange mailbox plan enabled"] if mailbox else []) + ([f"licences: {', '.join(licences)}"] if licences else [])
                findings.append(finding("ADMIN-DAILY-USE-ACCOUNT", "MEDIUM", who, "Admin account looks like a daily-use account",
                                        "; ".join(parts), "Create a separate cloud-only admin account without a mailbox or "
                                        "licence, move the roles to it, and remove them here"))
                note(uid, "mailbox" if mailbox else "licensed", "; ".join(parts))
            last = last_sign_in(u)
            if "signInActivity" in u and (last is None or (now - last).days > stale_days):
                findings.append(finding("ADMIN-STALE", "MEDIUM", who, "Admin has not signed in recently",
                                        f"last sign-in {iso_day(last)}", f"{ROLES_PORTAL}. Remove the role if it is not used"))
                note(uid, "stale", f"last sign-in {iso_day(last)}")
            if u.get("onPremisesSyncEnabled"):
                findings.append(finding("ADMIN-SYNCED", "LOW", who, "Admin account is synchronised from on-premises",
                                        "onPremisesSyncEnabled is true; a compromise of Active Directory reaches this role",
                                        "Use a cloud-only account for the admin role"))
                note(uid, "synced", "synchronised from on-premises Active Directory")
            if u.get("accountEnabled") is False:
                note(uid, "disabled", "account disabled but still holds a role")
        score = max(0, 100 - sum(WEIGHTS[k] for k, _ in issues.get(uid, [])))
        accounts.append({"account": who, "break_glass": bg, "roles": roles_of[uid], "score": score,
                         "methods": "not exported" if names is None else (", ".join(names) or "none"),
                         "evidence": [f"-{WEIGHTS[k]}: {t}" for k, t in issues.get(uid, [])]})
    accounts.sort(key=lambda r: (r["score"], r["account"].lower()))
    not_evaluated = []
    if h.schedules is None:
        not_evaluated.append("role-assignment-schedule-instances.json not found: every active assignment was treated as permanent")
    if h.activations is None:
        not_evaluated.append("PIM-ELIGIBLE-NEVER-ACTIVATED: role-activations.json not found")
    if h.registration is None and h.methods is None:
        not_evaluated.append("ADMIN-NO-MFA-METHOD and ADMIN-NO-PHISHING-RESISTANT: no authentication method export")
    if h.users_list is None:
        not_evaluated.append("ADMIN-DAILY-USE-ACCOUNT, ADMIN-STALE and ADMIN-SYNCED: users.json not found")
    elif not any("signInActivity" in u for u in h.users_list):
        not_evaluated.append("ADMIN-STALE: users.json has no signInActivity (needs AuditLog.Read.All and Entra ID P1)")
    rep = {"tool": "pim_review", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)), "missing_inputs": sorted(set(ex.missing)),
           "warnings": ex.warnings, "not_evaluated": not_evaluated, "findings": sort_findings(findings), "accounts": accounts,
           "note": "Built from exported data at one point in time. The hygiene score ranks accounts for review; it is not a risk "
                   "measurement. Verify each finding in the tenant before any change; the script changed nothing."}
    return rep, ex, person_names(h.users_list)


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Privileged access review", ex, now)
    lines += ["| Severity | Findings |", "|---|---|"] + [f"| {s} | {n} |" for s, n in rep["counts"].items()] + [""]
    lines += ["## Findings", ""] + render_findings(rep["findings"])
    if rep["accounts"]:
        lines += ["", "## Admin hygiene score (100 is best; lowest first)", "", "| Account | Score | Roles | Methods | Evidence |",
                  "|---|---|---|---|---|"]
        for a in rep["accounts"]:
            name = cell(a["account"]) + (" (break-glass)" if a["break_glass"] else "")
            lines.append(f"| {name} | {a['score']} | {cell('; '.join(a['roles']))} | {cell(a['methods'])} | "
                         f"{cell('; '.join(a['evidence']) or 'no deductions')} |")
    if rep["not_evaluated"]:
        lines += ["", "## Not fully evaluated", ""] + [f"- {cell(s)}" for s in rep["not_evaluated"]]
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved Graph JSON exports")
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
    print(dumps(rep) if args.json else render(rep, ex, now))
    return code


if __name__ == "__main__":
    sys.exit(main())
