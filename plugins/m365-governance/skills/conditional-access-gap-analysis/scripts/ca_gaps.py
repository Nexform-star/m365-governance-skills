#!/usr/bin/env python3
"""Find gaps, overlaps and exclusion problems in exported Microsoft Entra Conditional Access policies.

Evaluates the policies against a baseline of expected coverage, resolves who each policy really applies to from the
exported users, groups and role holders, and prints a coverage matrix (policy x persona).

Input folder (file names the skill tells you to save; optional unless noted):
  conditional-access-policies.json         GET /identity/conditionalAccess/policies (required)
  named-locations.json                     GET /identity/conditionalAccess/namedLocations
  users.json                               GET /users?$select=id,displayName,userPrincipalName,userType,accountEnabled
  groups.json                              GET /groups?$select=id,displayName
  group-members/<group-id>.json            GET /groups/{id}/transitiveMembers, for every group a policy includes or
                                               excludes
  role-definitions.json                    GET /roleManagement/directory/roleDefinitions
  role-assignments.json                    GET /roleManagement/directory/roleAssignments
  role-eligibility-schedule-instances.json GET /roleManagement/directory/roleEligibilityScheduleInstances (PIM)

How coverage is worked out: a policy applies to a user when the user is included (All users, the user id, guests,
a member of an included group, or a holder of an included role, active or eligible) and not excluded the same ways.
Only policies in state enabled count towards the baseline; report-only policies are shown in the matrix but cover
no one. "All cloud apps" means includeApplications contains All. Personas: all users (enabled users, not
break-glass), admins (holders of a privileged role, active or eligible, not break-glass), guests and break-glass.

Checks (id, default severity):
  CA-GAP-MFA-ALL             HIGH      enabled users not covered by an enabled policy that requires MFA or an
                                       authentication strength for all cloud apps
  CA-GAP-MFA-ADMINS          CRITICAL  admins not covered by such a policy
  CA-GAP-LEGACY-AUTH         HIGH      enabled users not covered by an enabled policy that blocks legacy
                                       authentication (exchangeActiveSync and other clients) for all cloud apps
  CA-GAP-ADMIN-DEVICE        MEDIUM    admins not covered by an enabled policy that requires a compliant or
                                       hybrid-joined device
  CA-GAP-SIGNIN-RISK         MEDIUM    no enabled policy requires MFA or blocks on sign-in risk
  CA-GAP-USER-RISK           LOW       no enabled policy acts on user risk
  CA-GAP-UNMANAGED-SESSION   MEDIUM    no enabled policy applies a session control to unmanaged devices (a device
                                       filter, or the browser client type)
  CA-BREAKGLASS-NOT-EXCLUDED HIGH      a configured break-glass account is covered by an enabled policy (lockout risk)
  CA-EXCLUSION-HAS-ADMIN     HIGH      a group excluded from a policy contains an admin who is not break-glass
  CA-EXCLUSION-UNEXPLAINED   MEDIUM    an excluded user, group or role is neither break-glass nor listed in
                                       explained_exclusions
  CA-REPORT-ONLY-STALE       MEDIUM    in report-only mode for more than report_only_max_days (default 30), counted
                                       from modifiedDateTime (or createdDateTime)
  CA-INCLUDE-EXCLUDE-CANCEL  MEDIUM    the same user, group or role is both included and excluded
  CA-ZERO-TARGET             MEDIUM    an enabled or report-only policy applies to no user in users.json
  CA-OVERLAP                 INFO      enabled policies with identical conditions and controls
  CA-LOCATION-BROAD          MEDIUM    a trusted named location has an IPv4 range wider than /broad_ipv4_prefix
                                       (default 16) or an IPv6 range wider than /32
  CA-TRUSTED-LOCATION-SKIP   LOW       an MFA policy for all users does not apply from trusted locations
  CA-DISABLED                INFO      a policy is disabled

Config (YAML or JSON, optional):
  break_glass: [00000000-0000-0000-0000-0000000000b1, breakglass2@example.com]   object ids or UPNs
  break_glass_groups: []                                                         group ids excluded on purpose
  explained_exclusions: {00000000-0000-0000-0000-000000000901: "Kiosk accounts, ticket CHG-1234"}   id or UPN: reason
  report_only_max_days: 30
  broad_ipv4_prefix: 16
  privileged_roles: [Global Administrator, ...]   role display names that make a user an admin (built-in list by default)
  list_limit: 10                                  names listed per finding before "and N more"

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
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
CONFIG_KEYS = {"break_glass", "break_glass_groups", "explained_exclusions", "report_only_max_days", "broad_ipv4_prefix",
               "privileged_roles", "list_limit"}
CA_PORTAL = "Entra admin center > Protection > Conditional Access > Policies"
PERSONAS = ["all users", "admins", "guests", "break-glass"]
SPECIAL_USERS = {"All", "None", "GuestsOrExternalUsers"}


def _cond(p: dict) -> dict:
    return p.get("conditions") or {}


def _users(p: dict) -> dict:
    return _cond(p).get("users") or {}


def _controls(p: dict) -> list[str]:
    return [str(c).lower() for c in (p.get("grantControls") or {}).get("builtInControls") or []]


def requires_mfa(p: dict) -> bool:
    return "mfa" in _controls(p) or bool((p.get("grantControls") or {}).get("authenticationStrength"))


def blocks(p: dict) -> bool:
    return "block" in _controls(p)


def requires_device(p: dict) -> bool:
    return bool({"compliantdevice", "domainjoineddevice"} & set(_controls(p)))


def all_apps(p: dict) -> bool:
    return "All" in ((_cond(p).get("applications") or {}).get("includeApplications") or [])


def blocks_legacy(p: dict) -> bool:
    return blocks(p) and {"exchangeActiveSync", "other"} <= set(_cond(p).get("clientAppTypes") or [])


def session_controls(p: dict) -> list[str]:
    s = p.get("sessionControls") or {}
    out = []
    for key in ("applicationEnforcedRestrictions", "cloudAppSecurity", "signInFrequency", "persistentBrowser"):
        v = s.get(key)
        if isinstance(v, dict) and v.get("isEnabled"):
            out.append(key)
    return out


def targets_unmanaged(p: dict) -> bool:
    devices = _cond(p).get("devices") or {}
    rule = str((devices.get("deviceFilter") or {}).get("rule", ""))
    return bool(rule) or "browser" in (_cond(p).get("clientAppTypes") or [])


def controls_label(p: dict) -> str:
    parts = list(_controls(p))
    strength = (p.get("grantControls") or {}).get("authenticationStrength")
    if strength:
        parts.append(f"authentication strength {strength.get('displayName', '') if isinstance(strength, dict) else strength}".strip())
    parts += session_controls(p)
    return ", ".join(parts) or "no controls"


class Tenant:
    """Users, group membership and role holders, with the lookups coverage needs."""

    def __init__(self, users, groups, members, role_defs, assignments, eligible, cfg):
        self.users = {u.get("id"): u for u in users or [] if u.get("id")}
        self.have_users = users is not None
        self.by_upn = {str(u.get("userPrincipalName", "")).lower(): u for u in users or []}
        self.group_names = {g.get("id"): g.get("displayName", g.get("id")) for g in groups or []}
        self.members: dict[str, set[str]] = {gid: {m.get("id") for m in ms} for gid, ms in (members or {}).items()}
        self.unknown_groups: set[str] = set()
        role_names = {GLOBAL_ADMIN_TEMPLATE: "Global Administrator"}
        for r in role_defs or []:
            for key in ("id", "templateId"):
                if r.get(key):
                    role_names[r[key]] = r.get("displayName", r[key])
        self.role_names = role_names
        self.roles_of: dict[str, set[str]] = {}
        for a in (assignments or []) + (eligible or []):
            rid, pid = a.get("roleDefinitionId", ""), a.get("principalId", "")
            principals = self.members.get(pid, {pid})
            for p in principals:
                self.roles_of.setdefault(p, set()).add(rid)
        privileged = set(cfg.get("privileged_roles") or PRIVILEGED_ROLE_NAMES)
        self.break_glass = self._ids(cfg.get("break_glass") or [])
        self.break_glass_groups = {str(g) for g in cfg.get("break_glass_groups") or []}
        for g in self.break_glass_groups:
            self.break_glass |= self.members.get(g, set())
        self.admins = {uid for uid, rids in self.roles_of.items() if uid in self.users
                       and any(self.role_names.get(r, r) in privileged for r in rids)} - self.break_glass
        explained = cfg.get("explained_exclusions") or {}
        if not isinstance(explained, dict):
            raise InputError("config explained_exclusions must map an id or UPN to a reason")
        self.explained = {}
        for k, v in explained.items():
            for i in self._ids([k]) | {str(k)}:
                self.explained[i] = str(v)

    def _ids(self, entries) -> set[str]:
        out = set()
        for e in entries:
            e = str(e)
            u = self.by_upn.get(e.lower()) if "@" in e else None
            out.add(u.get("id") if u else e)
        return out

    def label(self, oid: str) -> str:
        u = self.users.get(oid)
        if u:
            return u.get("userPrincipalName") or u.get("displayName") or oid
        if oid in self.group_names:
            return f"{self.group_names[oid]} (group)"
        if oid in self.role_names:
            return f"{self.role_names[oid]} (role)"
        return oid

    def is_guest(self, uid: str) -> bool:
        u = self.users.get(uid) or {}
        return u.get("userType") == "Guest" or "#EXT#" in str(u.get("userPrincipalName", ""))

    def group_has(self, gid: str, uid: str) -> bool:
        if gid not in self.members:
            self.unknown_groups.add(gid)
            return False
        return uid in self.members[gid]

    def _match(self, u: dict, side: str, uid: str) -> bool:
        ids = u.get(f"{side}Users") or []
        if uid in ids or ("All" in ids and side == "include"):
            return True
        if self.is_guest(uid) and ("GuestsOrExternalUsers" in ids or u.get(f"{side}GuestsOrExternalUsers")):
            return True
        if any(self.group_has(g, uid) for g in u.get(f"{side}Groups") or []):
            return True
        return bool(set(u.get(f"{side}Roles") or []) & self.roles_of.get(uid, set()))

    def applies(self, p: dict, uid: str) -> bool:
        u = _users(p)
        return self._match(u, "include", uid) and not self._match(u, "exclude", uid)

    def persona(self, name: str) -> set[str]:
        enabled = {i for i, u in self.users.items() if u.get("accountEnabled") is not False}
        if name == "all users":
            return enabled - self.break_glass
        if name == "admins":
            return self.admins & enabled
        if name == "guests":
            return {i for i in enabled if self.is_guest(i)} - self.break_glass
        return set(self.break_glass) & set(self.users)


def names_list(t: Tenant, ids, limit: int) -> str:
    labels = sorted(t.label(i) for i in ids)
    more = f" and {len(labels) - limit} more" if len(labels) > limit else ""
    return ", ".join(labels[:limit]) + more


def check_gaps(enabled: list[dict], t: Tenant, limit: int) -> list[dict]:
    out: list[dict] = []
    baselines = [
        ("CA-GAP-MFA-ALL", "HIGH", "all users", lambda p: requires_mfa(p) and all_apps(p),
         "Users not covered by an enabled policy that requires MFA for all cloud apps",
         "Create or widen a policy: All users, All cloud apps, grant require MFA or an authentication strength; exclude only "
         "break-glass accounts"),
        ("CA-GAP-MFA-ADMINS", "CRITICAL", "admins", lambda p: requires_mfa(p) and all_apps(p),
         "Admins not covered by an enabled policy that requires MFA for all cloud apps",
         "Add a policy for the privileged directory roles (or All users) that requires a phishing-resistant authentication strength"),
        ("CA-GAP-LEGACY-AUTH", "HIGH", "all users", lambda p: blocks_legacy(p) and all_apps(p),
         "Users not covered by an enabled policy that blocks legacy authentication",
         "Create a policy: All users, All cloud apps, client apps Exchange ActiveSync and Other clients, grant Block"),
        ("CA-GAP-ADMIN-DEVICE", "MEDIUM", "admins", lambda p: requires_device(p) and (all_apps(p) or "MicrosoftAdminPortals" in (
            (_cond(p).get("applications") or {}).get("includeApplications") or [])),
         "Admins not covered by an enabled policy that requires a compliant or hybrid-joined device",
         "Add a policy for the privileged roles: grant require device to be marked compliant or Microsoft Entra hybrid joined"),
    ]
    for check, sev, persona, qualifies, title, fix in baselines:
        policies = [p for p in enabled if qualifies(p)]
        if t.have_users:
            people = t.persona(persona)
            gap = {uid for uid in people if not any(t.applies(p, uid) for p in policies)}
            if not gap:
                continue
            via = ", ".join(p.get("displayName", "?") for p in policies) or "no qualifying enabled policy"
            out.append(finding(check, sev, persona, title, f"{len(gap)} of {len(people)} not covered: {names_list(t, gap, limit)}; "
                               f"qualifying policies: {via}", f"{CA_PORTAL}. {fix}"))
        elif not any("All" in (_users(p).get("includeUsers") or []) for p in policies):
            out.append(finding(check, sev, persona, title, "no qualifying enabled policy includes All users (users.json not "
                               "exported, so coverage was checked structurally)", f"{CA_PORTAL}. {fix}"))
    risk = [("CA-GAP-SIGNIN-RISK", "MEDIUM", "signInRiskLevels", "sign-in risk"), ("CA-GAP-USER-RISK", "LOW", "userRiskLevels", "user risk")]
    for check, sev, key, what in risk:
        if not any(_cond(p).get(key) and (requires_mfa(p) or blocks(p)) for p in enabled):
            out.append(finding(check, sev, "tenant", f"No enabled policy acts on {what}",
                               f"no enabled policy sets {key} with a grant of MFA or block",
                               f"{CA_PORTAL}. Add a {what} policy (needs Entra ID P2): require MFA (or a password change for user risk) "
                               "at medium and high risk"))
    if not any(session_controls(p) and targets_unmanaged(p) for p in enabled):
        out.append(finding("CA-GAP-UNMANAGED-SESSION", "MEDIUM", "tenant", "No session controls for unmanaged devices",
                           "no enabled policy combines a session control (app enforced restrictions, Defender for Cloud Apps, "
                           "sign-in frequency or persistent browser) with a device filter or the browser client type",
                           f"{CA_PORTAL}. Add a policy for browser sessions on devices that are not compliant: app enforced "
                           "restrictions or sign-in frequency"))
    return out


def check_exclusions(active: list[dict], enabled: list[dict], t: Tenant, limit: int) -> list[dict]:
    out: list[dict] = []
    for bg in sorted(t.break_glass & set(t.users)):
        hit = [p.get("displayName", "?") for p in enabled if t.applies(p, bg)]
        if hit:
            out.append(finding("CA-BREAKGLASS-NOT-EXCLUDED", "HIGH", t.label(bg), "Break-glass account is covered by enabled policies",
                               f"applies: {', '.join(sorted(hit))}",
                               f"{CA_PORTAL}. Exclude the break-glass account (or its group) from every policy, and monitor its sign-ins"))
    unexplained: dict[str, list[str]] = {}
    admin_groups: dict[str, list[str]] = {}
    for p in active:
        if not (requires_mfa(p) or blocks(p) or requires_device(p)):
            continue
        u = _users(p)
        name = p.get("displayName", "?")
        for kind in ("Users", "Groups", "Roles"):
            for oid in u.get(f"exclude{kind}") or []:
                if oid in SPECIAL_USERS or oid in t.break_glass or oid in t.break_glass_groups or oid in t.explained:
                    continue
                unexplained.setdefault(oid, []).append(name)
        for gid in u.get("excludeGroups") or []:
            if gid in t.members and t.members[gid] & t.admins:
                admin_groups.setdefault(gid, []).append(name)
    for oid, pols in unexplained.items():
        out.append(finding("CA-EXCLUSION-UNEXPLAINED", "MEDIUM", t.label(oid), "Exclusion with no recorded reason",
                           f"excluded from: {', '.join(sorted(pols))}",
                           f"{CA_PORTAL}. Record the reason in explained_exclusions, or remove the exclusion"))
    for gid, pols in admin_groups.items():
        admins = t.members[gid] & t.admins
        out.append(finding("CA-EXCLUSION-HAS-ADMIN", "HIGH", t.label(gid), "Excluded group contains admins",
                           f"admins in the group: {names_list(t, admins, limit)}; excluded from: {', '.join(sorted(pols))}",
                           "Entra admin center > Groups > (group) > Members. Remove the admins from the exclusion group, or "
                           "give them a separate policy with equal or stronger controls"))
    return out


def check_policies(policies: list[dict], t: Tenant, cfg: dict, now) -> list[dict]:
    out: list[dict] = []
    max_days = cfg_int(cfg, "report_only_max_days", 30)
    signatures: dict[str, list[str]] = {}
    for p in policies:
        name, state = p.get("displayName", p.get("id", "?")), p.get("state")
        u = _users(p)
        if state == "disabled":
            out.append(finding("CA-DISABLED", "INFO", name, "Policy is disabled", f"modified {iso_day(p.get('modifiedDateTime'))}",
                               f"{CA_PORTAL}. Delete it if it is no longer needed, or record why it is kept"))
            continue
        if state == "enabledForReportingButNotEnforced":
            since = p.get("modifiedDateTime") or p.get("createdDateTime")
            age = days_since(since, now)
            if age is not None and age > max_days:
                out.append(finding("CA-REPORT-ONLY-STALE", "MEDIUM", name, f"Report-only for {age} days",
                                   f"report-only since {iso_day(since)} (more than {max_days} days); controls: {controls_label(p)}",
                                   f"{CA_PORTAL}. Review the report-only results in the sign-in logs, then turn the policy on or delete it"))
        both = []
        for kind in ("Users", "Groups", "Roles"):
            inc = set(u.get(f"include{kind}") or []) - SPECIAL_USERS
            both += sorted(inc & set(u.get(f"exclude{kind}") or []))
        if both:
            out.append(finding("CA-INCLUDE-EXCLUDE-CANCEL", "MEDIUM", name, "Includes and excludes the same target",
                               f"both included and excluded: {', '.join(t.label(o) for o in both)}",
                               f"{CA_PORTAL}. Exclusion wins: fix the include list so the policy targets who it was meant to"))
        if t.have_users:
            t.unknown_groups.clear()
            reached = [uid for uid in t.users if t.applies(p, uid)]
            if not reached and not t.unknown_groups:
                out.append(finding("CA-ZERO-TARGET", "MEDIUM", name, "Policy applies to no user",
                                   f"state {state}; 0 of {len(t.users)} exported users are in scope" + ("; include and exclude cancel out"
                                                                                                          if both else ""),
                                   f"{CA_PORTAL}. Fix the assignments or delete the policy"))
        if state == "enabled":
            sig = json.dumps([p.get("conditions"), p.get("grantControls"), p.get("sessionControls")], sort_keys=True)
            signatures.setdefault(sig, []).append(name)
    for names in signatures.values():
        if len(names) > 1:
            out.append(finding("CA-OVERLAP", "INFO", " and ".join(sorted(names)), "Policies with identical conditions and controls",
                               f"{len(names)} enabled policies are the same apart from their names",
                               f"{CA_PORTAL}. Keep one, so later edits are not made to only one copy"))
    return out


def check_locations(locations, enabled: list[dict], cfg: dict) -> list[dict]:
    out: list[dict] = []
    prefix4 = cfg_int(cfg, "broad_ipv4_prefix", 16)
    trusted = {}
    for loc in locations or []:
        ranges = [r.get("cidrAddress", "") for r in loc.get("ipRanges") or []]
        if not loc.get("isTrusted"):
            continue
        trusted[loc.get("id")] = (loc.get("displayName", "?"), ranges)
        broad = []
        for r in ranges:
            try:
                net = ipaddress.ip_network(r, strict=False)
            except ValueError:
                continue
            if net.prefixlen < (prefix4 if net.version == 4 else 32):
                broad.append(r)
        if broad:
            out.append(finding("CA-LOCATION-BROAD", "MEDIUM", loc.get("displayName", "?"), "Trusted named location is very wide",
                               f"trusted ranges wider than /{prefix4} (IPv4) or /32 (IPv6): {', '.join(broad)}",
                               "Entra admin center > Protection > Conditional Access > Named locations. Narrow the ranges to your "
                               "egress addresses"))
    for p in enabled:
        if not (requires_mfa(p) and "All" in (_users(p).get("includeUsers") or [])):
            continue
        excl = ((_cond(p).get("locations") or {}).get("excludeLocations")) or []
        skipped = [("all trusted locations" if x == "AllTrusted" else trusted.get(x, (x, []))[0]) for x in excl
                   if x == "AllTrusted" or x in trusted]
        if skipped:
            out.append(finding("CA-TRUSTED-LOCATION-SKIP", "LOW", p.get("displayName", "?"), "MFA is skipped from trusted locations",
                               f"excluded locations: {', '.join(skipped)}",
                               f"{CA_PORTAL}. Require MFA everywhere, or record why the network is trusted"))
    return out


def matrix(policies: list[dict], t: Tenant) -> list[dict]:
    rows = []
    personas = {name: t.persona(name) for name in PERSONAS} if t.have_users else {}
    for p in policies:
        if p.get("state") == "disabled":
            continue
        row = {"policy": p.get("displayName", "?"), "state": "report-only" if p.get("state") != "enabled" else "enabled",
               "controls": controls_label(p)}
        for name in PERSONAS:
            people = personas.get(name)
            row[name] = "?" if people is None else f"{sum(1 for uid in people if t.applies(p, uid))}/{len(people)}"
        rows.append(row)
    return rows


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    policies = ex.list("conditional-access-policies.json", required=True)
    locations = ex.list("named-locations.json")
    users = ex.list("users.json")
    groups = ex.list("groups.json")
    members = ex.dir_lists("group-members")
    role_defs = ex.list("role-definitions.json")
    assignments = ex.list("role-assignments.json")
    eligible = ex.list("role-eligibility-schedule-instances.json")
    limit = cfg_int(cfg, "list_limit", 10)
    t = Tenant(users, groups, members, role_defs, assignments, eligible, cfg)
    enabled = [p for p in policies if p.get("state") == "enabled"]
    active = [p for p in policies if p.get("state") in ("enabled", "enabledForReportingButNotEnforced")]
    findings = check_gaps(enabled, t, limit) + check_exclusions(active, enabled, t, limit) + check_policies(policies, t, cfg, now)
    findings += check_locations(locations, enabled, cfg)
    t.unknown_groups.clear()
    rows = matrix(policies, t)
    for p in active:
        for uid in t.users:
            t.applies(p, uid)
    not_evaluated = []
    if users is None:
        not_evaluated.append("users.json not found: coverage, CA-ZERO-TARGET and the matrix need it; gaps were checked structurally")
    if assignments is None and eligible is None:
        not_evaluated.append("role-assignments.json not found: no admins known, so admin coverage was not evaluated")
    if t.unknown_groups:
        not_evaluated.append("no group-members export for referenced groups (treated as empty): "
                             + ", ".join(sorted(t.label(g) for g in t.unknown_groups)))
    if not cfg.get("break_glass") and not cfg.get("break_glass_groups"):
        not_evaluated.append("no break-glass accounts configured: every exclusion is reported as unexplained")
    rep = {"tool": "ca_gaps", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)), "missing_inputs": sorted(set(ex.missing)),
           "warnings": ex.warnings, "not_evaluated": not_evaluated,
           "personas": {n: len(t.persona(n)) for n in PERSONAS} if t.have_users else {},
           "findings": sort_findings(findings), "matrix": rows,
           "note": "Coverage is resolved from exported data and does not simulate sign-ins (no client, platform, location or risk "
                   "conditions per user). Verify in the What If tool before changing a policy; the script changed nothing."}
    return rep, ex, person_names(users)


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Conditional Access gap analysis", ex, now)
    lines += ["| Severity | Findings |", "|---|---|"] + [f"| {s} | {n} |" for s, n in rep["counts"].items()] + [""]
    lines += ["## Findings", ""] + render_findings(rep["findings"])
    if rep["matrix"]:
        lines += ["", "## Coverage matrix (users in scope / users in persona)", "",
                  "| Policy | State | Controls | " + " | ".join(PERSONAS) + " |", "|---|---|---|" + "---|" * len(PERSONAS)]
        for r in rep["matrix"]:
            lines.append(f"| {cell(r['policy'])} | {r['state']} | {cell(r['controls'])} | " + " | ".join(r[n] for n in PERSONAS) + " |")
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
