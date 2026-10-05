#!/usr/bin/env python3
"""Evaluate a folder of exported Microsoft Entra ID settings offline and report posture findings.

Input folder (file names the skill tells you to save; every file is optional unless noted, and checks whose input
is missing are listed as skipped):
  conditional-access-policies.json         GET /identity/conditionalAccess/policies
  security-defaults.json                   GET /policies/identitySecurityDefaultsEnforcementPolicy
  authorization-policy.json                GET /policies/authorizationPolicy
  role-definitions.json                    GET /roleManagement/directory/roleDefinitions
  role-assignments.json                    GET /roleManagement/directory/roleAssignments?$expand=principal
  role-eligibility-schedule-instances.json GET /roleManagement/directory/roleEligibilityScheduleInstances (PIM)
  role-assignment-schedule-instances.json  GET /roleManagement/directory/roleAssignmentScheduleInstances (PIM)
  users.json                               GET /users?$select=id,displayName,userPrincipalName,userType,
                                               accountEnabled,createdDateTime,signInActivity
  applications.json                        GET /applications
  service-principals.json                  GET /servicePrincipals
  graph-app-role-assignments.json          GET /servicePrincipals/{graph-sp-id}/appRoleAssignedTo
  signins.json                             GET /auditLogs/signIns (a recent window, optional)
  directory-audits.json                    GET /auditLogs/directoryAudits (a recent window, optional)

Checks (id, default severity):
  SECDEF-OFF-NO-CA           HIGH      security defaults off and no enabled Conditional Access policy
  SECDEF-ON                  INFO      security defaults on (the CA checks below are then informational)
  CA-NO-MFA-ALL              HIGH      no enabled CA policy requires MFA (or an authentication strength) for all users
  CA-NO-MFA-ADMINS           CRITICAL  no enabled CA policy requires MFA for all users or for the Global Administrator role
  CA-LEGACY-AUTH             HIGH      no enabled CA policy blocks legacy authentication (Exchange ActiveSync and other clients)
  CA-REPORT-ONLY             LOW       an MFA or block policy is in report-only mode
  CA-EXCLUSION               MEDIUM    an MFA or legacy-auth policy excludes users or groups that are not configured break-glass
  CA-BREAKGLASS-NOT-EXCLUDED MEDIUM    a configured break-glass account is not excluded from an enforcing all-users policy
  CA-NO-BREAKGLASS           INFO      no break-glass accounts configured, so exclusions cannot be told apart
  ROLE-GA-PERMANENT          HIGH      a standing (non-PIM, no end date) Global Administrator that is not break-glass
  ROLE-GA-COUNT              MEDIUM    more Global Administrators than max_global_admins (default 4); LOW when fewer than 2
  ROLE-GUEST-ADMIN           HIGH      a guest holds a directory role (active or eligible)
  ROLE-SP-PRIVILEGED         HIGH      a service principal holds a privileged directory role
  ROLE-DISABLED-HOLDER       LOW       a disabled user still holds an active or eligible directory role
  GUEST-STALE                MEDIUM    a guest has not signed in for stale_guest_days (default 90), or never has
  APP-SECRET-EXPIRED         LOW       an application credential has expired and is still listed
  APP-SECRET-EXPIRING        LOW       an application credential expires within expiring_days (default 30)
  APP-SECRET-LONG-LIVED      MEDIUM    a client secret valid for more than max_secret_days (default 365)
  SP-HIGH-PRIV-APPROLE       HIGH      a service principal holds a high-risk Microsoft Graph application permission
                                       (CRITICAL for permissions that allow tenant takeover)
  CONSENT-USER-ALLOWED       MEDIUM    users may consent to any app for themselves (legacy user consent policy)
  CONSENT-USER-LOW-RISK      INFO      users may consent only to low-risk permissions from verified publishers
  GUEST-INVITE-EVERYONE      LOW       anyone, including guests, can invite guests
  SIGNIN-LEGACY-USED         MEDIUM    successful sign-ins with legacy authentication clients in the exported window
  AUDIT-CONSENT              INFO      consent-to-application events in the exported audit window

Config (YAML or JSON, optional):
  break_glass: [00000000-0000-0000-0000-0000000000b1, breakglass1@example.com]   object ids or UPNs
  break_glass_groups: [00000000-0000-0000-0000-0000000000b9]                     group ids excluded on purpose
  max_global_admins: 4
  stale_guest_days: 90
  max_secret_days: 365
  expiring_days: 30

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
from _graphio import cfg_int as _cfg_int  # noqa: E402

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"  # built-in role template id, the same in every tenant
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph's application id, the same in every tenant
PRIVILEGED_ROLE_NAMES = {
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Security Administrator", "Conditional Access Administrator", "Application Administrator",
    "Cloud Application Administrator", "User Administrator", "Authentication Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Intune Administrator", "Hybrid Identity Administrator",
    "Helpdesk Administrator", "Billing Administrator", "Teams Administrator", "Groups Administrator",
}
TAKEOVER_APP_ROLES = {"RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
                      "Directory.ReadWrite.All"}
HIGH_RISK_APP_ROLES = TAKEOVER_APP_ROLES | {
    "Mail.ReadWrite", "Mail.Send", "Mail.Read", "Sites.FullControl.All", "Sites.ReadWrite.All", "Files.ReadWrite.All",
    "User.ReadWrite.All", "Group.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "Domain.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All", "DeviceManagementRBAC.ReadWrite.All",
    "Chat.ReadWrite.All", "MailboxSettings.ReadWrite", "Calendars.ReadWrite", "Policy.ReadWrite.AuthenticationMethod",
}
LEGACY_CLIENTS = {"Exchange ActiveSync", "Other clients", "IMAP4", "POP3", "SMTP", "Authenticated SMTP", "MAPI Over HTTP",
                  "Offline Address Book", "Exchange Web Services", "AutoDiscover", "Exchange Online PowerShell",
                  "Outlook Anywhere (RPC over HTTP)", "Reporting Web Services", "Universal Outlook"}
CONFIG_KEYS = {"break_glass", "break_glass_groups", "max_global_admins", "stale_guest_days", "max_secret_days", "expiring_days"}
CA_PORTAL = "Entra admin center > Protection > Conditional Access > Policies"


def _users(policy: dict) -> dict:
    return ((policy.get("conditions") or {}).get("users")) or {}


def _grant(policy: dict) -> dict:
    return policy.get("grantControls") or {}


def requires_mfa(policy: dict) -> bool:
    g = _grant(policy)
    return "mfa" in [str(c).lower() for c in g.get("builtInControls") or []] or bool(g.get("authenticationStrength"))


def blocks(policy: dict) -> bool:
    return "block" in [str(c).lower() for c in _grant(policy).get("builtInControls") or []]


def all_apps(policy: dict) -> bool:
    apps = ((policy.get("conditions") or {}).get("applications")) or {}
    return "All" in (apps.get("includeApplications") or [])


def all_users(policy: dict) -> bool:
    return "All" in (_users(policy).get("includeUsers") or [])


def blocks_legacy(policy: dict) -> bool:
    types = set(((policy.get("conditions") or {}).get("clientAppTypes")) or [])
    return blocks(policy) and {"exchangeActiveSync", "other"} <= types and all_users(policy)


class Directory:
    """Lookups from the exported users, service principals and role definitions."""

    def __init__(self, users, sps, role_defs):
        self.users = {u.get("id"): u for u in users or []}
        self.by_upn = {str(u.get("userPrincipalName", "")).lower(): u for u in users or []}
        self.sps = {s.get("id"): s for s in sps or []}
        self.roles: dict[str, str] = {}
        for r in role_defs or []:
            rid = r.get("id") or r.get("roleTemplateId")
            if rid:
                self.roles[rid] = r.get("displayName", rid)
            if r.get("roleTemplateId"):
                self.roles[r["roleTemplateId"]] = r.get("displayName", r["roleTemplateId"])
        self.roles.setdefault(GLOBAL_ADMIN_TEMPLATE, "Global Administrator")

    def role_name(self, rid: str) -> str:
        return self.roles.get(rid, rid)

    def describe(self, pid: str, expanded: dict | None = None) -> tuple[str, str]:
        """Return (label, kind) for a principal id; kind is user, guest, servicePrincipal, group or unknown."""
        p = expanded or {}
        otype = str(p.get("@odata.type", ""))
        u = self.users.get(pid)
        if u or otype.endswith("user"):
            u = u or p
            kind = "guest" if u.get("userType") == "Guest" or "#EXT#" in str(u.get("userPrincipalName", "")) else "user"
            return u.get("userPrincipalName") or u.get("displayName") or pid, kind
        s = self.sps.get(pid)
        if s or otype.endswith("servicePrincipal"):
            s = s or p
            return f"{s.get('displayName', pid)} (service principal {pid})", "servicePrincipal"
        if otype.endswith("group"):
            return f"{p.get('displayName', pid)} (group {pid})", "group"
        return pid, "unknown"


def break_glass_ids(cfg: dict, d: Directory) -> set[str]:
    out = set()
    for entry in cfg.get("break_glass") or []:
        e = str(entry)
        if "@" in e:
            u = d.by_upn.get(e.lower())
            if u:
                out.add(u.get("id"))
            out.add(e.lower())
        else:
            out.add(e)
    return out


def check_ca(policies, secdef, cfg, d: Directory) -> list[dict]:
    out: list[dict] = []
    enabled = [p for p in policies or [] if p.get("state") == "enabled"]
    secdef_on = bool((secdef or {}).get("isEnabled"))
    if secdef is not None and not secdef_on and policies is not None and not enabled:
        out.append(finding("SECDEF-OFF-NO-CA", "HIGH", "tenant", "Security defaults are off and no Conditional Access policy is enabled",
                           "identitySecurityDefaultsEnforcementPolicy.isEnabled is false; 0 enabled CA policies",
                           "Entra admin center > Overview > Properties > Manage security defaults, or create CA policies",
                           "PATCH /policies/identitySecurityDefaultsEnforcementPolicy {\"isEnabled\": true}"))
    if secdef_on:
        out.append(finding("SECDEF-ON", "INFO", "tenant", "Security defaults are on; MFA and legacy-auth blocking come from them",
                           "isEnabled is true", "Entra admin center > Overview > Properties > Manage security defaults"))
    if policies is None:
        return out
    sev = (lambda s: "INFO") if secdef_on else (lambda s: s)
    mfa_all = [p for p in enabled if requires_mfa(p) and all_users(p) and all_apps(p)]
    ga_ids = {rid for rid, name in d.roles.items() if name == "Global Administrator"} | {GLOBAL_ADMIN_TEMPLATE}
    mfa_admin = [p for p in enabled if requires_mfa(p) and all_apps(p) and (all_users(p) or ga_ids & set(_users(p).get("includeRoles") or []))]
    if not mfa_all:
        out.append(finding("CA-NO-MFA-ALL", sev("HIGH"), "conditional access", "No enabled policy requires MFA for all users and all apps",
                           f"{len(enabled)} enabled policies; none has includeUsers All, includeApplications All and grant mfa "
                           "or an authentication strength", CA_PORTAL + " > New policy (template: Require MFA for all users)",
                           "POST /identity/conditionalAccess/policies (start in report-only mode)"))
    if not mfa_admin:
        out.append(finding("CA-NO-MFA-ADMINS", sev("CRITICAL"), "conditional access", "No enabled policy requires MFA for Global Administrators",
                           "no enabled policy with grant mfa targets All users or the Global Administrator role",
                           CA_PORTAL + " > New policy (template: Require MFA for administrators)",
                           "POST /identity/conditionalAccess/policies (start in report-only mode)"))
    if not any(blocks_legacy(p) for p in enabled):
        out.append(finding("CA-LEGACY-AUTH", sev("HIGH"), "conditional access", "No enabled policy blocks legacy authentication",
                           "no enabled policy for All users blocks clientAppTypes exchangeActiveSync and other",
                           CA_PORTAL + " > New policy (template: Block legacy authentication)",
                           "POST /identity/conditionalAccess/policies (start in report-only mode)"))
    for p in policies:
        if p.get("state") == "enabledForReportingButNotEnforced" and (requires_mfa(p) or blocks(p)):
            out.append(finding("CA-REPORT-ONLY", "LOW", p.get("displayName", p.get("id", "?")), "Policy is report-only, so it is not enforced",
                               f"state enabledForReportingButNotEnforced, id {p.get('id')}", CA_PORTAL + " > (policy) > Enable policy: On",
                               f"PATCH /identity/conditionalAccess/policies/{p.get('id')} {{\"state\": \"enabled\"}}"))
    bg = break_glass_ids(cfg, d)
    bg_groups = {str(g) for g in cfg.get("break_glass_groups") or []}
    if not bg and not bg_groups:
        out.append(finding("CA-NO-BREAKGLASS", "INFO", "config", "No break-glass accounts configured",
                           "set break_glass in the config so exclusions can be told apart from gaps"))
    for p in enabled:
        if not (requires_mfa(p) or blocks_legacy(p)):
            continue
        u = _users(p)
        name = p.get("displayName", p.get("id", "?"))
        odd_users = [x for x in u.get("excludeUsers") or [] if x not in bg and x != "GuestsOrExternalUsers"]
        odd_groups = [x for x in u.get("excludeGroups") or [] if x not in bg_groups]
        if odd_users or odd_groups:
            labels = [d.describe(x)[0] for x in odd_users] + [f"group {g}" for g in odd_groups]
            out.append(finding("CA-EXCLUSION", "MEDIUM", name, "Policy excludes principals that are not configured break-glass",
                               "excluded: " + ", ".join(labels), CA_PORTAL + " > (policy) > Users > Exclude",
                               f"GET /identity/conditionalAccess/policies/{p.get('id')} then review conditions.users.excludeUsers"))
        if all_users(p) and (bg or bg_groups):
            excluded = set(u.get("excludeUsers") or []) | set(u.get("excludeGroups") or [])
            for b in sorted(x for x in bg if "@" not in x):
                if b not in excluded and not (bg_groups & excluded):
                    out.append(finding("CA-BREAKGLASS-NOT-EXCLUDED", "MEDIUM", name, "Break-glass account is not excluded (lockout risk)",
                                       f"{d.describe(b)[0]} is covered by this all-users policy", CA_PORTAL + " > (policy) > Users > Exclude",
                                       f"PATCH /identity/conditionalAccess/policies/{p.get('id')} (add the account to excludeUsers)"))
    return out


def check_roles(assignments, eligible, schedules, cfg, d: Directory) -> tuple[list[dict], list[dict]]:
    """Returns (findings, role holder rows)."""
    out: list[dict] = []
    holders: list[dict] = []
    bg = break_glass_ids(cfg, d)
    permanent_ids: set[str] | None = None
    if schedules is not None:
        permanent_ids = {s.get("principalId") for s in schedules
                         if s.get("assignmentType", "Assigned") == "Assigned" and not s.get("endDateTime")
                         and d.role_name(s.get("roleDefinitionId", "")) == "Global Administrator"}
    for a in assignments or []:
        label, kind = d.describe(a.get("principalId", ""), a.get("principal"))
        holders.append({"role": d.role_name(a.get("roleDefinitionId", "")), "principal": label, "kind": kind,
                        "principal_id": a.get("principalId", ""), "state": "active"})
    for e in eligible or []:
        label, kind = d.describe(e.get("principalId", ""), e.get("principal"))
        holders.append({"role": d.role_name(e.get("roleDefinitionId", "")), "principal": label, "kind": kind,
                        "principal_id": e.get("principalId", ""), "state": "eligible"})
    if assignments is None and eligible is None:
        return out, holders
    ga = [h for h in holders if h["role"] == "Global Administrator"]
    ga_principals = {h["principal_id"] for h in ga}
    max_ga = _cfg_int(cfg, "max_global_admins", 4)
    if len(ga_principals) > max_ga:
        out.append(finding("ROLE-GA-COUNT", "MEDIUM", "Global Administrator", f"{len(ga_principals)} Global Administrators (more than {max_ga})",
                           ", ".join(sorted(h["principal"] for h in ga)),
                           "Entra admin center > Roles and administrators > Global Administrator",
                           "DELETE /roleManagement/directory/roleAssignments/{id} for holders who do not need the role"))
    elif 0 < len(ga_principals) < 2:
        out.append(finding("ROLE-GA-COUNT", "LOW", "Global Administrator", "Only one Global Administrator (single point of failure)",
                           ", ".join(h["principal"] for h in ga), "Entra admin center > Roles and administrators > Global Administrator"))
    for h in ga:
        if h["state"] != "active" or h["principal_id"] in bg or h["principal"].lower() in bg:
            continue
        standing = h["principal_id"] in permanent_ids if permanent_ids is not None else True
        if standing:
            note = ("assignmentType Assigned with no endDateTime" if permanent_ids is not None
                    else "active assignment and no PIM schedule export, so treated as standing")
            out.append(finding("ROLE-GA-PERMANENT", "HIGH", h["principal"], "Standing Global Administrator assignment", note,
                               "Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles",
                               "POST /roleManagement/directory/roleEligibilityScheduleRequests (make eligible), then remove the active assignment"))
    for h in holders:
        user = d.users.get(h["principal_id"])
        if user and user.get("accountEnabled") is False:
            out.append(finding("ROLE-DISABLED-HOLDER", "LOW", h["principal"],
                               f"Disabled account holds the {h['role']} role",
                               f"principal {h['principal_id']} ({h['state']}); accountEnabled is false",
                               "Entra admin center > Roles and administrators > " + h["role"]))
        if h["kind"] == "guest":
            out.append(finding("ROLE-GUEST-ADMIN", "HIGH", h["principal"], f"Guest holds the {h['role']} role ({h['state']})",
                               f"principal {h['principal_id']}", "Entra admin center > Roles and administrators > " + h["role"],
                               "DELETE /roleManagement/directory/roleAssignments/{id}"))
        if h["kind"] == "servicePrincipal" and h["role"] in PRIVILEGED_ROLE_NAMES:
            out.append(finding("ROLE-SP-PRIVILEGED", "HIGH", h["principal"], f"Service principal holds the {h['role']} role",
                               f"principal {h['principal_id']} ({h['state']})", "Entra admin center > Roles and administrators > " + h["role"],
                               "DELETE /roleManagement/directory/roleAssignments/{id} and grant a scoped Graph permission instead"))
    return out, holders


def check_guests(users, cfg, now) -> list[dict]:
    out: list[dict] = []
    if users is None:
        return out
    limit = _cfg_int(cfg, "stale_guest_days", 90)
    has_signin = any("signInActivity" in u for u in users)
    for u in users:
        if u.get("userType") != "Guest" or u.get("accountEnabled") is False:
            continue
        upn = u.get("userPrincipalName") or u.get("mail") or u.get("id", "?")
        if not has_signin:
            continue
        sia = u.get("signInActivity") or {}
        last = max((dt for dt in (parse_dt(sia.get("lastSignInDateTime")), parse_dt(sia.get("lastNonInteractiveSignInDateTime"))) if dt),
                   default=None)
        age = days_since(last, now) if last else None
        created = days_since(u.get("createdDateTime"), now)
        if (age is not None and age > limit) or (age is None and (created is None or created > limit)):
            ev = f"last sign-in {iso_day(last)}" + ("" if last else f", created {iso_day(u.get('createdDateTime'))}")
            out.append(finding("GUEST-STALE", "MEDIUM", upn, f"Guest has not signed in for more than {limit} days", ev,
                               "Entra admin center > Users > (guest) > Disable or Delete; or an access review on guests",
                               f"PATCH /users/{u.get('id')} {{\"accountEnabled\": false}}"))
    return out


def check_app_credentials(apps, cfg, now) -> list[dict]:
    out: list[dict] = []
    max_days = _cfg_int(cfg, "max_secret_days", 365)
    soon = _cfg_int(cfg, "expiring_days", 30)
    for app in apps or []:
        name = f"{app.get('displayName', '?')} (appId {app.get('appId', '?')})"
        for kind, creds in (("secret", app.get("passwordCredentials") or []), ("certificate", app.get("keyCredentials") or [])):
            for c in creds:
                end, start = parse_dt(c.get("endDateTime")), parse_dt(c.get("startDateTime"))
                label = c.get("displayName") or c.get("keyId", "?")
                remove = (f"POST /applications/{app.get('id')}/removePassword {{\"keyId\": \"{c.get('keyId')}\"}}" if kind == "secret"
                          else f"PATCH /applications/{app.get('id')} (drop the expired entry from keyCredentials)")
                if end and end < now:
                    out.append(finding("APP-SECRET-EXPIRED", "LOW", name, f"Expired client {kind} still listed",
                                       f"{label} expired {iso_day(end)}", "Entra admin center > App registrations > (app) > Certificates & secrets",
                                       remove))
                    continue
                if end and (end - now).days <= soon:
                    out.append(finding("APP-SECRET-EXPIRING", "LOW", name, f"Client {kind} expires within {soon} days",
                                       f"{label} expires {iso_day(end)}", "Entra admin center > App registrations > (app) > Certificates & secrets"))
                if kind == "secret" and end and start and (end - start).days > max_days:
                    out.append(finding("APP-SECRET-LONG-LIVED", "MEDIUM", name, f"Client secret valid for more than {max_days} days",
                                       f"{label}: {iso_day(start)} to {iso_day(end)} ({(end - start).days} days)",
                                       "Entra admin center > App registrations > (app) > Certificates & secrets; prefer a certificate "
                                       "or workload identity federation", remove + " after rotating to a shorter-lived credential"))
    return out


def check_app_roles(sps, graph_assignments, d: Directory) -> list[dict]:
    out: list[dict] = []
    if not graph_assignments:
        return out
    role_names: dict[str, str] = {}
    for sp in sps or []:
        for r in sp.get("appRoles") or []:
            if r.get("id") and r.get("value"):
                role_names[r["id"]] = r["value"]
    for a in graph_assignments:
        perm = role_names.get(a.get("appRoleId", ""), "")
        if perm not in HIGH_RISK_APP_ROLES:
            continue
        sev = "CRITICAL" if perm in TAKEOVER_APP_ROLES else "HIGH"
        who = a.get("principalDisplayName") or d.describe(a.get("principalId", ""))[0]
        resource = a.get("resourceDisplayName", "Microsoft Graph")
        out.append(finding("SP-HIGH-PRIV-APPROLE", sev, who, f"Holds application permission {perm} on {resource}",
                           f"appRoleAssignment {a.get('id', '?')} created {iso_day(a.get('createdDateTime'))}",
                           "Entra admin center > Enterprise applications > (app) > Permissions",
                           f"DELETE /servicePrincipals/{a.get('principalId')}/appRoleAssignments/{a.get('id')} "
                           "after confirming the app does not need it"))
    return out


def check_authorization(auth) -> list[dict]:
    out: list[dict] = []
    if auth is None:
        return out
    grants = [str(x) for x in ((auth.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or [])]
    portal = "Entra admin center > Enterprise applications > Consent and permissions > User consent settings"
    if any(g.endswith("microsoft-user-default-legacy") for g in grants):
        out.append(finding("CONSENT-USER-ALLOWED", "MEDIUM", "tenant", "Users can consent to any application for themselves",
                           "permissionGrantPoliciesAssigned includes microsoft-user-default-legacy", portal,
                           "PATCH /policies/authorizationPolicy (set permissionGrantPoliciesAssigned to [] or the low-risk policy)"))
    elif any(g.endswith("microsoft-user-default-low") for g in grants):
        out.append(finding("CONSENT-USER-LOW-RISK", "INFO", "tenant", "Users can consent to low-risk permissions from verified publishers",
                           "permissionGrantPoliciesAssigned includes microsoft-user-default-low", portal))
    if auth.get("allowInvitesFrom") == "everyone":
        out.append(finding("GUEST-INVITE-EVERYONE", "LOW", "tenant", "Anyone in the organization, including guests, can invite guests",
                           "allowInvitesFrom is everyone", "Entra admin center > External Identities > External collaboration settings",
                           "PATCH /policies/authorizationPolicy {\"allowInvitesFrom\": \"adminsAndGuestInviters\"}"))
    return out


def check_logs(signins, audits) -> list[dict]:
    out: list[dict] = []
    legacy: dict[str, set[str]] = {}
    for s in signins or []:
        client = s.get("clientAppUsed", "")
        if client in LEGACY_CLIENTS and ((s.get("status") or {}).get("errorCode", 0) == 0):
            legacy.setdefault(s.get("userPrincipalName", "?"), set()).add(client)
    for upn, clients in sorted(legacy.items()):
        out.append(finding("SIGNIN-LEGACY-USED", "MEDIUM", upn, "Successful legacy-authentication sign-ins in the exported window",
                           "clients: " + ", ".join(sorted(clients)), "Entra admin center > Monitoring > Sign-in logs (filter Client app)"))
    for a in audits or []:
        if a.get("activityDisplayName") == "Consent to application":
            target = ", ".join(t.get("displayName", "?") for t in a.get("targetResources") or [])
            by = ((a.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName", "?")
            out.append(finding("AUDIT-CONSENT", "INFO", target or "?", "Consent to application recorded",
                               f"by {by} on {iso_day(a.get('activityDateTime'))}", "Entra admin center > Monitoring > Audit logs"))
    return out


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    policies = ex.list("conditional-access-policies.json")
    secdef = ex.obj("security-defaults.json")
    auth = ex.obj("authorization-policy.json")
    role_defs = ex.list("role-definitions.json", "directory-roles.json")
    assignments = ex.list("role-assignments.json")
    eligible = ex.list("role-eligibility-schedule-instances.json")
    schedules = ex.list("role-assignment-schedule-instances.json")
    users = ex.list("users.json")
    apps = ex.list("applications.json")
    sps = ex.list("service-principals.json")
    graph_assignments = ex.list("graph-app-role-assignments.json")
    signins = ex.list("signins.json")
    audits = ex.list("directory-audits.json")
    d = Directory(users, sps, role_defs)
    findings: list[dict] = []
    findings += check_ca(policies, secdef, cfg, d)
    role_findings, holders = check_roles(assignments, eligible, schedules, cfg, d)
    findings += role_findings
    findings += check_guests(users, cfg, now)
    findings += check_app_credentials(apps, cfg, now)
    findings += check_app_roles(sps, graph_assignments, d)
    findings += check_authorization(auth)
    findings += check_logs(signins, audits)
    skipped = []
    if users is not None and not any("signInActivity" in u for u in users):
        skipped.append("GUEST-STALE: users.json has no signInActivity (needs AuditLog.Read.All and Entra ID P1)")
    if assignments is not None and schedules is None:
        skipped.append("ROLE-GA-PERMANENT used active assignments only; export role-assignment-schedule-instances.json "
                       "to tell PIM activations apart")
    if sps is not None and graph_assignments is None:
        skipped.append("SP-HIGH-PRIV-APPROLE: graph-app-role-assignments.json not found")
    rep = {"tool": "entra_posture", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)),
           "missing_inputs": sorted(set(ex.missing)), "warnings": ex.warnings, "skipped": skipped,
           "findings": sort_findings(findings), "role_holders": holders,
           "note": "Findings come from exported data at one point in time. Verify each one in the tenant before any change; "
                   "the script changed nothing."}
    return rep, ex, person_names(users)


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Entra ID posture review", ex, now)
    lines += ["| Severity | Findings |", "|---|---|"] + [f"| {s} | {n} |" for s, n in rep["counts"].items()] + [""]
    lines += ["## Findings", ""] + render_findings(rep["findings"])
    if rep["skipped"]:
        lines += ["", "## Not fully evaluated", ""] + [f"- {s}" for s in rep["skipped"]]
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
