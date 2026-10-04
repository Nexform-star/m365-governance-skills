#!/usr/bin/env python3
"""Review the Microsoft Graph permissions an app registration or connector requests or holds, against what a task needs.

Input folder (each file optional, at least one permission source needed):
  application.json                 GET /applications/{object-id}            requiredResourceAccess (requested permissions)
  service-principal.json           GET /servicePrincipals/{object-id}       the app's enterprise application (its id filters grants)
  oauth2-permission-grants.json    GET /servicePrincipals/{sp-id}/oauth2PermissionGrants   delegated grants and consent type
  app-role-assignments.json        GET /servicePrincipals/{sp-id}/appRoleAssignments       application permissions granted
  resource-service-principals.json GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')
                                   the resource API's appRoles and oauth2PermissionScopes, used to turn permission ids into names
  declared-permissions.json        for a third-party connector that publishes its permission list instead:
                                   {"app": "name", "permissions": [{"name": "Mail.ReadWrite", "type": "Application"}]}

Needs manifest (--needs, YAML or JSON), written for the task before anything is consented:
  task: Read the shared events calendar into the booking tool
  type: Application                  default type for entries without one (Application or Delegated)
  needs:
    - Calendars.Read
    - {permission: User.ReadBasic.All, type: Delegated}

Checks (id, default severity):
  PERM-HIGH-RISK          CRITICAL/HIGH  a granted or requested permission is on the high-risk list. Application permissions take the
                                         listed severity; delegated ones are one level lower (bounded by the signed-in user's access)
  PERM-BROADER            HIGH/MEDIUM    write where read suffices, or a wider level or breadth than the need (Mail.ReadWrite for Mail.Read)
  PERM-APP-NOT-DELEGATED  HIGH           an application permission where the task needs only the delegated one
  PERM-UNUSED             MEDIUM         a permission no need explains (HIGH when it is also high risk)
  PERM-ALL-SCOPED         LOW            an .All permission where a scoped alternative exists (Sites.Selected and others)
  PERM-UNRESOLVED         LOW            a permission id that could not be turned into a name (export the resource service principal)
  CONSENT-ADMIN-ALL       INFO           delegated permissions consented by an admin for all users (consentType AllPrincipals)
  CONSENT-USER            INFO           delegated permissions consented by one user for themselves (MEDIUM when high risk)
  CONSENT-PENDING         INFO           requested permissions with no grant yet (consent has not happened)
  PERM-MISSING            INFO           a needed permission that is neither requested nor granted

Output: findings, a consent table, and the least-privilege replacement set (exact Graph permission names and types).
Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: removal calls are printed for review and never run.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _graphio import (  # noqa: E402
    RANK,
    SEVERITIES,
    Export,
    InputError,
    add_common_args,
    as_of_datetime,
    cell,
    counts,
    dumps,
    exit_code,
    filter_min,
    finding,
    load_config,
    redact,
    render_findings,
    render_header,
    sort_findings,
)

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph's application id, the same in every tenant
TYPES = {"application": "Application", "role": "Application", "delegated": "Delegated", "scope": "Delegated"}
LEVELS = {"ReadBasic": 1, "Read": 2, "ReadWrite": 3, "Manage": 4, "FullControl": 5}
BREADTH = {"": 0, "Shared": 1, "All": 2, "Directory": 2}
# Severity when held as an application permission. Delegated grants are reported one level lower.
HIGH_RISK = {
    "RoleManagement.ReadWrite.Directory": "CRITICAL", "AppRoleAssignment.ReadWrite.All": "CRITICAL",
    "Application.ReadWrite.All": "CRITICAL", "Directory.ReadWrite.All": "CRITICAL",
    "Sites.FullControl.All": "HIGH", "Sites.Manage.All": "HIGH", "Sites.ReadWrite.All": "HIGH", "Files.ReadWrite.All": "HIGH",
    "Mail.ReadWrite": "HIGH", "Mail.Send": "HIGH", "Mail.Read": "HIGH", "MailboxSettings.ReadWrite": "HIGH",
    "User.ReadWrite.All": "HIGH", "Group.ReadWrite.All": "HIGH", "GroupMember.ReadWrite.All": "HIGH",
    "Domain.ReadWrite.All": "HIGH", "Policy.ReadWrite.ConditionalAccess": "HIGH", "Policy.ReadWrite.AuthenticationMethod": "HIGH",
    "UserAuthenticationMethod.ReadWrite.All": "HIGH", "DeviceManagementConfiguration.ReadWrite.All": "HIGH",
    "DeviceManagementManagedDevices.PrivilegedOperations.All": "HIGH", "DeviceManagementRBAC.ReadWrite.All": "HIGH",
    "Chat.ReadWrite.All": "HIGH", "Chat.Read.All": "HIGH", "ChannelMessage.Read.All": "HIGH", "Calendars.ReadWrite": "HIGH",
    "Files.Read.All": "MEDIUM", "Sites.Read.All": "MEDIUM", "Calendars.Read": "MEDIUM", "Contacts.ReadWrite": "MEDIUM",
    "Directory.Read.All": "MEDIUM", "AuditLog.Read.All": "MEDIUM",
}
SCOPED_ALTERNATIVES = {
    "Sites.Read.All": "Sites.Selected (grant per site), or Lists.SelectedOperations.Selected for single lists",
    "Sites.ReadWrite.All": "Sites.Selected (grant per site)",
    "Sites.Manage.All": "Sites.Selected (grant per site)",
    "Sites.FullControl.All": "Sites.Selected (grant per site with the fullcontrol role only where needed)",
    "Files.Read.All": "Files.SelectedOperations.Selected (application) or Files.Read (delegated, the user's own files)",
    "Files.ReadWrite.All": "Files.SelectedOperations.Selected (application) or Files.ReadWrite (delegated, the user's own files)",
    "Mail.Read": "keep Mail.Read but limit it to named mailboxes with Exchange Online RBAC for Applications",
    "Mail.ReadWrite": "limit to named mailboxes with Exchange Online RBAC for Applications",
    "Mail.Send": "limit to named mailboxes with Exchange Online RBAC for Applications",
    "Calendars.Read": "limit to named mailboxes with Exchange Online RBAC for Applications",
    "Calendars.ReadWrite": "limit to named mailboxes with Exchange Online RBAC for Applications",
    "ChannelMessage.Read.All": "resource-specific consent: ChannelMessage.Read.Group per team",
    "Chat.Read.All": "resource-specific consent: ChatMessage.Read.Chat per chat",
    "Group.Read.All": "GroupMember.Read.All when only membership is read",
    "User.Read.All": "User.ReadBasic.All when only basic profile fields are read",
    "Directory.Read.All": "the specific User.Read.All, Group.Read.All or Application.Read.All the task reads",
}
# Directory-wide permissions also cover these narrower ones.
COVERS = {
    "Directory.Read.All": {"User.Read.All", "User.ReadBasic.All", "Group.Read.All", "GroupMember.Read.All", "Application.Read.All",
                           "Device.Read.All", "Organization.Read.All", "RoleManagement.Read.Directory", "AdministrativeUnit.Read.All"},
    "Group.Read.All": {"GroupMember.Read.All"},
    "Group.ReadWrite.All": {"GroupMember.ReadWrite.All", "GroupMember.Read.All"},
    "User.Read.All": {"User.ReadBasic.All"},
}
COVERS["Directory.ReadWrite.All"] = COVERS["Directory.Read.All"] | {"User.ReadWrite.All", "Group.ReadWrite.All", "Directory.Read.All",
                                                                    "GroupMember.ReadWrite.All"}
CONFIG_KEYS = {"task", "type", "needs"}
PORTAL_APP = "Entra admin center > App registrations > (app) > API permissions"
PORTAL_SP = "Entra admin center > Enterprise applications > (app) > Permissions"


def norm_type(value, default: str = "Delegated") -> str:
    t = TYPES.get(str(value or "").strip().lower())
    if value and not t:
        raise InputError(f"unknown permission type {value!r}: use Application or Delegated")
    return t or default


def parse(name: str) -> tuple[str, int | None, int]:
    """Split Mail.ReadWrite.Shared into (family Mail, level 3, breadth 1). Level None when the verb is not a read/write ladder."""
    parts = name.split(".")
    family = parts[0]
    level = LEVELS.get(parts[1]) if len(parts) > 1 else None
    breadth = BREADTH.get(parts[2], 0) if len(parts) > 2 else 0
    return family, level, breadth


def covers(have: str, need: str) -> bool:
    """True when permission `have` grants at least everything `need` grants (same type assumed)."""
    if have == need:
        return True
    if need in COVERS.get(have, set()):
        return True
    hf, hl, hb = parse(have)
    nf, nl, nb = parse(need)
    return hf == nf and hl is not None and nl is not None and hl >= nl and hb >= nb


def write_level(name: str) -> bool:
    level = parse(name)[1]
    return level is not None and level >= LEVELS["ReadWrite"] or name.endswith(".Send")


def lower(sev: str) -> str:
    return SEVERITIES[min(RANK[sev] + 1, len(SEVERITIES) - 1)]


def load_needs(path: str) -> dict:
    cfg = load_config(path, CONFIG_KEYS)
    default = norm_type(cfg.get("type"), "Delegated")
    needs = []
    for entry in cfg.get("needs") or []:
        if isinstance(entry, str):
            needs.append({"name": entry.strip(), "type": default})
        elif isinstance(entry, dict) and entry.get("permission"):
            needs.append({"name": str(entry["permission"]).strip(), "type": norm_type(entry.get("type"), default)})
        else:
            raise InputError(f"{path}: each needs entry is a permission name or {{permission, type}}")
    if not needs:
        raise InputError(f"{path}: the needs list is empty; list the permissions the task needs")
    return {"task": str(cfg.get("task") or ""), "needs": needs}


class Resolver:
    def __init__(self, resource_sps: list[dict] | None):
        self.roles: dict[str, str] = {}
        self.scopes: dict[str, str] = {}
        self.names: dict[str, str] = {GRAPH_APP_ID: "Microsoft Graph"}
        self.by_object: dict[str, str] = {}
        for sp in resource_sps or []:
            self.names[sp.get("appId", "")] = sp.get("displayName", sp.get("appId", "?"))
            self.by_object[sp.get("id", "")] = sp.get("displayName", "?")
            for r in sp.get("appRoles") or []:
                self.roles[r.get("id", "")] = r.get("value", "")
            for s in sp.get("oauth2PermissionScopes") or []:
                self.scopes[s.get("id", "")] = s.get("value", "")

    def name(self, pid: str, ptype: str) -> str | None:
        return (self.roles if ptype == "Application" else self.scopes).get(pid) or None


def collect(ex: Export, resolver: Resolver) -> tuple[list[dict], dict]:
    """Return permission records and app identity. Each record: name, type, resource, requested, granted, consent list."""
    perms: dict[tuple[str, str, str], dict] = {}
    unresolved: list[str] = []

    def rec(name: str, ptype: str, resource: str) -> dict:
        key = (resource, name, ptype)
        if key not in perms:
            perms[key] = {"name": name, "type": ptype, "resource": resource, "requested": False, "granted": False, "consent": []}
        return perms[key]

    app = ex.obj("application.json")
    sp = ex.obj("service-principal.json")
    grants = ex.list("oauth2-permission-grants.json")
    assignments = ex.list("app-role-assignments.json")
    declared = ex.obj("declared-permissions.json")
    identity = {"app": (app or sp or declared or {}).get("displayName") or (declared or {}).get("app") or "?",
                "app_id": (app or sp or {}).get("appId", ""), "sp_id": (sp or {}).get("id", "")}
    if app is None and sp is None and grants is None and assignments is None and declared is None:
        raise InputError(f"{ex.folder}: no permission source found (application.json, oauth2-permission-grants.json, "
                         "app-role-assignments.json or declared-permissions.json)")
    for rra in (app or {}).get("requiredResourceAccess") or []:
        resource = resolver.names.get(rra.get("resourceAppId", ""), rra.get("resourceAppId", "?"))
        for ra in rra.get("resourceAccess") or []:
            ptype = norm_type(ra.get("type"))
            name = resolver.name(ra.get("id", ""), ptype)
            if not name:
                name = f"unresolved:{ra.get('id', '?')}"
                unresolved.append(name)
            rec(name, ptype, resource)["requested"] = True
    for p in (declared or {}).get("permissions") or []:
        if not isinstance(p, dict) or not p.get("name"):
            raise InputError("declared-permissions.json: each permission needs a name")
        rec(str(p["name"]), norm_type(p.get("type")), str(p.get("resource") or "Microsoft Graph"))["requested"] = True
    for g in grants or []:
        if identity["sp_id"] and g.get("clientId") and g["clientId"] != identity["sp_id"]:
            continue
        resource = resolver.by_object.get(g.get("resourceId", ""), "Microsoft Graph")
        consent = "admin, all users" if g.get("consentType") == "AllPrincipals" else f"user {g.get('principalId', '?')}"
        for scope in str(g.get("scope") or "").split():
            r = rec(scope, "Delegated", resource)
            r["granted"] = True
            r["consent"].append({"consent": consent, "grant_id": g.get("id", ""), "kind": g.get("consentType", "?")})
    for a in assignments or []:
        if identity["sp_id"] and a.get("principalId") and a["principalId"] != identity["sp_id"]:
            continue
        name = resolver.name(a.get("appRoleId", ""), "Application")
        if not name:
            name = f"unresolved:{a.get('appRoleId', '?')}"
            unresolved.append(name)
        r = rec(name, "Application", a.get("resourceDisplayName") or resolver.by_object.get(a.get("resourceId", ""), "?"))
        r["granted"] = True
        r["consent"].append({"consent": "admin (application permission)", "grant_id": a.get("id", ""), "kind": "AppRole"})
    identity["unresolved"] = sorted(set(unresolved))
    identity["grant_data"] = grants is not None or assignments is not None
    return sorted(perms.values(), key=lambda p: (p["resource"], p["type"], p["name"])), identity


def fix_for(p: dict, identity: dict) -> tuple[str, str]:
    sp_id = identity.get("sp_id") or "{sp-id}"
    if p["granted"] and p["type"] == "Application":
        ids = ", ".join(c["grant_id"] for c in p["consent"]) or "{assignment-id}"
        return PORTAL_SP, f"DELETE /servicePrincipals/{sp_id}/appRoleAssignments/{ids}"
    if p["granted"]:
        ids = ", ".join(sorted({c["grant_id"] for c in p["consent"]})) or "{grant-id}"
        return PORTAL_SP, f"PATCH /oauth2PermissionGrants/{ids} with the scope string minus {p['name']} (DELETE when nothing remains)"
    return PORTAL_APP, "PATCH /applications/{object-id} with requiredResourceAccess minus " + p["name"]


def analyse(perms: list[dict], needs: list[dict], identity: dict) -> tuple[list[dict], list[dict]]:
    out: list[dict] = []
    replacement: list[dict] = []
    held = [p for p in perms if not p["name"].startswith("unresolved:")]
    for p in perms:
        subject = f"{p['name']} ({p['type']}, {p['resource']})"
        state = "granted" if p["granted"] else "requested only"
        portal, graph = fix_for(p, identity)
        if p["name"].startswith("unresolved:"):
            out.append(finding("PERM-UNRESOLVED", "LOW", subject, "Permission id could not be turned into a name",
                               "export resource-service-principals.json for this resource", portal))
            continue
        risk = HIGH_RISK.get(p["name"])
        if risk:
            sev = risk if p["type"] == "Application" else lower(risk)
            out.append(finding("PERM-HIGH-RISK", sev, subject, "High-risk permission", f"{state}; on the high-risk list as {risk} "
                               f"for application use", portal, graph if not any(n["name"] == p["name"] and n["type"] == p["type"]
                                                                                for n in needs) else ""))
        exact = [n for n in needs if n["name"] == p["name"] and n["type"] == p["type"]]
        if exact:
            if p["name"] in SCOPED_ALTERNATIVES:
                out.append(finding("PERM-ALL-SCOPED", "LOW", subject, "A scoped alternative exists",
                                   SCOPED_ALTERNATIVES[p["name"]], portal))
            continue
        same_type = [n for n in needs if n["type"] == p["type"] and covers(p["name"], n["name"])]
        delegated_only = [n for n in needs if n["type"] == "Delegated" and p["type"] == "Application" and covers(p["name"], n["name"])]
        if same_type:
            needed = ", ".join(n["name"] for n in same_type)
            sev = "HIGH" if write_level(p["name"]) and not any(write_level(n["name"]) for n in same_type) else "MEDIUM"
            what = "Write access where read suffices" if sev == "HIGH" else "Broader than the task needs"
            out.append(finding("PERM-BROADER", sev, subject, what, f"{state}; the task needs {needed}", portal, graph))
        elif delegated_only:
            out.append(finding("PERM-APP-NOT-DELEGATED", "HIGH", subject, "Application permission where a delegated one is enough",
                               f"{state}; the task needs {', '.join(n['name'] for n in delegated_only)} (Delegated). An application "
                               "permission works without a signed-in user, across the whole tenant", portal, graph))
        else:
            sev = "HIGH" if risk and p["type"] == "Application" else "MEDIUM"
            out.append(finding("PERM-UNUSED", sev, subject, "No listed need explains this permission", state, portal, graph))
        if p["name"] in SCOPED_ALTERNATIVES:
            out.append(finding("PERM-ALL-SCOPED", "LOW", subject, "A scoped alternative exists", SCOPED_ALTERNATIVES[p["name"]], portal))
    for p in held:
        for c in p["consent"]:
            if c["kind"] == "AllPrincipals":
                out.append(finding("CONSENT-ADMIN-ALL", "INFO", f"{p['name']} (Delegated)", "Admin consent for all users",
                                   f"grant {c['grant_id']}", PORTAL_SP))
            elif c["kind"] == "Principal":
                sev = "MEDIUM" if p["name"] in HIGH_RISK else "INFO"
                out.append(finding("CONSENT-USER", sev, f"{p['name']} (Delegated)", "Consented by one user for themselves",
                                   f"{c['consent']}, grant {c['grant_id']}", PORTAL_SP))
        if p["requested"] and not p["granted"] and identity["grant_data"]:
            out.append(finding("CONSENT-PENDING", "INFO", f"{p['name']} ({p['type']})", "Requested but not consented",
                                   "no grant or app role assignment found", PORTAL_APP))
    for n in needs:
        have = [p for p in held if p["type"] == n["type"] and covers(p["name"], n["name"])]
        if not have:
            out.append(finding("PERM-MISSING", "INFO", f"{n['name']} ({n['type']})", "Needed but neither requested nor granted",
                               "add it when the replacement set is applied", PORTAL_APP))
        replacement.append({"permission": n["name"], "type": n["type"], "resource": "Microsoft Graph",
                            "scoped_alternative": SCOPED_ALTERNATIVES.get(n["name"], "")})
    return out, replacement


def evaluate(folder: str, needs_path: str) -> tuple[dict, Export]:
    manifest = load_needs(needs_path)
    ex = Export(folder)
    resolver = Resolver(ex.list("resource-service-principals.json"))
    perms, identity = collect(ex, resolver)
    findings, replacement = analyse(perms, manifest["needs"], identity)
    consent_rows = [{"permission": p["name"], "type": p["type"], "resource": p["resource"],
                     "status": "granted" if p["granted"] else "requested, not consented",
                     "consent": "; ".join(c["consent"] for c in p["consent"]) or "none"} for p in perms]
    rep = {"tool": "permission_preflight", "task": manifest["task"], "app": identity["app"], "app_id": identity["app_id"],
           "inputs": sorted(set(ex.used)), "warnings": ex.warnings, "permissions": consent_rows,
           "findings": sort_findings(findings), "least_privilege_set": replacement,
           "note": "A preflight from exported data. Confirm the needs list with the task owner, apply the replacement set "
                   "yourself after review, and re-run. The script changed nothing."}
    return rep, ex


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header(f"Graph permission preflight: {cell(rep['app'])}", ex, now)
    if rep["task"]:
        lines += [f"Task: {cell(rep['task'])}", ""]
    lines += ["## Permissions and consent", "", "| Permission | Type | Resource | Status | Consent |", "|---|---|---|---|---|"]
    lines += [f"| {cell(p['permission'])} | {p['type']} | {cell(p['resource'])} | {p['status']} | {cell(p['consent'])} |"
              for p in rep["permissions"]]
    lines += ["", "## Findings", ""] + render_findings(rep["findings"])
    lines += ["", "## Least-privilege replacement set", "", "| Permission | Type | Resource | Scoped alternative |", "|---|---|---|---|"]
    lines += [f"| {r['permission']} | {r['type']} | {r['resource']} | {cell(r['scoped_alternative']) or '-'} |"
              for r in rep["least_privilege_set"]]
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder with the app's exported JSON")
    ap.add_argument("--needs", required=True, help="the task's needs manifest (YAML or JSON)")
    add_common_args(ap, config=False)
    args = ap.parse_args(argv)
    try:
        now = as_of_datetime(args.as_of)
        rep, ex = evaluate(args.folder, args.needs)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rep["findings"] = filter_min(rep["findings"], args.min_severity)
    rep["counts"] = counts(rep["findings"])
    code = exit_code(rep["findings"], args.fail_on)
    if args.redact:
        rep = redact(rep)
    print(dumps(rep) if args.json else render(rep, ex, now))
    return code


if __name__ == "__main__":
    sys.exit(main())
