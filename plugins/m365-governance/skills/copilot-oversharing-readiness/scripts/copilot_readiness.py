#!/usr/bin/env python3
"""Score a Microsoft 365 tenant's readiness for a Copilot rollout against the oversharing checks Microsoft
recommends, from read-only SharePoint and Graph exports, and print the remediation list by site owner.

Input folder (file names the skill tells you to save; only sites.json is required):
  sites.json          Get-PnPTenantSite -Detailed (PnP PowerShell) as JSON: Url, Title, Owner or OwnerEmail,
                          SharingCapability, SensitivityLabel, LastContentModifiedDate, RestrictContentOrgWideSearch.
                          Graph sites (webUrl, displayName) are accepted but carry no sharing or label fields.
  labels.json         Get-PnPAvailableSensitivityLabel, or GET /security/informationProtection/sensitivityLabels
                          (beta): id and name or displayName of each label
  site-groups.json    Get-PnPSiteGroup -Site <url> for every site, each row with SiteUrl added: SiteUrl, Title,
                          Roles, Users (login names)
  sharing-links.json  sharing links as Graph permission objects, GET /drives/{drive-id}/items/{item-id}/permissions,
                          each with siteUrl added; only link.scope is read (anonymous, organization, users)
  sharing-links.csv   or an aggregated CSV with columns site_url, anyone_links, organization_links, specific_people_links
                          (for example retyped from the SharePoint data access governance sharing links report)
  tenant.json         Get-PnPTenant as JSON, or GET /admin/sharepoint/settings: SharingCapability, DefaultSharingLinkType,
                          RequireAnonymousLinksExpireInDays
  dlp-policies.json   Get-DlpCompliancePolicy (Security and Compliance PowerShell) as JSON: Name, Mode, Enabled,
                          SharePointLocation, OneDriveLocation, Workload

Checks (id, default severity):
  SITE-EVERYONE-GRANT       HIGH      a site group contains "Everyone" or "Everyone except external users" (matched by
                                      the claim shape or the name); CRITICAL on a sensitive site
  SITE-ANYONE-LINKS         HIGH      the site has anyone (anonymous) sharing links; CRITICAL on a sensitive site
  SITE-ORG-LINKS            MEDIUM    the site has at least --org-links organisation-wide links (default 25)
  SITE-ANYONE-SHARING-ON    HIGH      the site's SharingCapability allows anyone links (ExternalUserAndGuestSharing)
  SITE-NO-LABEL             MEDIUM    the site has no sensitivity label
  SITE-NO-OWNER             MEDIUM    the site has no owner in the export, so nobody can attest to its access
  SITE-INACTIVE-BROAD       LOW       no content change for --inactive-days (default 180) and broad reach (an Everyone
                                      grant or organisation or anyone links) without restricted content discovery
  TENANT-DEFAULT-LINK-BROAD HIGH      the default sharing link is Anyone (HIGH) or People in your organisation (MEDIUM)
  TENANT-ANYONE-NO-EXPIRY   MEDIUM    anyone links are allowed tenant-wide and do not expire
  TENANT-NO-LABELS          HIGH      labels.json was exported and holds no label
  TENANT-NO-DLP             HIGH      no enabled DLP policy in enforce mode covers SharePoint or OneDrive
  TENANT-DLP-TEST-ONLY      MEDIUM    DLP policies cover SharePoint or OneDrive only in test mode

A site is sensitive when its label name or its title matches --sensitive-pattern.

Readiness (fixed rubric): every check that could be evaluated for a site or for the tenant counts once; the score is
the share of those that pass, 0 to 100. Rating: "not ready" with any CRITICAL or HIGH finding, "pilot only" with any
MEDIUM finding, otherwise "ready". Buckets: CRITICAL and HIGH are "fix before rollout", MEDIUM "fix before broad
rollout", LOW and INFO "hygiene". The remediation list groups every site finding by the site owner; tenant findings go
to "Tenant administrators".

Output: Markdown (default) or --json to stdout, or to --out; --csv writes the remediation list as CSV. Sharing link
URLs are never printed. --redact replaces e-mail addresses, login names and owner names with stable tokens.

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on (a person needs to act), 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc  # noqa: UP017 (keeps Python 3.10 working)
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
BUCKETS = {"CRITICAL": "fix before rollout", "HIGH": "fix before rollout", "MEDIUM": "fix before broad rollout", "LOW": "hygiene", "INFO": "hygiene"}
DEFAULT_SENSITIVE = r"(?i)(confidential|secret|restricted|highly|finance|payroll|hr|legal|board|m&a)"
# SharePoint SharingCapabilities and SharingLinkType, as ConvertTo-Json writes the enum (number) or as names.
SHARING = {0: "disabled", 1: "externalusersharingonly", 2: "externaluserandguestsharing", 3: "existingexternalusersharingonly"}
LINK_TYPE = {0: "none", 1: "direct", 2: "internal", 3: "anonymousaccess"}
# Claim shapes, described structurally: the tenant-wide "all users" role claim and the "everyone" true claim.
EEEU_RE = re.compile(r"spo-grid-all-users", re.I)
EVERYONE_RE = re.compile(r"^c:0\(\.s\|true$", re.I)
EVERYONE_NAMES = {"everyone", "everyone except external users"}
NULL_GUID = "00000000-0000-0000-0000-000000000000"
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)(client_?secret|password|token|sig)=([^&\s\"']+)"),
]
SPO_PORTAL = "SharePoint admin center > Sites > Active sites > (site)"
CSV_COLUMNS = ["owner", "site", "bucket", "severity", "check", "finding", "action"]


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: invalid JSON: {exc}") from exc


def items(data, where: str) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        data = data["value"]
    elif isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
        raise InputError(f'{where}: expected a JSON object, a list of objects, or {{"value": [...]}}')
    return data


def low(obj: dict) -> dict:
    """Keys lower-cased, so PnP (PascalCase) and Graph (camelCase) exports read the same way."""
    return {str(k).lower(): v for k, v in obj.items()}


def norm_url(url) -> str:
    return str(url or "").strip().rstrip("/").lower()


def parse_dt(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    m = re.match(r"^/Date\((\d+)\)/$", s)  # Windows PowerShell 5 date shape
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s[:-1] + "+00:00" if s.endswith("Z") else s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.year <= 1:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


def level(value, table: dict[int, str]) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return table.get(value, str(value))
    return str(value or "").replace(" ", "").lower()


def as_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip() or default)
    except ValueError:
        return default


def finding(check: str, severity: str, owner: str, site: str, title: str, evidence: str, action: str) -> dict:
    return {
        "check": check,
        "severity": severity,
        "bucket": BUCKETS[severity],
        "owner": owner,
        "site": site,
        "finding": title,
        "evidence": evidence,
        "action": action,
    }


def is_everyone(principal: str) -> str | None:
    p = principal.strip()
    if EEEU_RE.search(p) or p.lower() == "everyone except external users":
        return "Everyone except external users"
    if EVERYONE_RE.match(p) or p.lower() == "everyone":
        return "Everyone"
    return None


def listish(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(value.get("LoginName") or value.get("loginName") or value.get("Title") or value.get("Name") or "")]
    out: list[str] = []
    for v in value:
        out += listish(v)
    return out


class Folder:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.is_dir():
            raise InputError(f"{path}: not a folder")
        self.used: list[str] = []
        self.missing: list[str] = []

    def get(self, name: str, required: bool = False):
        p = self.path / name
        if not p.is_file():
            if required:
                raise InputError(f"{self.path}: required export {name} not found")
            self.missing.append(name)
            return None
        self.used.append(name)
        return load_json(p)

    def rows(self, name: str) -> list[dict] | None:
        p = self.path / name
        if not p.is_file():
            self.missing.append(name)
            return None
        try:
            with p.open(encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
        except (OSError, csv.Error) as exc:
            raise InputError(f"{name}: cannot read CSV: {exc}") from exc
        self.used.append(name)
        return [{str(k).strip().lower(): v for k, v in r.items() if k} for r in rows]


def read_links(folder: Folder) -> dict[str, dict[str, int]] | None:
    """Per site URL: counts of anyone, organization and specific-people links."""
    out: dict[str, dict[str, int]] = {}
    data = folder.get("sharing-links.json")
    rows = folder.rows("sharing-links.csv")
    if data is None and rows is None:
        return None
    for perm in items(data, "sharing-links.json") if data is not None else []:
        p = low(perm)
        site = norm_url(p.get("siteurl"))
        scope = str((p.get("link") or {}).get("scope") or "").lower() if isinstance(p.get("link"), dict) else ""
        if not site or not scope:
            continue
        key = {"anonymous": "anyone", "organization": "organization", "users": "specific"}.get(scope)
        if key:
            out.setdefault(site, {"anyone": 0, "organization": 0, "specific": 0})[key] += 1
    for r in rows or []:
        site = norm_url(r.get("site_url"))
        if not site:
            continue
        c = out.setdefault(site, {"anyone": 0, "organization": 0, "specific": 0})
        c["anyone"] += as_int(r.get("anyone_links"))
        c["organization"] += as_int(r.get("organization_links"))
        c["specific"] += as_int(r.get("specific_people_links"))
    return out


def read_grants(data) -> dict[str, list[str]] | None:
    """Per site URL: 'group: principal' strings for Everyone and Everyone except external users."""
    if data is None:
        return None
    out: dict[str, list[str]] = {}
    for g in items(data, "site-groups.json"):
        g = low(g)
        site = norm_url(g.get("siteurl") or g.get("url"))
        if not site:
            raise InputError("site-groups.json: every row needs SiteUrl")
        out.setdefault(site, [])
        for user in listish(g.get("users")):
            kind = is_everyone(user)
            if kind:
                out[site].append(f"{g.get('title') or 'site group'}: {kind}")
    return out


def dlp_state(policies: list[dict]) -> str:
    """'enforced', 'test' or 'none' for SharePoint and OneDrive coverage."""
    best = "none"
    for pol in policies:
        p = low(pol)
        covers = bool(listish(p.get("sharepointlocation")) or listish(p.get("onedrivelocation"))) or bool(
            re.search(r"sharepoint|onedrive", str(p.get("workload") or ""), re.I)
        )
        if not covers or p.get("enabled") is False:
            continue
        mode = str(p.get("mode") or "Enable").lower()
        if mode == "enable":
            return "enforced"
        if mode.startswith("test"):
            best = "test"
    return best


def evaluate(path: str, args) -> dict:
    folder = Folder(path)
    sites = [low(s) for s in items(folder.get("sites.json", required=True), "sites.json")]
    label_data = folder.get("labels.json")
    labels = (
        None
        if label_data is None
        else {str(low(x).get("id") or ""): str(low(x).get("displayname") or low(x).get("name") or "") for x in items(label_data, "labels.json")}
    )
    grants = read_grants(folder.get("site-groups.json"))
    links = read_links(folder)
    tenant_data = folder.get("tenant.json")
    tenant = low(items(tenant_data, "tenant.json")[0]) if tenant_data else None
    dlp_data = folder.get("dlp-policies.json")
    dlp = items(dlp_data, "dlp-policies.json") if dlp_data is not None else None
    try:
        sensitive = re.compile(args.sensitive_pattern)
    except re.error as exc:
        raise InputError(f"--sensitive-pattern is not a valid regular expression: {exc}") from exc
    now = as_of(args.as_of)
    findings: list[dict] = []
    evaluated = 0
    site_rows = []
    for s in sorted(sites, key=lambda x: norm_url(x.get("url") or x.get("weburl"))):
        url = str(s.get("url") or s.get("weburl") or "").rstrip("/")
        if not url:
            raise InputError("sites.json: every site needs Url (or webUrl)")
        key = norm_url(url)
        title = str(s.get("title") or s.get("displayname") or url)
        owner = str(s.get("owneremail") or s.get("owner") or s.get("ownerloginname") or "").strip()
        label_id = str(s.get("sensitivitylabel") or "").strip().lower()
        label_name = (labels or {}).get(label_id, label_id) if label_id and label_id != NULL_GUID else ""
        is_sensitive = bool(sensitive.search(label_name) or sensitive.search(title))
        who = owner or "No owner recorded"
        here: list[dict] = []
        broad = []
        if grants is not None:
            evaluated += 1
            g = grants.get(key, [])
            if g:
                broad.append("Everyone grant")
                here.append(
                    finding(
                        "SITE-EVERYONE-GRANT",
                        "CRITICAL" if is_sensitive else "HIGH",
                        who,
                        url,
                        "Site is open to everyone in the organisation",
                        "; ".join(sorted(set(g))) + ("; sensitive site" if is_sensitive else ""),
                        f"{SPO_PORTAL} > Membership: replace the Everyone principal with a named group the owner confirms",
                    )
                )
        if links is not None:
            evaluated += 2
            c = links.get(key, {"anyone": 0, "organization": 0, "specific": 0})
            if c["anyone"]:
                broad.append("anyone links")
                here.append(
                    finding(
                        "SITE-ANYONE-LINKS",
                        "CRITICAL" if is_sensitive else "HIGH",
                        who,
                        url,
                        "Files are shared with anyone links",
                        f"{c['anyone']} anyone link(s)" + ("; sensitive site" if is_sensitive else ""),
                        "Site > Manage access > Links: remove anyone links, or reshare with specific people",
                    )
                )
            if c["organization"] >= args.org_links:
                broad.append("organisation links")
                here.append(
                    finding(
                        "SITE-ORG-LINKS",
                        "MEDIUM",
                        who,
                        url,
                        "Many files are shared with organisation-wide links",
                        f"{c['organization']} organisation link(s) (threshold {args.org_links})",
                        "Site > Manage access > Links: replace organisation links with specific people links",
                    )
                )
        if "sharingcapability" in s:
            evaluated += 1
            if level(s.get("sharingcapability"), SHARING) == "externaluserandguestsharing":
                here.append(
                    finding(
                        "SITE-ANYONE-SHARING-ON",
                        "HIGH",
                        who,
                        url,
                        "Site allows anyone links",
                        f"SharingCapability {s.get('sharingcapability')}",
                        f"{SPO_PORTAL} > Settings > External file sharing: New and existing guests or lower",
                    )
                )
        if "sensitivitylabel" in s:
            evaluated += 1
            if not label_name:
                here.append(
                    finding(
                        "SITE-NO-LABEL",
                        "MEDIUM",
                        who,
                        url,
                        "Site has no sensitivity label",
                        "SensitivityLabel empty",
                        f"{SPO_PORTAL} > Settings > Sensitivity: apply the label the owner chooses",
                    )
                )
        evaluated += 1
        if not owner:
            here.append(
                finding(
                    "SITE-NO-OWNER",
                    "MEDIUM",
                    who,
                    url,
                    "Site has no owner in the export",
                    "Owner and OwnerEmail empty",
                    f"{SPO_PORTAL} > Membership > Site admins: name an owner who will review access",
                )
            )
        changed = parse_dt(s.get("lastcontentmodifieddate"))
        if changed is not None and (grants is not None or links is not None):
            evaluated += 1
            idle = (now - changed).days
            if idle > args.inactive_days and broad and s.get("restrictcontentorgwidesearch") is not True:
                here.append(
                    finding(
                        "SITE-INACTIVE-BROAD",
                        "LOW",
                        who,
                        url,
                        "Inactive site that many people can reach",
                        f"no content change for {idle} days; reach: {', '.join(broad)}",
                        f"{SPO_PORTAL}: archive the site, or turn on restricted content discovery for it",
                    )
                )
        findings += here
        site_rows.append(
            {
                "site": url,
                "title": title,
                "owner": who,
                "label": label_name or "-",
                "sensitive": is_sensitive,
                "findings": len(here),
            }
        )
    not_evaluated = []
    if tenant is not None:
        evaluated += 2
        dl = level(tenant.get("defaultsharinglinktype"), LINK_TYPE)
        if dl in ("anonymousaccess", "internal"):
            sev = "HIGH" if dl == "anonymousaccess" else "MEDIUM"
            findings.append(
                finding(
                    "TENANT-DEFAULT-LINK-BROAD",
                    sev,
                    "Tenant administrators",
                    "tenant",
                    "Default sharing link reaches more people than needed",
                    f"DefaultSharingLinkType {tenant.get('defaultsharinglinktype')}",
                    "SharePoint admin center > Policies > Sharing > File and folder links: Specific people",
                )
            )
        expiry = tenant.get("requireanonymouslinksexpireindays")
        if level(tenant.get("sharingcapability"), SHARING) == "externaluserandguestsharing" and as_int(expiry) <= 0:
            findings.append(
                finding(
                    "TENANT-ANYONE-NO-EXPIRY",
                    "MEDIUM",
                    "Tenant administrators",
                    "tenant",
                    "Anyone links are allowed and never expire",
                    f"RequireAnonymousLinksExpireInDays {expiry}",
                    "SharePoint admin center > Policies > Sharing: set an expiry for anyone links",
                )
            )
    else:
        not_evaluated.append("tenant.json not found: default link type and anyone-link expiry were not checked")
    if labels is not None:
        evaluated += 1
        if not labels:
            findings.append(
                finding(
                    "TENANT-NO-LABELS",
                    "HIGH",
                    "Tenant administrators",
                    "tenant",
                    "No sensitivity labels are available",
                    "labels.json holds no label",
                    "Microsoft Purview portal > Information protection > Labels: publish labels for sites and files",
                )
            )
    else:
        not_evaluated.append("labels.json not found: label names are shown as ids and TENANT-NO-LABELS was not checked")
    if dlp is not None:
        evaluated += 1
        state = dlp_state(dlp)
        if state != "enforced":
            findings.append(
                finding(
                    "TENANT-NO-DLP" if state == "none" else "TENANT-DLP-TEST-ONLY",
                    "HIGH" if state == "none" else "MEDIUM",
                    "Tenant administrators",
                    "tenant",
                    "No enforced DLP policy covers SharePoint and OneDrive"
                    if state == "none"
                    else "DLP for SharePoint and OneDrive is in test mode only",
                    f"{len(dlp)} DLP policy(ies) exported; coverage {state}",
                    "Microsoft Purview portal > Data loss prevention > Policies: enforce a policy for SharePoint and OneDrive",
                )
            )
    else:
        not_evaluated.append("dlp-policies.json not found: DLP coverage was not checked")
    if grants is None:
        not_evaluated.append("site-groups.json not found: Everyone and Everyone except external users grants were not checked")
    if links is None:
        not_evaluated.append("sharing-links.json or sharing-links.csv not found: sharing links were not checked")
    findings.sort(key=lambda f: (RANK[f["severity"]], f["owner"].lower(), f["site"].lower(), f["check"]))
    failed = len(findings)
    score = round(100 * (evaluated - failed) / evaluated) if evaluated else 0
    sev = {f["severity"] for f in findings}
    rating = "not ready" if sev & {"CRITICAL", "HIGH"} else "pilot only" if "MEDIUM" in sev else "ready"
    return {
        "tool": "copilot_readiness",
        "as_of": now.strftime("%Y-%m-%d"),
        "inputs": sorted(set(folder.used)),
        "missing_inputs": sorted(set(folder.missing)),
        "not_evaluated": not_evaluated,
        "sites": len(sites),
        "score": max(score, 0),
        "checks_evaluated": evaluated,
        "rating": rating,
        "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        "findings": findings,
        "site_summary": site_rows,
        "note": "Findings come from a point-in-time export. Confirm each remediation with the site owner; the script changed nothing.",
    }


def as_of(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    dt = parse_dt(value + "T00:00:00Z" if "T" not in value else value)
    if dt is None:
        raise InputError(f"--as-of: cannot parse {value!r}; use YYYY-MM-DD")
    return dt


def token(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:8]


def scrub(obj, redact_people: bool, names: set[str]):
    """Secret-shaped strings are always masked; people are tokenised with --redact."""
    ordered = sorted((n for n in names if len(n.strip()) > 2), key=len, reverse=True)

    def _s(s: str) -> str:
        for rx in SECRET_RES:
            s = rx.sub(lambda m: (m.group(1) + "=[redacted]") if m.re.groups == 2 else "[redacted]", s)
        if redact_people:
            s = EMAIL_RE.sub(lambda m: f"user-{token(m.group(0))}@redacted.invalid", s)
            for n in ordered:
                s = re.sub(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", f"person-{token(n)}", s)
        return s

    def walk(o):
        if isinstance(o, str):
            return _s(o)
        if isinstance(o, list):
            return [walk(x) for x in o]
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        return o

    return walk(obj)


def cell(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "'")


def render(rep: dict) -> str:
    lines = [
        "# Copilot oversharing readiness",
        "",
        f"Evaluated as of {rep['as_of']}. Read: {', '.join(rep['inputs'])}.",
        "",
        f"**Readiness: {rep['rating']}, score {rep['score']} of 100** ({rep['checks_evaluated']} checks evaluated across {rep['sites']} sites).",
        "",
        "| Bucket | Findings |",
        "|---|---|",
    ]
    for bucket in ("fix before rollout", "fix before broad rollout", "hygiene"):
        lines.append(f"| {bucket} | {sum(1 for f in rep['findings'] if f['bucket'] == bucket)} |")
    lines += ["", "## Remediation by owner", ""]
    if not rep["findings"]:
        lines.append("No findings at or above the selected severity.")
    owners: dict[str, list[dict]] = {}
    for f in rep["findings"]:
        owners.setdefault(f["owner"], []).append(f)
    for owner in sorted(owners, key=lambda o: (o != "Tenant administrators", o == "No owner recorded", o.lower())):
        lines += [f"### {cell(owner)}", "", "| Bucket | Severity | Check | Site | Finding | Evidence | Action |", "|---|---|---|---|---|---|---|"]
        for f in owners[owner]:
            row = [f["bucket"], f["severity"], f["check"], cell(f["site"]), cell(f["finding"]), cell(f["evidence"]), cell(f["action"])]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
    if rep["not_evaluated"]:
        lines += ["## Not evaluated", ""] + [f"- {cell(s)}" for s in rep["not_evaluated"]] + [""]
    lines.append(rep["note"])
    return "\n".join(lines)


def remediation_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for f in findings:
        w.writerow([f["owner"], f["site"], f["bucket"], f["severity"], f["check"], f["finding"], f["action"]])
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved exports")
    ap.add_argument("--as-of", help="evaluate dates as of this day (YYYY-MM-DD); default today")
    ap.add_argument("--sensitive-pattern", default=DEFAULT_SENSITIVE, help="regular expression for sensitive label names and site titles")
    ap.add_argument("--org-links", type=int, default=25, help="organisation links per site that raise SITE-ORG-LINKS (default 25)")
    ap.add_argument("--inactive-days", type=int, default=180, help="days without content change for SITE-INACTIVE-BROAD (default 180)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="INFO", help="hide findings below this severity (default INFO)")
    ap.add_argument(
        "--fail-on", choices=SEVERITIES + ["NONE"], default="HIGH", help="exit 1 when a finding is at or above this severity (default HIGH)"
    )
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses, login names and owner names with tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    ap.add_argument("--csv", help="also write the remediation list by owner as CSV to this path")
    args = ap.parse_args(argv)
    if args.org_links < 1 or args.inactive_days < 0:
        print("error: --org-links must be at least 1 and --inactive-days at least 0", file=sys.stderr)
        return 2
    try:
        rep = evaluate(args.folder, args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rep["findings"] = [f for f in rep["findings"] if RANK[f["severity"]] <= RANK[args.min_severity]]
    rep["counts"] = {s: sum(1 for f in rep["findings"] if f["severity"] == s) for s in SEVERITIES}
    code = 0 if args.fail_on == "NONE" else int(any(RANK[f["severity"]] <= RANK[args.fail_on] for f in rep["findings"]))
    names = {f["owner"] for f in rep["findings"]} - {"Tenant administrators", "No owner recorded"}
    rep = scrub(rep, args.redact, names if args.redact else set())
    text = json.dumps(rep, indent=2) if args.json else render(rep)
    try:
        if args.csv:
            Path(args.csv).write_text(remediation_csv(rep["findings"]), encoding="utf-8")
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
