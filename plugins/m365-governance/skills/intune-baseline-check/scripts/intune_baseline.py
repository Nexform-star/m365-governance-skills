#!/usr/bin/env python3
"""Evaluate exported Microsoft Intune devices, compliance policies and configuration profiles offline against a baseline.

Input folder (file names the skill tells you to save; optional unless noted):
  managed-devices.json            GET /deviceManagement/managedDevices (required)
  compliance-policies.json        GET /deviceManagement/deviceCompliancePolicies?$expand=assignments
  configuration-profiles.json     GET /deviceManagement/deviceConfigurations?$expand=assignments
  configuration-policies.json     GET beta /deviceManagement/configurationPolicies?$expand=assignments (settings catalog,
                                  assignments only; the settings themselves are not evaluated)
  device-management-settings.json GET /deviceManagement?$select=settings

Checks (id, default severity):
  DEV-NONCOMPLIANT          MEDIUM  device complianceState is noncompliant, error or conflict
  DEV-STALE                 MEDIUM  device has not checked in for stale_device_days (default 30)
  DEV-PERSONAL              MEDIUM  personally owned device enrolled while corporate_only is true
  DEV-UNENCRYPTED           HIGH    device reports isEncrypted false (Windows, macOS, Android)
  DEV-JAILBROKEN            HIGH    device reports jailBroken True
  DEV-OS-BELOW-MIN          MEDIUM  osVersion is below min_os_version for its platform (config)
  POL-UNASSIGNED            MEDIUM  compliance policy with no assignments
  BASE-NO-POLICY            HIGH    a platform with enrolled devices has no assigned compliance policy
  BASE-ENCRYPTION           HIGH    no assigned policy for the platform requires disk encryption (Windows, macOS, Android)
  BASE-MIN-OS               MEDIUM  no assigned policy for the platform sets a minimum OS version
  BASE-PASSWORD             HIGH    no assigned policy for the platform requires a password or PIN
  BASE-JAILBREAK            HIGH    no assigned policy blocks jailbroken or rooted devices (iOS, Android)
  BASE-DEFENDER             MEDIUM  no assigned Windows policy requires Defender, antivirus or a device threat level
  PROF-ALL-DEVICES          LOW     a configuration profile or policy is assigned to All devices or All users with no exclusion
  INTUNE-NOT-SECURE-DEFAULT MEDIUM  devices with no compliance policy are reported as compliant (settings.secureByDefault false)

Per-platform summary: devices, compliant, non-compliant, stale, personal, unencrypted, and assigned compliance policies.

Config (YAML or JSON, optional):
  stale_device_days: 30
  corporate_only: true
  min_os_version: {Windows: "10.0.19045", iOS: "17.0", macOS: "14.0", Android: "13"}
  ignore_platforms: [Linux]

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
"""
from __future__ import annotations

import argparse
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
    redact,
    render_findings,
    render_header,
    sort_findings,
)

CONFIG_KEYS = {"stale_device_days", "corporate_only", "min_os_version", "ignore_platforms"}
POLICY_PLATFORM = {
    "windows10CompliancePolicy": "Windows", "windows81CompliancePolicy": "Windows", "iosCompliancePolicy": "iOS",
    "macOSCompliancePolicy": "macOS", "androidCompliancePolicy": "Android", "androidWorkProfileCompliancePolicy": "Android",
    "androidDeviceOwnerCompliancePolicy": "Android", "aospDeviceOwnerCompliancePolicy": "Android",
}
DEVICE_PLATFORM = {"windows": "Windows", "ios": "iOS", "ipados": "iOS", "macos": "macOS", "android": "Android"}
# Baseline control -> (platforms it applies to, policy fields any of which satisfies it, severity)
CONTROLS = {
    "BASE-ENCRYPTION": ({"Windows", "macOS", "Android"}, ("bitLockerEnabled", "storageRequireEncryption"), "HIGH",
                        "disk encryption required"),
    "BASE-MIN-OS": ({"Windows", "macOS", "Android", "iOS"}, ("osMinimumVersion",), "MEDIUM", "minimum OS version"),
    "BASE-PASSWORD": ({"Windows", "macOS", "Android", "iOS"}, ("passwordRequired", "passcodeRequired"), "HIGH", "password or PIN required"),
    "BASE-JAILBREAK": ({"Android", "iOS"}, ("securityBlockJailbrokenDevices",), "HIGH", "jailbroken or rooted devices blocked"),
    "BASE-DEFENDER": ({"Windows"}, ("defenderEnabled", "antivirusRequired", "deviceThreatProtectionEnabled"), "MEDIUM",
                      "Defender, antivirus or device threat level required"),
}
BAD_STATES = {"noncompliant", "error", "conflict"}
PORTAL_COMPLIANCE = "Intune admin center > Devices > Compliance > Policies"
PORTAL_DEVICES = "Intune admin center > Devices > All devices"
ALL_TARGETS = {"#microsoft.graph.allDevicesAssignmentTarget": "All devices",
               "#microsoft.graph.allLicensedUsersAssignmentTarget": "All users"}
EXCLUDE_TARGET = "#microsoft.graph.exclusionGroupAssignmentTarget"


def platform_of_device(d: dict) -> str:
    os_name = str(d.get("operatingSystem") or "").strip()
    return DEVICE_PLATFORM.get(os_name.lower(), os_name or "Unknown")


def platform_of_policy(p: dict) -> str | None:
    return POLICY_PLATFORM.get(str(p.get("@odata.type", "")).rsplit(".", 1)[-1])


def version_tuple(v) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4])


def satisfied(policy: dict, fields: tuple[str, ...]) -> bool:
    for f in fields:
        v = policy.get(f)
        if v is True or (isinstance(v, str) and v.strip() and f != "deviceThreatProtectionEnabled"):
            return True
    return False


def device_label(d: dict) -> str:
    return f"{d.get('deviceName', '?')} ({d.get('id', '?')})"


def check_devices(devices: list[dict], cfg: dict, now) -> list[dict]:
    out: list[dict] = []
    stale = cfg_int(cfg, "stale_device_days", 30)
    min_os = cfg.get("min_os_version") or {}
    if not isinstance(min_os, dict):
        raise InputError("config min_os_version must be a mapping of platform to version")
    for d in devices:
        plat = platform_of_device(d)
        label = device_label(d)
        user = d.get("userPrincipalName") or "no primary user"
        state = str(d.get("complianceState", "")).lower()
        if state in BAD_STATES:
            out.append(finding("DEV-NONCOMPLIANT", "MEDIUM", label, f"{plat} device is {state}", f"user {user}, last check-in "
                               f"{iso_day(d.get('lastSyncDateTime'))}", PORTAL_DEVICES + " > (device) > Device compliance"))
        age = days_since(d.get("lastSyncDateTime"), now)
        if age is None or age > stale:
            out.append(finding("DEV-STALE", "MEDIUM", label, f"No check-in for more than {stale} days",
                               f"last check-in {iso_day(d.get('lastSyncDateTime'))}, user {user}",
                               PORTAL_DEVICES + " > (device) > Retire or Delete after confirming with the user",
                               f"POST /deviceManagement/managedDevices/{d.get('id')}/retire (review first)"))
        if cfg.get("corporate_only") and str(d.get("managedDeviceOwnerType", "")).lower() == "personal":
            out.append(finding("DEV-PERSONAL", "MEDIUM", label, "Personally owned device in a corporate-only estate",
                               f"managedDeviceOwnerType personal, user {user}",
                               "Intune admin center > Devices > Enrollment > Device platform restrictions (block personal devices)",
                               f"PATCH /deviceManagement/managedDevices/{d.get('id')} {{\"managedDeviceOwnerType\": \"company\"}} "
                               "if the device is in fact company owned"))
        if plat in {"Windows", "macOS", "Android"} and d.get("isEncrypted") is False:
            out.append(finding("DEV-UNENCRYPTED", "HIGH", label, f"{plat} device reports no disk encryption", f"isEncrypted false, user {user}",
                               "Intune admin center > Endpoint security > Disk encryption"))
        if str(d.get("jailBroken", "")).lower() == "true":
            out.append(finding("DEV-JAILBROKEN", "HIGH", label, "Device reports jailbroken or rooted", f"jailBroken True, user {user}",
                               PORTAL_DEVICES + " > (device) > Retire"))
        floor = min_os.get(plat)
        if floor and d.get("osVersion") and version_tuple(d["osVersion"]) < version_tuple(floor):
            out.append(finding("DEV-OS-BELOW-MIN", "MEDIUM", label, f"OS version below {floor}", f"osVersion {d['osVersion']}, user {user}",
                               "Intune admin center > Devices > Windows updates or Apple updates"))
    return out


def assigned(item: dict) -> bool:
    return any(str((a.get("target") or {}).get("@odata.type", "")) != EXCLUDE_TARGET for a in item.get("assignments") or [])


def check_policies(policies: list[dict] | None, platforms: set[str]) -> tuple[list[dict], dict[str, list[str]]]:
    out: list[dict] = []
    per_platform: dict[str, list[str]] = {p: [] for p in platforms}
    if policies is None:
        return out, per_platform
    for p in policies:
        if "assignments" not in p:
            raise InputError("compliance-policies.json has no assignments: export it with $expand=assignments")
    for p in policies:
        name = p.get("displayName", p.get("id", "?"))
        if not assigned(p):
            out.append(finding("POL-UNASSIGNED", "MEDIUM", name, "Compliance policy is not assigned to anyone",
                               f"{p.get('@odata.type', '?')}, id {p.get('id')}", PORTAL_COMPLIANCE + " > (policy) > Assignments",
                               f"POST /deviceManagement/deviceCompliancePolicies/{p.get('id')}/assign (after choosing the groups)"))
    for plat in sorted(platforms):
        live = [p for p in policies if platform_of_policy(p) == plat and assigned(p)]
        per_platform[plat] = [p.get("displayName", "?") for p in live]
        if not live:
            out.append(finding("BASE-NO-POLICY", "HIGH", plat, f"{plat} devices are enrolled but no compliance policy is assigned",
                               "no assigned policy of a matching type", PORTAL_COMPLIANCE + " > Create policy"))
            continue
        for check, (applies, fields, sev, what) in CONTROLS.items():
            if plat in applies and not any(satisfied(p, fields) for p in live):
                out.append(finding(check, sev, plat, f"No assigned {plat} compliance policy has: {what}",
                                   "checked " + ", ".join(sorted(per_platform[plat])) + f" for {', '.join(fields)}",
                                   PORTAL_COMPLIANCE + " > (policy) > Properties > Compliance settings"))
    return out, per_platform


def check_profiles(profiles: list[dict] | None, kind: str) -> list[dict]:
    out: list[dict] = []
    for p in profiles or []:
        if "assignments" not in p:
            raise InputError(f"{kind} has no assignments: export it with $expand=assignments")
        types = [str((a.get("target") or {}).get("@odata.type", "")) for a in p.get("assignments") or []]
        broad = [ALL_TARGETS[t] for t in types if t in ALL_TARGETS]
        if broad and EXCLUDE_TARGET not in types:
            name = p.get("displayName") or p.get("name") or p.get("id", "?")
            out.append(finding("PROF-ALL-DEVICES", "LOW", name, f"Assigned to {', '.join(sorted(set(broad)))} with no exclusion group",
                               f"{kind}, id {p.get('id')}", "Intune admin center > Devices > Configuration > (profile) > Assignments "
                               "(add an exclusion group for break-fix and pilot devices)"))
    return out


def summary(devices: list[dict], cfg: dict, now, per_platform: dict[str, list[str]]) -> list[dict]:
    stale = cfg_int(cfg, "stale_device_days", 30)
    rows: dict[str, dict] = {}
    for d in devices:
        plat = platform_of_device(d)
        r = rows.setdefault(plat, {"platform": plat, "devices": 0, "compliant": 0, "noncompliant": 0, "stale": 0, "personal": 0,
                                   "unencrypted": 0, "policies": per_platform.get(plat, [])})
        r["devices"] += 1
        state = str(d.get("complianceState", "")).lower()
        r["compliant"] += state == "compliant"
        r["noncompliant"] += state in BAD_STATES
        age = days_since(d.get("lastSyncDateTime"), now)
        r["stale"] += age is None or age > stale
        r["personal"] += str(d.get("managedDeviceOwnerType", "")).lower() == "personal"
        r["unencrypted"] += d.get("isEncrypted") is False and plat != "iOS"
    return [rows[k] for k in sorted(rows)]


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    devices = ex.list("managed-devices.json", required=True)
    ignore = {str(p) for p in cfg.get("ignore_platforms") or []}
    devices = [d for d in devices if platform_of_device(d) not in ignore]
    policies = ex.list("compliance-policies.json")
    profiles = ex.list("configuration-profiles.json")
    catalog = ex.list("configuration-policies.json")
    settings = ex.obj("device-management-settings.json")
    platforms = {platform_of_device(d) for d in devices} & set(DEVICE_PLATFORM.values())
    findings = check_devices(devices, cfg, now)
    pol_findings, per_platform = check_policies(policies, platforms)
    findings += pol_findings
    findings += check_profiles(profiles, "configuration-profiles.json")
    findings += check_profiles(catalog, "configuration-policies.json")
    if settings is not None:
        s = settings.get("settings") or settings
        if s.get("secureByDefault") is False:
            findings.append(finding("INTUNE-NOT-SECURE-DEFAULT", "MEDIUM", "tenant", "Devices with no compliance policy count as compliant",
                                    "settings.secureByDefault is false",
                                    "Intune admin center > Devices > Compliance > Compliance settings > Mark devices with no compliance "
                                    "policy assigned as: Not compliant"))
    skipped = []
    if policies is None:
        skipped.append("POL-UNASSIGNED and BASE-*: compliance-policies.json not found")
    rep = {"tool": "intune_baseline", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)),
           "missing_inputs": sorted(set(ex.missing)), "warnings": ex.warnings, "skipped": skipped,
           "platforms": summary(devices, cfg, now, per_platform), "findings": sort_findings(findings),
           "note": "Findings come from exported data at one point in time. Device state changes at each check-in; verify in the "
                   "Intune admin center before acting. The script changed nothing."}
    return rep, ex, {d.get("userDisplayName", "") for d in devices if d.get("userDisplayName")}


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Intune baseline check", ex, now)
    header = "| Platform | Devices | Compliant | Non-compliant | Stale | Personal | Unencrypted | Assigned compliance policies |"
    lines += ["## Platforms", "", header, "|---|---|---|---|---|---|---|---|"]
    lines += [f"| {cell(r['platform'])} | {r['devices']} | {r['compliant']} | {r['noncompliant']} | {r['stale']} | {r['personal']} | "
              f"{r['unencrypted']} | {cell(', '.join(r['policies']) or 'none')} |" for r in rep["platforms"]]
    lines += ["", "| Severity | Findings |", "|---|---|"] + [f"| {s} | {n} |" for s, n in rep["counts"].items()]
    lines += ["", "## Findings", ""] + render_findings(rep["findings"])
    if rep["skipped"]:
        lines += ["", "## Not evaluated", ""] + [f"- {s}" for s in rep["skipped"]]
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
