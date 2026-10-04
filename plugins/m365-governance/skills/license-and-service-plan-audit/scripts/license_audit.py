#!/usr/bin/env python3
"""Audit Microsoft 365 licence assignments from exported Graph data and build a reclaim list with estimated counts.

Input folder (file names the skill tells you to save; optional unless noted):
  subscribed-skus.json   GET /subscribedSkus (required)
  users.json             GET /users?$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,
                             assignedLicenses,licenseAssignmentStates,signInActivity (required)
  groups.json            GET /groups?$select=id,displayName (only to name groups in licensing errors)

Checks (id, default severity):
  LIC-DISABLED-ACCOUNT  MEDIUM  a disabled account still holds licences
  LIC-NEVER-SIGNED-IN   LOW     an enabled, licensed account created more than never_signed_in_grace_days (default 30)
                                ago has never signed in
  LIC-INACTIVE          LOW     an enabled, licensed account has not signed in for inactive_days (default 90)
  LIC-OVERLAP           MEDIUM  one user holds two SKUs where at least overlap_ratio (default 0.8) of one SKU's service
                                plans are also in the other, or a pair listed in overlapping_skus
  LIC-UNWANTED-PLAN     LOW     a service plan listed in unwanted_service_plans is enabled for users (one finding per plan)
  LIC-GROUP-ERROR       MEDIUM  group-based licensing failed for users (state Error or ActiveWithError; one finding per
                                group and SKU)
  LIC-SKU-SPARE         INFO    a SKU has purchased units that are not assigned

The reclaim list holds one row per user and SKU that a check above makes reclaimable (disabled, never signed in,
inactive, or the smaller SKU of an overlapping pair), with how the licence is assigned (direct or the group). Counts per
SKU are estimates from the export. The script holds no prices: totals appear only when the config supplies unit_costs,
and are that unit cost multiplied by the count, in the currency and period the config states.

Config (YAML or JSON, optional):
  inactive_days: 90
  never_signed_in_grace_days: 30
  overlap_ratio: 0.8
  overlapping_skus: [[SPE_E5, ENTERPRISEPACK]]     [larger SKU, smaller SKU] pairs that always count as overlap
  unwanted_service_plans: [YAMMER_ENTERPRISE]      service plan names the organisation has decided not to use
  unit_costs: {SPE_E5: 0.0}                        your own unit cost per skuPartNumber, for totals
  cost_label: "AUD per month"                      printed next to totals

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
Nothing is changed in the tenant: fix guidance is printed for review and never run.
"""
from __future__ import annotations

import argparse
import csv
import io
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

CONFIG_KEYS = {"inactive_days", "never_signed_in_grace_days", "overlap_ratio", "overlapping_skus", "unwanted_service_plans",
               "unit_costs", "cost_label"}
LIC_PORTAL = "Microsoft 365 admin center > Billing > Licenses"
USER_PORTAL = "Microsoft 365 admin center > Users > Active users > (user) > Licenses and apps"
CSV_COLUMNS = ["user", "sku", "reasons", "assigned_by", "last_sign_in", "decision"]


def last_sign_in(u: dict):
    sia = u.get("signInActivity") or {}
    dates = [d for d in (parse_dt(sia.get("lastSignInDateTime")), parse_dt(sia.get("lastNonInteractiveSignInDateTime"))) if d]
    return max(dates) if dates else None


def cfg_number(cfg: dict, key: str, default: float) -> float:
    value = cfg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise InputError(f"config {key} must be a non-negative number")
    return float(value)


class Skus:
    def __init__(self, skus: list[dict]):
        self.name = {s.get("skuId"): s.get("skuPartNumber") or s.get("skuId") for s in skus}
        self.plans = {s.get("skuId"): {p.get("servicePlanId"): p.get("servicePlanName") for p in s.get("servicePlans") or []
                                       if p.get("appliesTo", "User") == "User"} for s in skus}
        self.skus = skus

    def overlap(self, big: str, small: str, ratio: float, pairs: set[tuple[str, str]]) -> str | None:
        """Evidence when `small` is (mostly) contained in `big`, else None."""
        if (self.name.get(big), self.name.get(small)) in pairs:
            return f"{self.name.get(small)} is listed under overlapping_skus with {self.name.get(big)}"
        small_plans = set(self.plans.get(small, {}).values())
        big_plans = set(self.plans.get(big, {}).values())
        if not small_plans or len(big_plans) < len(small_plans):
            return None
        shared = small_plans & big_plans
        if len(shared) / len(small_plans) >= ratio:
            return f"{len(shared)} of {len(small_plans)} service plans of {self.name.get(small)} are also in {self.name.get(big)}"
        return None


def evaluate(folder: str, cfg: dict, now) -> tuple[dict, Export, set[str]]:
    ex = Export(folder)
    sku_list = ex.list("subscribed-skus.json", required=True)
    users = ex.list("users.json", required=True)
    groups = ex.list("groups.json")
    inactive_days = cfg_int(cfg, "inactive_days", 90)
    grace = cfg_int(cfg, "never_signed_in_grace_days", 30)
    ratio = cfg_number(cfg, "overlap_ratio", 0.8)
    pairs = cfg.get("overlapping_skus") or []
    if not isinstance(pairs, list) or not all(isinstance(p, list) and len(p) == 2 for p in pairs):
        raise InputError("config overlapping_skus must be a list of [larger SKU, smaller SKU] pairs")
    pairs = {(str(a), str(b)) for a, b in pairs}
    unwanted = {str(p) for p in cfg.get("unwanted_service_plans") or []}
    costs = cfg.get("unit_costs") or {}
    if not isinstance(costs, dict) or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in costs.values()):
        raise InputError("config unit_costs must map skuPartNumber to a number")
    s = Skus(sku_list)
    group_names = {g.get("id"): g.get("displayName", g.get("id")) for g in groups or []}
    findings: list[dict] = []
    reclaim: list[dict] = []
    plan_users: dict[str, set[str]] = {}
    plan_skus: dict[str, set[str]] = {}
    group_errors: dict[tuple[str, str], dict] = {}
    licensed = 0
    for u in users:
        who = u.get("userPrincipalName") or u.get("displayName") or u.get("id", "?")
        lics = u.get("assignedLicenses") or []
        states = u.get("licenseAssignmentStates") or []
        for st in states:
            if st.get("assignedByGroup") and st.get("state") in ("Error", "ActiveWithError"):
                key = (st["assignedByGroup"], st.get("skuId", ""))
                e = group_errors.setdefault(key, {"users": [], "errors": set()})
                e["users"].append(who)
                e["errors"].add(st.get("error") or "unknown")
        if not lics:
            continue
        licensed += 1
        sku_ids = [x.get("skuId") for x in lics]
        names = [s.name.get(x, x) for x in sku_ids]
        by_group = {st.get("skuId"): group_names.get(st["assignedByGroup"], st["assignedByGroup"])
                    for st in states if st.get("assignedByGroup")}
        reasons: dict[str, list[str]] = {}
        last = last_sign_in(u)
        has_activity = "signInActivity" in u
        if u.get("accountEnabled") is False:
            findings.append(finding("LIC-DISABLED-ACCOUNT", "MEDIUM", who, "Disabled account holds licences", f"licences: {', '.join(names)}"
                                    + (f"; last sign-in {iso_day(last)}" if has_activity else ""),
                                    f"{USER_PORTAL}. Remove the licences (or the account from the licensing group) once mailbox and "
                                    "OneDrive retention are settled"))
            for x in sku_ids:
                reasons.setdefault(x, []).append("account disabled")
        elif has_activity and last is None and (days_since(u.get("createdDateTime"), now) or 0) > grace:
            findings.append(finding("LIC-NEVER-SIGNED-IN", "LOW", who, "Licensed account has never signed in",
                                    f"created {iso_day(u.get('createdDateTime'))}; licences: {', '.join(names)}",
                                    f"{USER_PORTAL}. Confirm the account is needed"))
            for x in sku_ids:
                reasons.setdefault(x, []).append("never signed in")
        elif has_activity and last is not None and (now - last).days > inactive_days:
            findings.append(finding("LIC-INACTIVE", "LOW", who, f"No sign-in for {(now - last).days} days",
                                    f"last sign-in {iso_day(last)}; licences: {', '.join(names)}", f"{USER_PORTAL}. Confirm with the manager"))
            for x in sku_ids:
                reasons.setdefault(x, []).append(f"no sign-in for more than {inactive_days} days")
        for big in sku_ids:
            for small in sku_ids:
                if big == small:
                    continue
                ev = s.overlap(big, small, ratio, pairs)
                if ev and not (s.overlap(small, big, ratio, pairs) and big > small):
                    findings.append(finding("LIC-OVERLAP", "MEDIUM", who, f"{s.name.get(small)} overlaps {s.name.get(big)}", ev,
                                            f"{USER_PORTAL}. Remove {s.name.get(small)} after checking no service plan in it is "
                                            "needed on its own"))
                    reasons.setdefault(small, []).append(f"overlaps {s.name.get(big)}")
        for lic in lics:
            disabled = set(lic.get("disabledPlans") or [])
            for pid, pname in s.plans.get(lic.get("skuId"), {}).items():
                if pname in unwanted and pid not in disabled:
                    plan_users.setdefault(pname, set()).add(who)
                    plan_skus.setdefault(pname, set()).add(s.name.get(lic.get("skuId"), "?"))
        for x, why in reasons.items():
            reclaim.append({"user": who, "sku": s.name.get(x, x), "reasons": why, "assigned_by": by_group.get(x, "direct"),
                            "last_sign_in": iso_day(last) if has_activity else "not exported"})
    for pname in sorted(plan_users):
        findings.append(finding("LIC-UNWANTED-PLAN", "LOW", pname, "Service plan the organisation does not use is enabled",
                                f"enabled for {len(plan_users[pname])} user(s) through {', '.join(sorted(plan_skus[pname]))}",
                                f"{LIC_PORTAL} > (product) > (group or user): clear the service plan, preferably on the licensing group"))
    for (gid, sku), e in sorted(group_errors.items()):
        findings.append(finding("LIC-GROUP-ERROR", "MEDIUM", group_names.get(gid, gid), f"Group-based licensing errors for {s.name.get(sku, sku)}",
                                f"{len(e['users'])} user(s), errors: {', '.join(sorted(e['errors']))}",
                                "Entra admin center > Groups > (group) > Licenses: fix the error (buy units, resolve the conflicting "
                                "licence, or set the usage location), then reprocess"))
    per_sku = []
    for sku in s.skus:
        name = s.name.get(sku.get("skuId"))
        enabled = (sku.get("prepaidUnits") or {}).get("enabled") or 0
        consumed = sku.get("consumedUnits") or 0
        spare = max(0, enabled - consumed)
        if spare:
            findings.append(finding("LIC-SKU-SPARE", "INFO", name, f"{spare} purchased unit(s) not assigned",
                                    f"{consumed} of {enabled} units assigned", f"{LIC_PORTAL}. Reduce the subscription at renewal "
                                    "or assign the units"))
        rows = sorted({r["user"] for r in reclaim if r["sku"] == name})
        entry = {"sku": name, "purchased": enabled, "assigned": consumed, "spare": spare, "reclaimable": len(rows)}
        if name in costs:
            entry["unit_cost"] = costs[name]
            entry["estimated_total"] = round(costs[name] * (len(rows) + spare), 2)
        per_sku.append(entry)
    reclaim.sort(key=lambda r: (r["sku"], r["user"].lower()))
    not_evaluated = []
    if not any("signInActivity" in u for u in users):
        not_evaluated.append("LIC-NEVER-SIGNED-IN and LIC-INACTIVE: users.json has no signInActivity (needs AuditLog.Read.All and "
                             "Entra ID P1)")
    if not unwanted:
        not_evaluated.append("LIC-UNWANTED-PLAN: no unwanted_service_plans in the config")
    rep = {"tool": "license_audit", "as_of": now.strftime("%Y-%m-%d"), "inputs": sorted(set(ex.used)), "missing_inputs": sorted(set(ex.missing)),
           "warnings": ex.warnings, "not_evaluated": not_evaluated, "licensed_users": licensed, "findings": sort_findings(findings),
           "per_sku": per_sku, "reclaim": reclaim, "cost_label": str(cfg.get("cost_label") or ""),
           "note": "Counts are estimates from exported data. Totals appear only for unit costs supplied in the config; the script "
                   "holds no prices. Confirm each reclaim line (retention, shared use, upcoming starters) before removing a licence; "
                   "the script changed nothing."}
    return rep, ex, person_names(users)


def reclaim_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([r["user"], r["sku"], "; ".join(r["reasons"]), r["assigned_by"], r["last_sign_in"], ""])
    return buf.getvalue()


def render(rep: dict, ex: Export, now) -> str:
    lines = render_header("Licence and service plan audit", ex, now)
    lines += [f"Licensed users in the export: {rep['licensed_users']}.", "", "| Severity | Findings |", "|---|---|"]
    lines += [f"| {s} | {n} |" for s, n in rep["counts"].items()] + [""]
    lines += ["## Findings", ""] + render_findings(rep["findings"])
    label = f" ({cell(rep['cost_label'])})" if rep["cost_label"] else ""
    lines += ["", "## Per SKU (estimates)", "", f"| SKU | Purchased | Assigned | Spare | Reclaimable | Unit cost{label} | Spare plus reclaimable "
              f"x unit cost{label} |", "|---|---|---|---|---|---|---|"]
    for e in rep["per_sku"]:
        lines.append(f"| {cell(e['sku'])} | {e['purchased']} | {e['assigned']} | {e['spare']} | {e['reclaimable']} | "
                     f"{e.get('unit_cost', 'not supplied')} | {e.get('estimated_total', '-')} |")
    lines += ["", "## Reclaim list (draft)", ""]
    if rep["reclaim"]:
        lines += ["| User | SKU | Reasons | Assigned by | Last sign-in |", "|---|---|---|---|---|"]
        for r in rep["reclaim"]:
            lines.append(f"| {cell(r['user'])} | {cell(r['sku'])} | {cell('; '.join(r['reasons']))} | {cell(r['assigned_by'])} | "
                         f"{r['last_sign_in']} |")
    else:
        lines.append("Nothing to reclaim.")
    if rep["not_evaluated"]:
        lines += ["", "## Not fully evaluated", ""] + [f"- {cell(s)}" for s in rep["not_evaluated"]]
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved Graph JSON exports")
    ap.add_argument("--csv", help="also write the reclaim list as CSV to this path")
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
            Path(args.csv).write_text(reclaim_csv(rep["reclaim"]), encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.csv}: {exc}", file=sys.stderr)
            return 2
    print(dumps(rep) if args.json else render(rep, ex, now))
    return code


if __name__ == "__main__":
    sys.exit(main())
