# Good first issues

Small, well-specified pieces of work for a first contribution. Each is self-contained, has a test to add, and needs no Microsoft 365 tenant, credentials or network access. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: standard library only, tests with every change, scripts never call Microsoft Graph, fixtures use example ids and `example.com` users, plain language without em-dashes. If you change `_graphio.py`, copy it to every skill.

To claim one, open an issue with the title below (or comment on the existing one) and say you are working on it. Run `python3 -m pytest -q`, `python3 -m ruff check .` and `python3 scripts/validate_plugins.py` before opening the pull request.

## 1. entra-posture-review: disabled accounts that still hold roles

**Labels:** good first issue, entra-posture-review, python

**Context.** `users.json` carries `accountEnabled`, and role holders are already resolved in `check_roles()`, but a disabled user who still holds a directory role is not reported.

**Acceptance criteria.**
- New check `ROLE-DISABLED-HOLDER` (LOW): a role holder whose user object has `accountEnabled` false.
- A fixture user that triggers it and an enabled one that must not; tests in `tests/test_entra_posture.py`.
- The docstring, `SKILL.md` and the README coverage section list the check.

## 2. entra-posture-review: Conditional Access policies that target no one

**Labels:** good first issue, entra-posture-review, python

**Context.** A policy whose `includeUsers`, `includeGroups` and `includeRoles` are all empty, or whose only target is `None`, is enabled but does nothing.

**Acceptance criteria.**
- New check `CA-EMPTY-TARGET` (LOW) for enabled policies with no effective include.
- A fixture policy and a test; the docstring lists the check.

## 3. intune-baseline-check: devices with no primary user

**Labels:** good first issue, intune-baseline-check, python

**Context.** Shared or kiosk devices are expected to have no primary user, but on a corporate laptop estate a missing `userPrincipalName` usually means an enrollment problem.

**Acceptance criteria.**
- Config key `require_primary_user: [Windows, macOS]` (default empty); new check `DEV-NO-PRIMARY-USER` (LOW) for devices on those platforms with no `userPrincipalName`.
- A fixture device and a test with and without the config key.

## 4. teams-and-groups-sprawl: owners who are guests

**Labels:** good first issue, teams-and-groups-sprawl, python

**Context.** Owner exports include `userType`. A guest owner can add members and guests to a team, which most tenants do not intend.

**Acceptance criteria.**
- New check `GRP-GUEST-OWNER` (MEDIUM) when any owner is a guest (`userType` Guest or `#EXT#` in the user principal name).
- A fixture group with a guest owner and a test.

## 5. graph-permission-preflight: read the permission list from a consent URL

**Labels:** good first issue, graph-permission-preflight, python

**Context.** Vendors often send an admin consent link instead of a permission list. The link carries `scope=` with space- or `+`-separated delegated permissions (for example `https://graph.microsoft.com/Mail.Read`).

**Acceptance criteria.**
- Optional input `consent-url.txt` holding one URL; delegated permission names are parsed from its `scope` parameter with `urllib.parse` (parsing only, no request) and treated as requested permissions.
- `offline_access`, `openid`, `profile` and `email` are recognised as sign-in scopes.
- A fixture URL and a test.

## 6. access-review-pack: last sign-in of service principals

**Labels:** good first issue, access-review-pack, python

**Context.** Service principal role holders show `n/a` for last sign-in. Graph publishes `GET /reports/servicePrincipalSignInActivities` (beta) with each app's last sign-in.

**Acceptance criteria.**
- Optional input `service-principal-sign-ins.json`; when present, rows for service principals show the latest of the reported sign-in dates.
- The export (command or REST path and the AuditLog.Read.All permission) is added to `SKILL.md`, with a note that it is a beta endpoint.
- A fixture and a test.

## 7. conditional-access-gap-analysis: no policy blocks device code flow

**Labels:** good first issue, conditional-access-gap-analysis, python

**Context.** Conditional Access can block the device code authentication flow (`conditions.authenticationFlows.transferMethods` containing `deviceCodeFlow`, grant Block). Device code phishing is common, and `ca_gaps.py` does not look at authentication flows yet.

**Acceptance criteria.**
- New check `CA-GAP-DEVICE-CODE` (LOW) when no enabled policy for All users blocks `deviceCodeFlow`.
- The `baseline-met` fixture gains such a policy (so it stays clean) and the `gaps` fixture does not; a test in `tests/test_ca_gaps.py`.
- The docstring, `SKILL.md` and the README coverage section list the check.

## 8. conditional-access-gap-analysis: named locations no policy uses

**Labels:** good first issue, conditional-access-gap-analysis, python

**Context.** `named-locations.json` is read only for trusted IP ranges. A named location that no policy includes or excludes is clutter, and a trusted one still affects risk detection.

**Acceptance criteria.**
- New check `CA-LOCATION-UNUSED` (INFO) for a named location whose id appears in no policy's `conditions.locations` (enabled, report-only or disabled).
- A fixture location that triggers it, one that must not, and a test.

## 9. privileged-access-review: write the hygiene score table as CSV

**Labels:** good first issue, privileged-access-review, python

**Context.** The admin hygiene score is printed in Markdown and JSON. Reviewers often want it in a spreadsheet.

**Acceptance criteria.**
- Option `--csv <path>` writes one row per account with columns `account, break_glass, score, roles, methods, evidence` (lists joined with `; `), after `--redact` is applied.
- A test that checks the header, the row count and that redaction applies to the file.
- `SKILL.md` lists the option.

## 10. privileged-access-review: eligible Global Administrator with no end date

**Labels:** good first issue, privileged-access-review, python

**Context.** An eligible assignment with no `endDateTime` never comes up for renewal. For Global Administrator that is usually not intended.

**Acceptance criteria.**
- New check `PIM-ELIGIBLE-NO-EXPIRY` (LOW) for eligible privileged assignments with no `endDateTime`; config key `eligible_no_expiry_roles` (default `[Global Administrator]`).
- A fixture eligibility that triggers it, one with an end date that must not, and a test.

## 11. guest-and-external-sharing-review: disabled guests still in groups

**Labels:** good first issue, guest-and-external-sharing-review, python

**Context.** Disabling a guest is a common first step before removal, but the guest stays in its groups and reappears if re-enabled. `external_sharing.py` already knows `accountEnabled` and group membership.

**Acceptance criteria.**
- New check `GUEST-DISABLED-IN-GROUPS` (LOW) for a guest with `accountEnabled` false that is still a member of at least one group; the evidence lists the groups.
- A fixture guest and a test.

## 12. license-and-service-plan-audit: licences assigned to guests

**Labels:** good first issue, license-and-service-plan-audit, python

**Context.** Guests rarely need a paid licence in the host tenant; a licensed guest is usually a mistake or a leftover from a migration. `users.json` already carries `userType` and `assignedLicenses`.

**Acceptance criteria.**
- New check `LIC-GUEST-LICENSED` (LOW) for a user with `userType` Guest (or `#EXT#` in the user principal name) who holds a licence; the licence is added to the reclaim list with the reason "guest account".
- A fixture guest and a test.
