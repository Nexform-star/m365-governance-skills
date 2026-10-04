# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.1.0] - 2026-10-04

### Added

- Plugin marketplace `m365-governance-skills` with one plugin, `m365-governance`.
- `graph-permission-preflight`: `permission_preflight.py` compares an app's requested permissions, delegated grants and application permission assignments (or a connector's declared list) with a needs manifest; reports high-risk permissions, write where read suffices, application where delegated is enough, unused and `.All`-where-scoped permissions, consent types, and a least-privilege replacement set.
- `entra-posture-review`: `entra_posture.py`, 23 offline checks across Conditional Access, security defaults, Global Administrators and PIM, guests, app credentials, service principals with high-risk Graph application permissions, user consent and guest invitation settings, and legacy sign-ins.
- `intune-baseline-check`: `intune_baseline.py`, 15 offline checks across managed devices, compliance policy controls per platform, unassigned policies, profiles assigned to All devices or All users without exclusions, and the "no policy means compliant" setting, with a per-platform summary.
- `teams-and-groups-sprawl`: `groups_sprawl.py` (ownerless and single-owner groups, guests, public and inactive teams, empty groups, naming convention, expiration) and a draft cleanup list with proposed owners from member managers.
- `access-review-pack`: `access_review_pack.py` builds a Markdown reviewer checklist and a sign-off CSV (role holders, app owners, sensitive group owners, guests per group, expiring credentials).
- `--redact` and `--json` on every script; shared `_graphio.py` and `_miniyaml.py` helpers copied into each skill.
- Offline pytest suite with hand-written fixtures, `scripts/validate_plugins.py`, ruff configuration, and a CI workflow with read-only permissions.
