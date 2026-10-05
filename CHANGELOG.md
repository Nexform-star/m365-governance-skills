# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

- Report disabled users that still hold active or eligible directory roles,
  with synthetic fixtures and redaction regression coverage.

## [0.2.1] - 2026-10-04

### Fixed

- Quoted SKILL.md descriptions that contained a colon so the frontmatter parses under strict YAML readers such as the skills CLI; the validator now fails on unquoted scalars with ': ' or ' #'.

## [0.2.0] - 2026-10-04

Four new skills, each with a standard-library script, hand-written fixtures with planted problems, and tests. The plugin now has nine skills.

### Added

- `conditional-access-gap-analysis`: `ca_gaps.py` resolves who each Conditional Access policy applies to (users, transitive group members, active and eligible role holders, guests) and checks 17 conditions: MFA for all users and for admins, legacy authentication blocked, compliant or hybrid-joined device for admins, sign-in and user risk policies, session controls for unmanaged devices, break-glass accounts excluded from every enabled policy, exclusions without a recorded reason, exclusion groups that contain admins, policies in report-only mode beyond a configurable age, include and exclude lists that cancel out, policies that reach no user, duplicate policies, very wide trusted named locations, MFA skipped from trusted locations and disabled policies. Prints a policy by persona coverage matrix.
- `privileged-access-review`: `pim_review.py` reports permanent privileged role assignments (CRITICAL for Global Administrator), eligible assignments never activated, admins with no MFA method or no phishing-resistant method, admin accounts with a mailbox or licences, stale and on-premises synchronised admins, service principals in privileged roles, assignments scoped below the tenant root and roles held by groups, and gives each admin account a hygiene score with one evidence line per deduction.
- `guest-and-external-sharing-review`: `external_sharing.py` reports guests from blocked or not-allowed domains (CRITICAL when also in a sensitive group), guests in sensitive groups, stale guests, invitations not accepted, SharePoint and OneDrive anyone links and their expiry, sharing with no domain restriction, guest resharing, Teams external access open to all domains and chat with personal Teams accounts. Builds a per-guest access map and a draft removal list (`--csv`).
- `license-and-service-plan-audit`: `license_audit.py` reports licences on disabled, never-signed-in and inactive accounts, overlapping SKUs on one user (from the SKUs' service plans, or configured pairs), service plans the organisation has decided not to use, group-based licensing errors and unassigned units, with a reclaim list (`--csv`) and counts per SKU. It holds no prices; totals use only unit costs supplied in the config.
- Dispatcher subcommands `ca-gaps`, `pim-review`, `external-sharing` and `license-audit`, with tests that run each one on its fixtures; the container build check in CI runs their `--help`.
- Six new starter tasks in `docs/good-first-issues.md` for the new skills.

### Changed

- README, plugin README, manifests and image labels list the nine skills; version 0.2.0 in `pyproject.toml`, `plugin.json`, `marketplace.json` and `scripts/cli.py`.

## [0.1.1] - 2026-10-04

The skill scripts are published as a container image on GitHub Packages, using only the workflow's `GITHUB_TOKEN`: `ghcr.io/basitalisandhu/m365-governance-skills`, tagged `0.1.1` and `latest`, for linux/amd64 and linux/arm64, with an SPDX SBOM, a build provenance attestation and a keyless cosign signature. The skills themselves are unchanged.

### Added

- `scripts/cli.py`: a standard-library dispatcher, `m365-governance <subcommand> [args]`, over the skill scripts (`preflight`, `entra-posture`, `intune-baseline`, `groups-sprawl`, `access-review`), with `--help` listing the subcommands and `--version`; tests in `tests/test_cli.py`.
- `Dockerfile`: two stages on a digest-pinned `python:3.12-slim`, only the dispatcher and the skill scripts, no pip dependencies, uid 1000, `WORKDIR /work`, entrypoint `m365-governance`.
- `publish-github-packages.yml`: on a `v*` tag, tests, checks that every version field matches the tag, builds, pushes, attests and signs the image, and creates the GitHub release with the SBOM attached. Pull requests that touch packaging run it as a dry run.
- CI job that builds the image and runs `--help`, every subcommand's `--help` and `--version`, and checks the user and working directory.
- README Install section with the `docker run` usage and the verify commands.

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
