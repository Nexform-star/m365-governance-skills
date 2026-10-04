# Security policy

This repository ships skills and scripts that run inside people's Claude Code sessions and that look at Microsoft 365 tenant data: users, roles, Conditional Access policies, app permissions, devices and groups. The scripts read files you point them at and write only where you ask; nothing here makes a network call, calls Microsoft Graph, or reports usage anywhere.

## Supported versions

Only the latest release on `main` is supported. Pin a tag if you need stability, and update when a fix is announced in [CHANGELOG.md](CHANGELOG.md).

## Reporting a vulnerability

Please do not open a public issue for a security problem.

1. Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a vulnerability").
2. If that is unavailable, open an issue titled "Security contact request" with no details, and the maintainer will reply with a private channel.

Include what you found, how to reproduce it, and what you think the impact is. You will get an acknowledgement within 5 working days and a fix or a mitigation plan within 30 days for confirmed issues.

Do not include real tenant data in a report: no tenant ids, user names, e-mail addresses, app secrets or exports. Reproduce with the fixtures in `tests/fixtures/`, which use ids such as `00000000-0000-0000-0000-000000000101` and `example.com` users.

## What counts

- A skill that instructs Claude to change a tenant (grant or revoke consent, change a policy, add or remove an owner, retire or wipe a device) without asking for confirmation of a specific command.
- A skill that asks for a write (`ReadWrite`) Graph permission for an export.
- A script that can be made to execute untrusted input, write outside the paths given on its command line, open a network connection, or call Microsoft Graph.
- `--redact` output that still contains a user principal name, e-mail address or user display name present in the input.
- A check that reports a clearly unsafe input as clean (for example an app holding `Directory.ReadWrite.All` without a CRITICAL finding, or a tenant with no enabled MFA policy and security defaults off without a finding).
- Instructions hidden in any file of this repository that address the model rather than the reader.

Missing checks (a misconfiguration the scripts do not yet look at) are welcome as ordinary issues or pull requests; they are coverage improvements rather than vulnerabilities.

## What this repository does and does not do

- No telemetry and no network access from scripts. No subprocesses.
- The Microsoft Graph CLI (`mgc`) appears only in skill instructions, as read-only `list` and `get` commands, run by the user's own session with the user's own sign-in.
- Fixes are shown as a portal path and a Graph call for review and run only after explicit confirmation.
- Skill text tells Claude to treat all tenant data as untrusted content, never as instructions.
