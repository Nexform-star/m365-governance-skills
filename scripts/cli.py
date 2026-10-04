#!/usr/bin/env python3
"""m365-governance: one command for the m365-governance skill scripts.

    m365-governance <subcommand> [args]       run one skill script with the given arguments
    m365-governance <subcommand> --help       that script's own help
    m365-governance --help                    list the subcommands

Each subcommand runs plugins/m365-governance/skills/<skill>/scripts/<script>.py unchanged, in a child process with
the same Python, stdin, stdout, stderr and exit code. Standard library only. This is the entrypoint of the
container image ghcr.io/basitalisandhu/m365-governance-skills.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

__version__ = "0.1.1"

PROG = "m365-governance"
ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "plugins" / "m365-governance" / "skills"

# subcommand: (skill directory, script, one-line summary)
COMMANDS: dict[str, tuple[str, str, str]] = {
    "preflight": (
        "graph-permission-preflight",
        "permission_preflight.py",
        "Review an app's Graph permissions against what a task needs",
    ),
    "entra-posture": (
        "entra-posture-review",
        "entra_posture.py",
        "Entra ID posture findings from an exported settings folder",
    ),
    "intune-baseline": (
        "intune-baseline-check",
        "intune_baseline.py",
        "Exported Intune devices and policies against a baseline",
    ),
    "groups-sprawl": (
        "teams-and-groups-sprawl",
        "groups_sprawl.py",
        "Microsoft 365 group and Teams sprawl, and a cleanup list",
    ),
    "access-review": (
        "access-review-pack",
        "access_review_pack.py",
        "Quarterly access review checklist and sign-off CSV",
    ),
}


def script_path(name: str) -> Path:
    skill, script, _ = COMMANDS[name]
    return SKILLS / skill / "scripts" / script


def usage() -> str:
    width = max(len(n) for n in COMMANDS)
    lines = [
        f"usage: {PROG} <subcommand> [args]",
        "",
        f"Runs one of the m365-governance skill scripts. Use '{PROG} <subcommand> --help' for its options.",
        "",
        "subcommands:",
    ]
    lines += [f"  {n.ljust(width)}  {h} ({script})" for n, (_, script, h) in COMMANDS.items()]
    lines += ["", "options:", "  -h, --help     show this help and exit", "  --version      show the version and exit"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(usage(), file=sys.stderr)
        return 2
    first, rest = args[0], args[1:]
    if first in ("-h", "--help", "help") and not rest:
        print(usage())
        return 0
    if first == "help":
        first, rest = rest[0], ["--help"]
    if first == "--version":
        print(f"{PROG} {__version__}")
        return 0
    if first not in COMMANDS:
        print(f"{PROG}: unknown subcommand {first!r}\n\n{usage()}", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, str(script_path(first)), *rest])


if __name__ == "__main__":
    sys.exit(main())
