"""Tests for the frontmatter scalar, description and Limits checks in scripts/validate_plugins.py."""
from __future__ import annotations

import importlib.util
import json

import pytest
from conftest import ROOT

_spec = importlib.util.spec_from_file_location("validator_under_test", ROOT / "scripts" / "validate_plugins.py")
validator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validator)


def doc(*lines: str) -> str:
    return "---\n" + "\n".join(lines) + "\n---\n\nBody: text with a colon is fine.\n"


def test_plain_scalar_with_colon_space_is_rejected():
    problems = validator.scalar_problems(doc("name: x", "description: Draft narratives: strictly from the map"))
    assert len(problems) == 1
    assert "line 3" in problems[0] and "'description'" in problems[0]


@pytest.mark.parametrize("line", [
    "description: Use for C # code",
    "description: Ends with:",
    "description: *starts with an alias",
    "description: @mention first",
    'description: "never closed',
    "description: 'never closed",
    'description: "ends with an escaped quote\\"',
])
def test_other_defects_are_rejected(line):
    assert len(validator.scalar_problems(doc(line))) == 1


def test_nested_metadata_values_are_checked():
    problems = validator.scalar_problems(doc("name: x", "metadata:", "  note: has: a colon"))
    assert len(problems) == 1 and "line 4" in problems[0]


@pytest.mark.parametrize("line", [
    'description: "Quoted: with a colon # and a hash"',
    "description: 'Single: quoted'",
    "description: Plain text, a URL https://example.com/a:b and a#b",
    "description: C:\\path\\to",
    "description: >-",
    "allowed-tools: [Read, Grep]",
    "name: plain-name",
])
def test_accepted_forms(line):
    assert validator.scalar_problems(doc(line)) == []


def test_block_scalar_content_is_not_checked():
    assert validator.scalar_problems(doc("description: |", "  Text: with a colon", "name: x")) == []


def test_text_without_frontmatter_is_ignored():
    assert validator.scalar_problems("description: a: b\n") == []


def test_every_skill_md_in_this_repository_parses_cleanly():
    skills = sorted(ROOT.glob("plugins/*/skills/*/SKILL.md"))
    assert skills
    for path in skills:
        assert validator.scalar_problems(path.read_text(encoding="utf-8")) == [], str(path.relative_to(ROOT))


def quoted(desc: str) -> str:
    return "---\nname: x\ndescription: " + json.dumps(desc) + "\n---\n\nBody.\n"


GOOD = "Check a thing for a reason. Use when asked \"is this fine?\". Not for other things."


def test_good_description_passes():
    assert validator.description_problems(quoted(GOOD)) == []


def test_description_over_600_chars_is_rejected():
    problems = validator.description_problems(quoted(GOOD + " " + "x" * 600))
    assert len(problems) == 1 and "house limit 600" in problems[0]


def test_description_without_use_or_not_for_is_rejected():
    assert len(validator.description_problems(quoted("Check a thing. Not for other things."))) == 1
    assert len(validator.description_problems(quoted("Check a thing. Use when asked."))) == 1


@pytest.mark.parametrize("line", [
    "description: Check a thing. Use when asked. Not for other things.",
    "description: 'Check a thing. Use when asked. Not for other things.'",
    "description: >-",
])
def test_description_must_be_double_quoted(line):
    problems = validator.description_problems("---\nname: x\n" + line + "\n---\n")
    assert problems == ["description must be a single double-quoted line"]


def test_limits_section_is_detected():
    assert validator.has_limits_section("# T\n\n## Limits\n\n- one\n")
    assert not validator.has_limits_section("# T\n\n## Limitations\n\n- one\n")
    assert not validator.has_limits_section("# T\n\nSee ## Limits inline\n")


def test_every_skill_md_in_this_repository_meets_the_description_and_limits_rules():
    skills = sorted(ROOT.glob("plugins/*/skills/*/SKILL.md"))
    assert skills
    for path in skills:
        text = path.read_text(encoding="utf-8")
        assert validator.description_problems(text) == [], str(path.relative_to(ROOT))
        assert validator.has_limits_section(text), str(path.relative_to(ROOT))
