"""Tests for ci_safety_gate.action_defaults -- the reader that keeps
--local's tool defaults tied to the real action.yml instead of a second,
hardcoded copy that could drift out from under it."""

from __future__ import annotations

from ci_safety_gate import action_defaults


def test_finds_the_real_action_yml():
    path = action_defaults.find_action_yml()
    assert path.name == "action.yml"
    assert path.is_file()


def test_reads_known_input_defaults():
    # These are the exact values action.yml declares today. If action.yml
    # changes one of them, this test is the tripwire that says so --
    # cli.py's own defaults come from this same function, so a real drift
    # would otherwise only show up as --local quietly using a stale value.
    defaults = action_defaults.input_defaults()
    assert defaults["noslop-version"] == "0.10.0"
    assert defaults["noslop-code-globs"] == "*.py *.js *.jsx *.ts *.tsx *.go *.rs *.sh *.rb"
    assert defaults["noslop-docs-globs"] == "*.md"
    assert defaults["zizmor-min-severity"] == "medium"
    assert defaults["zizmor-offline"] == "true"
    assert defaults["skillxray-ref"] == "v0.1.1"
    assert defaults["skillxray-fail-on"] == "high"
    assert defaults["secrets-max-bytes"] == "2000000"


def test_default_raises_a_clear_error_for_an_unknown_input():
    try:
        action_defaults.default("not-a-real-input")
    except KeyError as exc:
        assert "not-a-real-input" in str(exc)
    else:
        raise AssertionError("expected KeyError for an unknown input name")


def test_step_blocks_cover_every_named_step():
    blocks = action_defaults.step_blocks()
    for name in ("Secrets scan", "noslop", "zizmor", "skillxray", "Evaluate gate"):
        assert name in blocks
        assert blocks[name].strip() != ""
