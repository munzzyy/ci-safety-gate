"""Tests for ci_safety_gate.checks -- the argv builders --local runs.

The parity tests in this file are the "don't hardcode a second copy of
the tool list/flags" guard the local runner needs: each one asserts that
every flag checks.py bakes into a command is still literally present in
action.yml's real bash for that step. Rename or drop a flag in one place
without the other and one of these fails.
"""

from __future__ import annotations

import sys

from ci_safety_gate import action_defaults, checks


def test_secrets_argv_flags_match_action_yml():
    argv = checks.secrets_argv("some/path", 2_000_000, ["tests/fixtures/*"])
    assert argv == ["some/path", "--max-bytes", "2000000", "--summary",
                     "--exclude", "tests/fixtures/*"]
    block = action_defaults.step_block("Secrets scan")
    for flag in ("--max-bytes", "--summary", "--exclude"):
        assert flag in block


def test_noslop_code_argv_flags_match_action_yml():
    argv = checks.noslop_code_argv("7")
    assert argv == ["noslop", "--no-config", "--code", "--threshold", "7"]
    block = action_defaults.step_block("noslop")
    for flag in ("--no-config", "--code", "--threshold"):
        assert flag in block


def test_noslop_docs_argv_flags_match_action_yml():
    argv = checks.noslop_docs_argv("")
    assert argv == ["noslop", "--no-config", "--markdown"]
    block = action_defaults.step_block("noslop")
    for flag in ("--no-config", "--markdown"):
        assert flag in block


def test_zizmor_argv_flags_match_action_yml():
    argv = checks.zizmor_argv(".", "high", True)
    assert argv == ["zizmor", "--no-progress", "--color", "never", "--offline",
                     "--min-severity", "high", "."]
    block = action_defaults.step_block("zizmor")
    for flag in ("--no-progress", "--color", "--offline", "--min-severity"):
        assert flag in block


def test_zizmor_argv_omits_offline_when_disabled():
    argv = checks.zizmor_argv(".", "medium", False)
    assert "--offline" not in argv


def test_skillxray_argv_flags_match_action_yml():
    argv = checks.skillxray_argv("/repo", "high")
    assert argv == [sys.executable, "-m", "skillxray", "/repo", "--fail-on", "high", "--no-color"]
    block = action_defaults.step_block("skillxray")
    assert "-m skillxray" in block
    for flag in ("--fail-on", "--no-color"):
        assert flag in block
