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


def test_secrets_argv_appends_fail_on_skip_and_matches_action_yml():
    argv = checks.secrets_argv("some/path", 2_000_000, [], fail_on_skip=True)
    assert argv == ["some/path", "--max-bytes", "2000000", "--summary", "--fail-on-skip"]
    block = action_defaults.step_block("Secrets scan")
    assert "--fail-on-skip" in block


def test_secrets_argv_omits_fail_on_skip_by_default():
    argv = checks.secrets_argv("some/path", 2_000_000, [])
    assert "--fail-on-skip" not in argv


def test_secrets_argv_appends_annotations_and_matches_action_yml():
    argv = checks.secrets_argv("some/path", 2_000_000, [], annotations=True)
    assert argv == ["some/path", "--max-bytes", "2000000", "--summary", "--github-annotations"]
    block = action_defaults.step_block("Secrets scan")
    assert "--github-annotations" in block


def test_secrets_argv_omits_annotations_by_default():
    assert "--github-annotations" not in checks.secrets_argv("some/path", 2_000_000, [])


def test_zizmor_argv_flags_match_action_yml():
    argv = checks.zizmor_argv(".", "high", True, "auditor")
    assert argv == ["zizmor", "--no-progress", "--color", "never", "--offline",
                     "--persona", "auditor", "--min-severity", "high", "."]
    block = action_defaults.step_block("zizmor")
    for flag in ("--no-progress", "--color", "--offline", "--persona", "--min-severity"):
        assert flag in block


def test_zizmor_argv_omits_offline_when_disabled():
    argv = checks.zizmor_argv(".", "medium", False)
    assert "--offline" not in argv


def test_zizmor_argv_defaults_to_the_auditor_persona():
    # Not cosmetic: audits like secrets-outside-env only fire under
    # auditor, so a regular run reports a pass with a class of findings
    # never evaluated.
    argv = checks.zizmor_argv(".", "medium", True)
    assert argv[argv.index("--persona") + 1] == "auditor"
    assert action_defaults.default("zizmor-persona") == "auditor"


def test_zizmor_pip_spec_matches_the_action_yml_install_step():
    # The local --install-missing path used to install a bare, unpinned
    # zizmor while the action installed a floored one, so a pin added to
    # action.yml never reached it.
    version = action_defaults.default("zizmor-version")
    assert checks.zizmor_pip_spec(version) == f"zizmor{version}"
    block = action_defaults.step_block("Install zizmor")
    assert '"zizmor${INPUTS_ZIZMOR_VERSION}"' in block


def test_zizmor_version_floor_excludes_the_credential_leaking_release():
    # zizmor 1.27.0 shipped GHSA-f42p-wjw5-97qh (debug logging printed
    # available GitHub credentials in cleartext) and was yanked; 1.28.0 is
    # the fix. An unpinned install can still resolve 1.27.0 from a mirror.
    assert action_defaults.default("zizmor-version") == ">=1.28.0"


def test_skillxray_ref_is_pinned_to_a_commit_sha_not_a_movable_tag():
    ref = action_defaults.default("skillxray-ref")
    assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), (
        "skillxray-ref must be a full commit SHA: a git tag can be moved, "
        "which silently changes what every consumer installs"
    )


def test_skillxray_argv_flags_match_action_yml():
    argv = checks.skillxray_argv("/repo", "high")
    assert argv == [sys.executable, "-m", "skillxray", "/repo", "--fail-on", "high", "--no-color"]
    block = action_defaults.step_block("skillxray")
    assert "-m skillxray" in block
    for flag in ("--fail-on", "--no-color"):
        assert flag in block
