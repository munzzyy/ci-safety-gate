"""Tests for evaluate_gate.py -- the extracted pass/fail decision that used
to live only as a case statement inside action.yml's "Evaluate gate" step.

The scenario every test file in this module ultimately protects against:
a check's install step breaks (yanked pin, registry outage, network
policy), the check's own scan step gets cascade-skipped as a result, and
the gate must never render that the same as "this check was turned off on
purpose" -- doing so is a silent pass on a check that never ran.
"""

from __future__ import annotations

import evaluate_gate


# ---------------------------------------------------------------------------
# decide_check (secrets, noslop, zizmor share this)
# ---------------------------------------------------------------------------

def test_disabled_check_is_skipped_not_failed():
    r = evaluate_gate.decide_check("noslop", False, "success", "success")
    assert r.status == "skipped"
    assert "disabled" in r.note


def test_disabled_check_ignores_outcomes_entirely():
    # Even if the outcomes look broken, a check the caller turned off must
    # never fail the gate -- "off" wins.
    r = evaluate_gate.decide_check("noslop", False, "failure", "failure")
    assert r.status == "skipped"


def test_enabled_check_with_failed_install_is_fail():
    r = evaluate_gate.decide_check("noslop", True, "failure", "skipped")
    assert r.status == "fail"
    assert "install" in r.note


def test_enabled_check_with_install_skipped_by_upstream_cascade_is_fail():
    # This is the exact shape the original bug produced: the install step's
    # own outcome is "skipped" (not "failure") because an earlier required
    # step failed, which cascade-skips everything after it via the implicit
    # success() on every later `if:`.
    r = evaluate_gate.decide_check("zizmor", True, "skipped", "skipped")
    assert r.status == "fail"
    assert "outcome=skipped" in r.note


def test_enabled_check_clean_install_and_clean_scan_is_pass():
    r = evaluate_gate.decide_check("noslop", True, "success", "success")
    assert r.status == "pass"


def test_enabled_check_clean_install_but_scan_found_issue_is_fail():
    r = evaluate_gate.decide_check("zizmor", True, "success", "failure")
    assert r.status == "fail"
    assert "found an issue" in r.note


def test_check_with_no_install_step_uses_scan_outcome_directly():
    # secrets has no install step -- install_outcome is None, not a string.
    r = evaluate_gate.decide_check("secrets", True, None, "success")
    assert r.status == "pass"
    r = evaluate_gate.decide_check("secrets", True, None, "failure")
    assert r.status == "fail"


def test_enabled_check_with_no_install_step_but_scan_never_ran_is_fail():
    # Defensive/fail-closed: install_outcome=None means "not applicable",
    # not "assume success" -- a scan outcome that's neither success nor
    # failure (e.g. the run was cancelled) must still fail closed.
    r = evaluate_gate.decide_check("secrets", True, None, "cancelled")
    assert r.status == "fail"


# ---------------------------------------------------------------------------
# decide_skillxray (has a second legitimate "off": no SKILL.md found)
# ---------------------------------------------------------------------------

def test_skillxray_disabled_is_skipped():
    r = evaluate_gate.decide_skillxray(False, "", "success", "success")
    assert r.status == "skipped"
    assert "disabled" in r.note


def test_skillxray_enabled_but_no_target_is_skipped_not_failed():
    # Auto-detection found no SKILL.md/skills/.claude -- a legitimate skip,
    # must not be confused with a broken install.
    r = evaluate_gate.decide_skillxray(True, "", "success", "success")
    assert r.status == "skipped"
    assert "no SKILL.md" in r.note


def test_skillxray_enabled_with_target_and_broken_install_is_fail():
    r = evaluate_gate.decide_skillxray(True, "/repo", "failure", "skipped")
    assert r.status == "fail"


def test_skillxray_enabled_with_target_and_clean_run_is_pass():
    r = evaluate_gate.decide_skillxray(True, "/repo", "success", "success")
    assert r.status == "pass"


def test_skillxray_enabled_with_target_and_scan_found_issue_is_fail():
    r = evaluate_gate.decide_skillxray(True, "/repo", "success", "failure")
    assert r.status == "fail"


# ---------------------------------------------------------------------------
# evaluate() -- the whole-gate verdict, matching the task's required matrix
# ---------------------------------------------------------------------------

def _all_clean(**overrides):
    base = dict(
        secrets_enabled=True, secrets_outcome="success",
        noslop_enabled=True, install_noslop_outcome="success", noslop_outcome="success",
        zizmor_enabled=True, install_zizmor_outcome="success", zizmor_outcome="success",
        skillxray_enabled=True, skillxray_target="/repo",
        install_skillxray_outcome="success", skillxray_outcome="success",
    )
    base.update(overrides)
    return base


def test_all_clean_is_overall_pass():
    results, passed = evaluate_gate.evaluate(**_all_clean())
    assert passed is True
    assert all(r.status == "pass" for r in results)


def test_a_broken_install_fails_the_whole_gate():
    # noslop's install broke (network policy / registry outage / bad pin);
    # everything else is genuinely clean. The gate must still fail.
    results, passed = evaluate_gate.evaluate(**_all_clean(
        install_noslop_outcome="skipped", noslop_outcome="skipped",
    ))
    assert passed is False
    noslop = next(r for r in results if r.name == "noslop")
    assert noslop.status == "fail"


def test_a_disabled_check_does_not_block_an_otherwise_clean_pass():
    results, passed = evaluate_gate.evaluate(**_all_clean(
        zizmor_enabled=False, install_zizmor_outcome="skipped", zizmor_outcome="skipped",
    ))
    assert passed is True
    zizmor = next(r for r in results if r.name == "zizmor")
    assert zizmor.status == "skipped"


def test_a_real_scan_finding_fails_the_whole_gate():
    results, passed = evaluate_gate.evaluate(**_all_clean(zizmor_outcome="failure"))
    assert passed is False


def test_reported_vulnerability_scenario_is_no_longer_a_silent_pass():
    # The exact scenario from the bug report: an install step for an
    # ENABLED check breaks, cascading a skip onto every step after it
    # (secrets already ran and was clean; noslop's install is the one that
    # broke; zizmor and skillxray never even got a chance to install).
    # Naive logic that only reads the terminal scan step's outcome sees
    # four "skipped"/"success" results and no "failure" -> PASS. The fixed
    # logic must fail, because noslop was enabled and never actually ran.
    results, passed = evaluate_gate.evaluate(
        secrets_enabled=True, secrets_outcome="success",
        noslop_enabled=True, install_noslop_outcome="failure", noslop_outcome="skipped",
        zizmor_enabled=True, install_zizmor_outcome="skipped", zizmor_outcome="skipped",
        skillxray_enabled=True, skillxray_target="",
        install_skillxray_outcome="skipped", skillxray_outcome="skipped",
    )
    assert passed is False, "an install failure on an enabled check must never silently pass the gate"
    statuses = {r.name: r.status for r in results}
    assert statuses["noslop"] == "fail"


def test_only_skillxray_enabled_and_its_install_breaks_still_fails():
    # The narrowest version of the hole: every other check disabled, only
    # skillxray on, and its install breaks after auto-detection already
    # found real skill content to scan.
    results, passed = evaluate_gate.evaluate(
        secrets_enabled=False, secrets_outcome="skipped",
        noslop_enabled=False, install_noslop_outcome="skipped", noslop_outcome="skipped",
        zizmor_enabled=False, install_zizmor_outcome="skipped", zizmor_outcome="skipped",
        skillxray_enabled=True, skillxray_target="/repo/skills",
        install_skillxray_outcome="failure", skillxray_outcome="skipped",
    )
    assert passed is False


# ---------------------------------------------------------------------------
# render_summary -- the text a maintainer actually reads
# ---------------------------------------------------------------------------

def test_summary_distinguishes_disabled_from_broken_install():
    results, passed = evaluate_gate.evaluate(**_all_clean(
        zizmor_enabled=False, install_zizmor_outcome="skipped", zizmor_outcome="skipped",
        install_noslop_outcome="skipped", noslop_outcome="skipped",
    ))
    text = evaluate_gate.render_summary(results, passed)
    assert "- zizmor: skipped (disabled)" in text
    assert "- noslop: FAIL (install/setup did not complete" in text
    assert "**ci-safety-gate: FAIL**" in text


def test_summary_all_pass_renders_pass_verdict():
    results, passed = evaluate_gate.evaluate(**_all_clean())
    text = evaluate_gate.render_summary(results, passed)
    assert "**ci-safety-gate: PASS**" in text
    assert "FAIL" not in text


def test_summary_notes_a_broken_setup_python_non_fatally():
    results, passed = evaluate_gate.evaluate(**_all_clean())
    text = evaluate_gate.render_summary(results, passed, setup_python_outcome="failure")
    assert "Set up Python did not complete" in text
    # Every check still genuinely ran clean, so this alone must not flip the verdict.
    assert "**ci-safety-gate: PASS**" in text


def test_summary_omits_setup_python_note_when_it_succeeded():
    results, passed = evaluate_gate.evaluate(**_all_clean())
    text = evaluate_gate.render_summary(results, passed, setup_python_outcome="success")
    assert "Set up Python" not in text


# ---------------------------------------------------------------------------
# main() -- the actual entry point action.yml invokes, env-var driven
# ---------------------------------------------------------------------------

_ALL_CLEAN_ENV = {
    "INPUTS_SECRETS": "true", "STEPS_SECRETS_OUTCOME": "success",
    "INPUTS_NOSLOP": "true", "STEPS_INSTALL_NOSLOP_OUTCOME": "success", "STEPS_NOSLOP_OUTCOME": "success",
    "INPUTS_ZIZMOR": "true", "STEPS_INSTALL_ZIZMOR_OUTCOME": "success", "STEPS_ZIZMOR_OUTCOME": "success",
    "INPUTS_SKILLXRAY": "true", "STEPS_SKILLXRAY_DETECT_OUTPUTS_TARGET": "/repo",
    "STEPS_INSTALL_SKILLXRAY_OUTCOME": "success", "STEPS_SKILLXRAY_OUTCOME": "success",
    "STEPS_SETUP_PYTHON_OUTCOME": "success",
}


def _set_env(monkeypatch, overrides=None):
    for k, v in _ALL_CLEAN_ENV.items():
        monkeypatch.setenv(k, v)
    for k, v in (overrides or {}).items():
        monkeypatch.setenv(k, v)


def test_main_all_clean_exits_zero_and_writes_pass(tmp_path, monkeypatch):
    _set_env(monkeypatch)
    summary = tmp_path / "summary.md"
    output = tmp_path / "output.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    code = evaluate_gate.main()

    assert code == 0
    assert output.read_text() == "result=pass\n"
    assert "**ci-safety-gate: PASS**" in summary.read_text()


def test_main_broken_install_exits_one_and_writes_fail(tmp_path, monkeypatch):
    _set_env(monkeypatch, {
        "STEPS_INSTALL_NOSLOP_OUTCOME": "skipped", "STEPS_NOSLOP_OUTCOME": "skipped",
    })
    summary = tmp_path / "summary.md"
    output = tmp_path / "output.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    code = evaluate_gate.main()

    assert code == 1
    assert output.read_text() == "result=fail\n"
    text = summary.read_text()
    assert "**ci-safety-gate: FAIL**" in text
    assert "- noslop: FAIL" in text


def test_main_appends_to_existing_summary_rather_than_overwriting(tmp_path, monkeypatch):
    _set_env(monkeypatch)
    summary = tmp_path / "summary.md"
    summary.write_text("## noslop (AI-slop detection)\n\nclean\n", encoding="utf-8")
    output = tmp_path / "output.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    evaluate_gate.main()

    text = summary.read_text()
    assert text.startswith("## noslop (AI-slop detection)")
    assert "**ci-safety-gate: PASS**" in text
