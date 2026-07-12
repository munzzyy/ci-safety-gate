#!/usr/bin/env python3
"""Decide ci-safety-gate's combined pass/fail verdict.

Standard library only, same as scan_secrets.py. Reads each check's
enablement and its steps' outcomes from the environment and renders the
"## Result" step-summary section plus the `result` action output.

This needs its own logic rather than a bare case statement because a GitHub
Actions step's `outcome` reads "skipped" in two completely different
situations: a check that was turned off on purpose, and a check whose
install step (or an earlier required step) failed and cascaded a skip onto
it. Those must never render the same way -- "off" is fine, "was supposed to
run and didn't" is a FAIL, full stop. Conflating them is exactly the
"flips the combined verdict to pass" scenario SECURITY.md calls a
vulnerability in this action.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # "pass" | "fail" | "skipped"
    note: str  # human-readable reason, shown next to skipped/fail in the summary


def decide_check(name: str, enabled: bool, install_outcome: str | None, scan_outcome: str) -> CheckResult:
    """Decide one check's verdict.

    `install_outcome` is the outcome of that check's install step, or None
    for a check with no separate install step (secrets, which is stdlib
    Python and needs nothing installed).
    """
    if not enabled:
        return CheckResult(name, "skipped", "disabled")
    if install_outcome is not None and install_outcome != "success":
        return CheckResult(
            name, "fail",
            f"install/setup did not complete (outcome={install_outcome}) -- check did not run",
        )
    if scan_outcome == "success":
        return CheckResult(name, "pass", "pass")
    if scan_outcome == "failure":
        return CheckResult(name, "fail", "found an issue")
    # Enabled, install fine (or not needed), yet the scan step itself never
    # produced a real verdict -- e.g. the run was cancelled mid-flight, or
    # something upstream broke in a way this function wasn't told about.
    # Fail closed: an enabled check with no real outcome is not a pass.
    return CheckResult(name, "fail", f"did not complete (outcome={scan_outcome!r})")


def decide_skillxray(enabled: bool, target: str, install_outcome: str, scan_outcome: str) -> CheckResult:
    """skillxray has a second, legitimate way to be "off": auto-detection
    found no SKILL.md / skills/ / .claude to scan. That must stay a clean
    skip -- the check isn't broken, there's just nothing to check."""
    if not enabled:
        return CheckResult("skillxray", "skipped", "disabled")
    if not target:
        return CheckResult("skillxray", "skipped", "no SKILL.md/skills/.claude found")
    return decide_check("skillxray", True, install_outcome, scan_outcome)


def evaluate(
    *,
    secrets_enabled: bool,
    secrets_outcome: str,
    noslop_enabled: bool,
    install_noslop_outcome: str,
    noslop_outcome: str,
    zizmor_enabled: bool,
    install_zizmor_outcome: str,
    zizmor_outcome: str,
    skillxray_enabled: bool,
    skillxray_target: str,
    install_skillxray_outcome: str,
    skillxray_outcome: str,
) -> tuple[list[CheckResult], bool]:
    """Return (per-check results, overall passed) for the whole gate."""
    results = [
        decide_check("secrets", secrets_enabled, None, secrets_outcome),
        decide_check("noslop", noslop_enabled, install_noslop_outcome, noslop_outcome),
        decide_check("zizmor", zizmor_enabled, install_zizmor_outcome, zizmor_outcome),
        decide_skillxray(skillxray_enabled, skillxray_target, install_skillxray_outcome, skillxray_outcome),
    ]
    passed = not any(r.status == "fail" for r in results)
    return results, passed


def render_summary(results: list[CheckResult], passed: bool, setup_python_outcome: str = "") -> str:
    lines = ["", "## Result", ""]
    if setup_python_outcome and setup_python_outcome != "success":
        # Non-fatal on its own (continue-on-error lets later steps still
        # attempt to run against whatever Python is on the runner), but a
        # maintainer reading the summary should know the pinned
        # python-version may not be the one that actually ran.
        lines.append(
            f"- note: Set up Python did not complete (outcome={setup_python_outcome}); "
            "checks below still show their own real, independent result"
        )
    for r in results:
        if r.status == "pass":
            lines.append(f"- {r.name}: pass")
        elif r.status == "skipped":
            lines.append(f"- {r.name}: skipped ({r.note})")
        else:
            lines.append(f"- {r.name}: FAIL ({r.note})")
    lines.append("")
    lines.append(f"**ci-safety-gate: {'PASS' if passed else 'FAIL'}**")
    return "\n".join(lines) + "\n"


def _env(name: str) -> str:
    return os.environ.get(name, "")


def _env_bool(name: str) -> bool:
    return _env(name).strip().lower() == "true"


def main() -> int:
    """No CLI arguments -- everything comes from the environment, the same
    way the action step this replaces read `${{ }}` values through `env:`."""
    results, passed = evaluate(
        secrets_enabled=_env_bool("INPUTS_SECRETS"),
        secrets_outcome=_env("STEPS_SECRETS_OUTCOME"),
        noslop_enabled=_env_bool("INPUTS_NOSLOP"),
        install_noslop_outcome=_env("STEPS_INSTALL_NOSLOP_OUTCOME"),
        noslop_outcome=_env("STEPS_NOSLOP_OUTCOME"),
        zizmor_enabled=_env_bool("INPUTS_ZIZMOR"),
        install_zizmor_outcome=_env("STEPS_INSTALL_ZIZMOR_OUTCOME"),
        zizmor_outcome=_env("STEPS_ZIZMOR_OUTCOME"),
        skillxray_enabled=_env_bool("INPUTS_SKILLXRAY"),
        skillxray_target=_env("STEPS_SKILLXRAY_DETECT_OUTPUTS_TARGET"),
        install_skillxray_outcome=_env("STEPS_INSTALL_SKILLXRAY_OUTCOME"),
        skillxray_outcome=_env("STEPS_SKILLXRAY_OUTCOME"),
    )
    summary = render_summary(results, passed, setup_python_outcome=_env("STEPS_SETUP_PYTHON_OUTCOME"))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary)
    else:
        print(summary, end="")

    result_line = f"result={'pass' if passed else 'fail'}\n"
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as fh:
            fh.write(result_line)
    else:
        print(result_line, end="")

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
