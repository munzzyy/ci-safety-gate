"""Tests for ci_safety_gate.runner -- the check-by-check local execution.

detect_skillxray_target gets checked against action.yml's real find
pipeline (prune .git/node_modules, respect max_depth, target the whole
root on any hit). The rest of this file protects the missing-tool path:
run_zizmor/run_skillxray must both report install_outcome
"failure" with a scan_outcome that evaluate_gate.decide_check turns into
FAIL, and a summary naming the exact install command -- a scanner that
silently skips because it isn't installed and still reports clean is a
gate bug, not a convenience.
"""

from __future__ import annotations

import importlib.util
import os
import shlex
import shutil
import subprocess

import pytest

from ci_safety_gate import action_defaults, runner


def _action_yml_find_hits(root) -> bool:
    """Run the exact find pipeline action.yml's "Detect skill-shaped
    content" step uses, so the port can be checked against real find rather
    than a paraphrase of it. test_detect_find_pipeline_matches_action_yml
    guards the hardcoded predicate below against drift from action.yml."""
    cmd = (
        f"find -L {shlex.quote(str(root))} -maxdepth 6 "
        r"\( -path '*/.git' -o -path '*/node_modules' \) -prune -o "
        r"\( -type f -name 'SKILL.md' -o -type d -name 'skills' "
        r"-o -type d -name '.claude' \) -print "
        "2>/dev/null | grep -q ."
    )
    return subprocess.run(["bash", "-c", cmd]).returncode == 0


# ---------------------------------------------------------------------------
# detect_skillxray_target
# ---------------------------------------------------------------------------

def test_detect_finds_skill_md_at_root(tmp_path):
    (tmp_path / "SKILL.md").write_text("# skill\n")
    assert runner.detect_skillxray_target(tmp_path) == str(tmp_path)


def test_detect_finds_skills_directory(tmp_path):
    (tmp_path / "skills" / "demo").mkdir(parents=True)
    assert runner.detect_skillxray_target(tmp_path) == str(tmp_path)


def test_detect_finds_dot_claude_directory(tmp_path):
    (tmp_path / ".claude").mkdir()
    assert runner.detect_skillxray_target(tmp_path) == str(tmp_path)


def test_detect_returns_empty_when_nothing_matches(tmp_path):
    (tmp_path / "src" / "app.py").parent.mkdir(parents=True)
    (tmp_path / "src" / "app.py").write_text("print('hi')\n")
    assert runner.detect_skillxray_target(tmp_path) == ""


def test_detect_ignores_skill_md_inside_dot_git(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "SKILL.md").write_text("not a real skill\n")
    assert runner.detect_skillxray_target(tmp_path) == ""


def test_detect_ignores_skills_dir_inside_node_modules(tmp_path):
    (tmp_path / "node_modules" / "skills").mkdir(parents=True)
    assert runner.detect_skillxray_target(tmp_path) == ""


def test_detect_respects_max_depth(tmp_path):
    # Six nested directories (d0..d5) puts SKILL.md one level past
    # action.yml's real `find -maxdepth 6` -- must be missed at the real
    # default and found once max_depth is opened up to include it.
    deep = tmp_path
    for i in range(6):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "SKILL.md").write_text("# skill\n")
    assert runner.detect_skillxray_target(tmp_path) == ""  # default max_depth=6
    assert runner.detect_skillxray_target(tmp_path, max_depth=7) == str(tmp_path)


def test_detect_on_missing_root_returns_empty(tmp_path):
    assert runner.detect_skillxray_target(tmp_path / "does-not-exist") == ""


def test_detect_find_pipeline_matches_action_yml():
    # The find predicate _action_yml_find_hits hardcodes must still be the
    # one action.yml actually runs, so the parity fixtures below compare the
    # port against real semantics -- not a stale copy.
    block = action_defaults.step_block("Detect skill-shaped content")
    for token in (
        "find -L ",
        "-type f -name 'SKILL.md'",
        "-type d -name 'skills'",
        "-type d -name '.claude'",
    ):
        assert token in block
    # -xtype is a GNU-only primary that errors out on BSD/macOS find (and,
    # combined with -type f, missed a symlinked SKILL.md). It must be gone.
    assert "-xtype" not in block


@pytest.mark.skipif(
    os.name == "nt",
    reason="_action_yml_find_hits runs a POSIX find pipeline; the action runs on Linux runners",
)
def test_detect_symlinked_skills_dir_is_a_hit_in_both_engines(tmp_path):
    # A repo whose skills/ is a symlink to a real dir must still be
    # detected -- and the CI find and the local port must agree, or a
    # symlinked skill tree gets scanned in one mode and clean-skipped in
    # the other.
    (tmp_path / "realskills").mkdir()
    try:
        os.symlink("realskills", tmp_path / "skills")
    except (OSError, NotImplementedError):
        pytest.skip("platform does not allow creating symlinks without elevated privilege")

    assert runner.detect_skillxray_target(tmp_path) == str(tmp_path)
    assert _action_yml_find_hits(tmp_path) is True


@pytest.mark.skipif(
    os.name == "nt",
    reason="_action_yml_find_hits runs a POSIX find pipeline; the action runs on Linux runners",
)
def test_detect_symlinked_skill_md_is_a_hit_in_both_engines(tmp_path):
    # A repo whose only skill marker is a SKILL.md symlinked to a real file
    # must be detected by both engines. The old CI predicate `-type f`
    # tested the symlink's own type (l, not f) and missed it, so CI left the
    # target empty and skipped skillxray entirely -- a fail-OPEN divergence
    # from the port, which finds the symlink in os.walk's filenames.
    (tmp_path / "actual.md").write_text("# skill\n")
    try:
        os.symlink("actual.md", tmp_path / "SKILL.md")
    except (OSError, NotImplementedError):
        pytest.skip("platform does not allow creating symlinks without elevated privilege")

    assert runner.detect_skillxray_target(tmp_path) == str(tmp_path)
    assert _action_yml_find_hits(tmp_path) is True


def test_detect_directory_named_skill_md_is_not_a_hit_in_both_engines(tmp_path):
    # A directory literally named SKILL.md is not a skill file; neither
    # engine should treat it as a hit.
    (tmp_path / "SKILL.md" / "nested").mkdir(parents=True)

    assert runner.detect_skillxray_target(tmp_path) == ""
    assert _action_yml_find_hits(tmp_path) is False


# ---------------------------------------------------------------------------
# Missing-tool paths never read as a clean pass
# ---------------------------------------------------------------------------

def test_run_zizmor_fails_loud_when_not_installed(tmp_path, monkeypatch):
    real_which = shutil.which

    def fake_which(name):
        if name == "zizmor":
            return None
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)

    install_outcome, scan_outcome, summary = runner.run_zizmor(
        tmp_path, ".", "medium", True, install_missing=False,
    )
    assert install_outcome == "failure"
    assert scan_outcome == "skipped"
    assert "did not run (not installed)" in summary
    # The hint has to name the same floored spec the action installs, not a
    # bare `pip install zizmor` that resolves anything.
    assert 'pip install "zizmor>=1.28.0"' in summary


def test_run_skillxray_fails_loud_when_not_installed(tmp_path, monkeypatch):
    (tmp_path / "SKILL.md").write_text("# fake skill\n")
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name, *args, **kwargs):
        if name == "skillxray":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    target, install_outcome, scan_outcome, summary = runner.run_skillxray(
        tmp_path, "", "high", "v0.1.1", install_missing=False,
    )
    assert target == str(tmp_path)
    assert install_outcome == "failure"
    assert scan_outcome == "skipped"
    assert "did not run (not installed)" in summary
    assert "skillxray@v0.1.1" in summary


def test_run_skillxray_skips_cleanly_with_no_target(tmp_path):
    target, install_outcome, scan_outcome, summary = runner.run_skillxray(
        tmp_path, "", "high", "v0.1.1", install_missing=False,
    )
    assert target == ""
    assert install_outcome is None
    assert scan_outcome == "skipped"
    assert "no SKILL.md" in summary


# ---------------------------------------------------------------------------
# run_secrets (stdlib-only, always runnable)
# ---------------------------------------------------------------------------

def test_run_secrets_passes_on_a_clean_tree(tmp_path):
    (tmp_path / "app.py").write_text("def greet(name):\n    return f'hi {name}'\n")
    install_outcome, scan_outcome, summary = runner.run_secrets(tmp_path, ".", 2_000_000, [])
    assert install_outcome is None
    assert scan_outcome == "success"
    assert "Secrets scan" in summary


def test_run_secrets_fails_on_a_planted_credential(tmp_path):
    token = "ghp_" + "0" * 36
    (tmp_path / "leak.py").write_text(f"TOKEN = {token!r}\n")
    install_outcome, scan_outcome, summary = runner.run_secrets(tmp_path, ".", 2_000_000, [])
    assert install_outcome is None
    assert scan_outcome == "failure"
    assert "Secrets scan" in summary


def test_run_secrets_fail_on_skip_turns_a_skip_into_a_failure(tmp_path):
    # An oversized file is a skip, not a finding. Without the flag the scan
    # still passes; with it, run_secrets must report scan_outcome "failure"
    # so evaluate_gate.decide_check turns the gate FAIL.
    (tmp_path / "big.py").write_text("x" * 200, encoding="utf-8")

    _, scan_outcome_default, _ = runner.run_secrets(tmp_path, ".", 50, [])
    assert scan_outcome_default == "success"

    _, scan_outcome_strict, summary = runner.run_secrets(tmp_path, ".", 50, [], fail_on_skip=True)
    assert scan_outcome_strict == "failure"
    assert "big.py" in summary
    assert "too large" in summary


# ---------------------------------------------------------------------------
# run_checkout_safety
# ---------------------------------------------------------------------------

def test_run_checkout_safety_passes_on_a_repo_with_no_workflows(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    install_outcome, scan_outcome, summary = runner.run_checkout_safety(tmp_path, ".", "high")
    assert install_outcome is None
    assert scan_outcome == "success"
    assert "Checkout safety" in summary


def test_run_checkout_safety_fails_on_an_unsafe_pr_checkout(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "build.yml").write_text(
        "name: build\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v7\n"
        "        with:\n"
        "          allow-unsafe-pr-checkout: true\n",
        encoding="utf-8",
    )
    _, scan_outcome, summary = runner.run_checkout_safety(tmp_path, ".", "high")
    assert scan_outcome == "failure"
    assert "allow-unsafe-pr-checkout" in summary
