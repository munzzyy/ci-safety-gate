"""Tests for ci_safety_gate.runner -- the check-by-check local execution.

detect_skillxray_target gets checked against action.yml's real find
pipeline (prune .git/node_modules, respect max_depth, target the whole
root on any hit). The rest of this file protects the missing-tool path:
run_noslop/run_zizmor/run_skillxray must all report install_outcome
"failure" with a scan_outcome that evaluate_gate.decide_check turns into
FAIL, and a summary naming the exact install command -- a scanner that
silently skips because it isn't installed and still reports clean is a
gate bug, not a convenience.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess

from ci_safety_gate import runner


def _init_git_repo(root, files: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=root, check=True)


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


# ---------------------------------------------------------------------------
# _git_ls_files
# ---------------------------------------------------------------------------

def test_git_ls_files_matches_only_tracked_globbed_files(tmp_path):
    _init_git_repo(tmp_path, {
        "a.py": "print('a')\n",
        "b.md": "# doc\n",
        "sub/c.py": "print('c')\n",
    })
    (tmp_path / "untracked.py").write_text("print('untracked')\n")

    files, note = runner._git_ls_files(tmp_path, "*.py")
    assert note == ""
    assert sorted(files) == ["a.py", "sub/c.py"]


def test_git_ls_files_on_non_git_dir_returns_empty_with_a_note(tmp_path):
    files, note = runner._git_ls_files(tmp_path, "*.py")
    assert files == []
    assert "note:" in note


# ---------------------------------------------------------------------------
# Missing-tool paths never read as a clean pass
# ---------------------------------------------------------------------------

def test_run_noslop_fails_loud_when_not_installed(tmp_path, monkeypatch):
    _init_git_repo(tmp_path, {"a.py": "print('a')\n"})
    real_which = shutil.which

    def fake_which(name):
        if name == "noslop":
            return None
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)

    install_outcome, scan_outcome, summary = runner.run_noslop(
        tmp_path, "*.py", "*.md", "", "0.10.0", install_missing=False,
    )
    assert install_outcome == "failure"
    assert scan_outcome == "skipped"
    assert "did not run (not installed)" in summary
    assert "noslop-lint==0.10.0" in summary


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
    assert "pip install zizmor" in summary


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
