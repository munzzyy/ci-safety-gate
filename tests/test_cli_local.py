"""End-to-end tests for `ci-safety-gate --local` (ci_safety_gate.cli.main).

These exercise the full path: runner.py's checks feed straight into the
real evaluate_gate.evaluate()/render_summary() -- the same functions
action.yml's "Evaluate gate" step calls -- so a green test here is proof
the local CLI is reusing the verdict logic, not re-deriving its own.
noslop/zizmor/skillxray are disabled in most of these so the suite runs
the same whether or not those tools happen to be installed on the machine
running pytest; the missing-tool behavior itself is covered directly in
test_runner.py.
"""

from __future__ import annotations

import shutil
import subprocess

from ci_safety_gate import cli


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


def test_local_passes_on_a_clean_fixture(tmp_path, capsys):
    _init_git_repo(tmp_path, {"app.py": "def greet(name):\n    return f'hi {name}'\n"})

    code = cli.main(["--local", "--no-noslop", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "# CI Safety Gate" in out
    assert "## Secrets scan" in out
    assert "secrets: pass" in out
    assert "**ci-safety-gate: PASS**" in out


def test_local_fails_on_a_planted_credential(tmp_path, capsys):
    token = "ghp_" + "1" * 36
    _init_git_repo(tmp_path, {"leak.py": f"TOKEN = {token!r}\n"})

    code = cli.main(["--local", "--no-noslop", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 1
    assert "secrets: FAIL" in out
    assert "**ci-safety-gate: FAIL**" in out


def test_local_disabled_checks_render_as_skipped_not_pass(tmp_path, capsys):
    _init_git_repo(tmp_path, {"app.py": "print('hi')\n"})

    code = cli.main(["--local", "--no-noslop", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "noslop: skipped (disabled)" in out
    assert "zizmor: skipped (disabled)" in out
    assert "skillxray: skipped (disabled)" in out


def test_local_reports_missing_tool_as_fail_not_a_silent_pass(tmp_path, capsys, monkeypatch):
    # No planted secrets and no SKILL.md -- the only reason this should
    # fail is noslop being unavailable, which must never read as a pass.
    _init_git_repo(tmp_path, {"app.py": "print('hi')\n"})
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "noslop" else real_which(name))

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 1
    assert "did not run (not installed)" in out
    assert "noslop: FAIL" in out


def test_missing_target_directory_errors_cleanly(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    code = cli.main(["--local", str(missing)])
    err = capsys.readouterr().err
    assert code == 2
    assert "no such directory" in err


def test_without_local_flag_is_a_no_op_not_a_crash(capsys):
    code = cli.main([])
    err = capsys.readouterr().err
    assert code == 2
    assert "--local" in err
