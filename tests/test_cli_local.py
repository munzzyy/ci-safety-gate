"""End-to-end tests for `ci-safety-gate --local` (ci_safety_gate.cli.main).

These exercise the full path: runner.py's checks feed straight into the
real evaluate_gate.evaluate()/render_summary() -- the same functions
action.yml's "Evaluate gate" step calls -- so a green test here is proof
the local CLI is reusing the verdict logic, not re-deriving its own.
zizmor/skillxray are disabled in most of these so the suite runs
the same whether or not those tools happen to be installed on the machine
running pytest; the missing-tool behavior itself is covered directly in
test_runner.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from ci_safety_gate import action_defaults, cli


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

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "# CI Safety Gate" in out
    assert "## Secrets scan" in out
    assert "secrets: pass" in out
    assert "**ci-safety-gate: PASS**" in out


def test_local_fails_on_a_planted_credential(tmp_path, capsys):
    token = "ghp_" + "1" * 36
    _init_git_repo(tmp_path, {"leak.py": f"TOKEN = {token!r}\n"})

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 1
    assert "secrets: FAIL" in out
    assert "**ci-safety-gate: FAIL**" in out


def test_local_disabled_checks_render_as_skipped_not_pass(tmp_path, capsys):
    _init_git_repo(tmp_path, {"app.py": "print('hi')\n"})

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "zizmor: skipped (disabled)" in out
    assert "skillxray: skipped (disabled)" in out


def test_local_reports_missing_tool_as_fail_not_a_silent_pass(tmp_path, capsys, monkeypatch):
    # No planted secrets and no SKILL.md -- the only reason this should
    # fail is zizmor being unavailable, which must never read as a pass.
    _init_git_repo(tmp_path, {"app.py": "print('hi')\n"})
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "zizmor" else real_which(name))

    code = cli.main(["--local", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 1
    assert "did not run (not installed)" in out
    assert "zizmor: FAIL" in out


def test_local_fail_on_skip_fails_the_gate_when_a_file_is_skipped(tmp_path, capsys):
    # An oversized file is skipped by the secrets scan. With --fail-on-skip
    # the whole gate must go FAIL -- an under-scan can't hide behind a clean
    # verdict.
    _init_git_repo(tmp_path, {"big.py": "x" * 200})

    code = cli.main([
        "--local", "--no-zizmor", "--no-skillxray",
        "--secrets-max-bytes", "50", "--fail-on-skip", str(tmp_path),
    ])

    out = capsys.readouterr().out
    assert code == 1
    assert "secrets: FAIL" in out
    assert "big.py" in out
    assert "**ci-safety-gate: FAIL**" in out


def test_local_without_fail_on_skip_still_passes_on_a_skip(tmp_path, capsys):
    # Same skipped file, no flag: the skip is reported in the summary but the
    # gate still passes, so default behavior is unchanged.
    _init_git_repo(tmp_path, {"big.py": "x" * 200})

    code = cli.main([
        "--local", "--no-zizmor", "--no-skillxray",
        "--secrets-max-bytes", "50", str(tmp_path),
    ])

    out = capsys.readouterr().out
    assert code == 0
    assert "secrets: pass" in out
    assert "big.py" in out
    assert "**ci-safety-gate: PASS**" in out


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


def test_local_flags_an_unsafe_pr_checkout_and_fails_the_gate(tmp_path, capsys):
    _init_git_repo(tmp_path, {
        ".github/workflows/build.yml": (
            "name: build\n"
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v7\n"
            "        with:\n"
            "          allow-unsafe-pr-checkout: true\n"
        ),
    })

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 1
    assert "## Checkout safety" in out
    assert "checkout-safety: FAIL" in out


def test_local_json_reports_pass_and_a_result_per_check(tmp_path, capsys):
    _init_git_repo(tmp_path, {"app.py": "print('hi')\n"})

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", "--json", str(tmp_path)])

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 0
    assert payload["passed"] is True
    checks_by_name = {c["name"]: c for c in payload["checks"]}
    assert checks_by_name["secrets"]["status"] == "pass"
    assert checks_by_name["zizmor"]["status"] == "skipped"


def test_local_json_reports_fail_on_a_planted_credential(tmp_path, capsys):
    token = "ghp_" + "1" * 36
    _init_git_repo(tmp_path, {"leak.py": f"TOKEN = {token!r}\n"})

    code = cli.main(["--local", "--no-zizmor", "--no-skillxray", "--json", str(tmp_path)])

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 1
    assert payload["passed"] is False
    checks_by_name = {c["name"]: c for c in payload["checks"]}
    assert checks_by_name["secrets"]["status"] == "fail"
    assert "# CI Safety Gate" not in out


def test_local_checkout_safety_can_be_turned_off(tmp_path, capsys):
    _init_git_repo(tmp_path, {"app.py": "print('hi')\n"})

    code = cli.main([
        "--local", "--no-zizmor", "--no-skillxray", "--no-checkout-safety", str(tmp_path),
    ])

    out = capsys.readouterr().out
    assert code == 0
    assert "checkout-safety: skipped (disabled)" in out


@pytest.fixture
def installed_layout(tmp_path, monkeypatch):
    """No action.yml next to the package, the way pre-commit installs it."""
    monkeypatch.setattr(action_defaults, "_ACTION_YML", tmp_path / "no-such" / "action.yml")
    action_defaults.read_action_yml_text.cache_clear()
    action_defaults.input_defaults.cache_clear()
    yield
    action_defaults.read_action_yml_text.cache_clear()
    action_defaults.input_defaults.cache_clear()


def test_installed_cli_ignores_an_action_yml_in_the_current_directory(
        tmp_path, monkeypatch, installed_layout, capsys):
    # Someone who writes GitHub Actions runs the hook in a repo with its own
    # action.yml. Its inputs are not ours and must never become defaults.
    repo = tmp_path / "their-action"
    _init_git_repo(repo, {
        "action.yml": (
            'name: x\ninputs:\n  token:\n    description: "t"\n    default: "abc"\n'
            "runs:\n  using: node20\n  main: x.js\n"
        ),
    })
    monkeypatch.chdir(repo)

    assert action_defaults.input_defaults() == action_defaults.packaged_defaults()
    args = cli.build_parser().parse_args(["--local"])
    assert args.skillxray_ref == action_defaults.packaged_defaults()["skillxray-ref"]
    assert args.secrets_path == "."

    code = cli.main(["--local", ".", "--no-zizmor", "--no-skillxray"])
    assert code == 0
    assert "**ci-safety-gate: PASS**" in capsys.readouterr().out


def test_cli_fallbacks_match_action_yml(monkeypatch):
    # The fallbacks only render when no defaults source is found, but a
    # stale one there would quietly install something else.
    real = vars(cli.build_parser().parse_args(["--local"]))

    def missing(name):
        raise action_defaults.ActionYamlNotFound("simulated broken install")

    monkeypatch.setattr(action_defaults, "default", missing)
    assert vars(cli.build_parser().parse_args(["--local"])) == real
