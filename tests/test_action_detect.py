"""Run action.yml's step scripts for real.

Each step is pulled out of action.yml and run under the exact shell
GitHub uses for composite steps (`bash --noprofile --norc -e -o
pipefail`). For "Detect skill-shaped content", a fixture that should be
scanned has to come out as `target=<root>`; anything else means skillxray
is skipped and the gate reports a pass on content nobody scanned.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="runs action.yml's bash and POSIX find; the action runs on Linux runners",
)

DETECT = "Detect skill-shaped content"


def _detect(run_action_step, tmp_path, root, skillxray_path=""):
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    proc = run_action_step(
        DETECT,
        env={
            "GITHUB_OUTPUT": str(output),
            "GITHUB_WORKSPACE": str(root),
            "INPUTS_SKILLXRAY_PATH": skillxray_path,
        },
        replacements={"${{ github.workspace }}": "$GITHUB_WORKSPACE"},
    )
    assert proc.returncode == 0, proc.stderr
    return output.read_text(encoding="utf-8")


def _symlink(src, dst):
    try:
        os.symlink(src, dst)
    except (OSError, NotImplementedError):
        pytest.skip("platform does not allow creating symlinks without elevated privilege")


def test_skill_md_next_to_a_symlink_loop_is_still_detected(run_action_step, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    _symlink(".", root / "loop")
    assert _detect(run_action_step, tmp_path, root) == f"target={root}\n"


def test_a_large_skill_collection_is_detected(run_action_step, tmp_path):
    root = tmp_path / "repo"
    for n in range(300):
        skill = root / "skills" / f"s{n}"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    assert _detect(run_action_step, tmp_path, root) == f"target={root}\n"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root reads a chmod 000 directory anyway")
def test_skill_md_next_to_an_unreadable_directory_is_detected(run_action_step, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    locked = root / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert _detect(run_action_step, tmp_path, root) == f"target={root}\n"
    finally:
        locked.chmod(0o755)


def test_a_lone_skill_md_is_detected(run_action_step, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    assert _detect(run_action_step, tmp_path, root) == f"target={root}\n"


def test_a_repo_with_no_skill_content_is_a_clean_skip(run_action_step, tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _detect(run_action_step, tmp_path, root) == "target=\n"


def test_an_explicit_skillxray_path_skips_detection(run_action_step, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    assert _detect(run_action_step, tmp_path, root, skillxray_path="docs") == "target=docs\n"


# ---------------------------------------------------------------------------
# Sub-option toggles compare without regard to case, like the step `if:`s
# and evaluate_gate.py do.
# ---------------------------------------------------------------------------

def _stub_dir(tmp_path) -> Path:
    stub = tmp_path / "action"
    stub.mkdir()
    (stub / "scan_secrets.py").write_text(
        "import json, sys\nprint(json.dumps(sys.argv[1:]))\n", encoding="utf-8")
    return stub


@pytest.mark.parametrize("value,expected", [("True", True), ("TRUE", True), ("false", False)])
def test_secrets_sub_options_ignore_case(run_action_step, tmp_path, value, expected):
    summary = tmp_path / "summary.md"
    proc = run_action_step(
        "Secrets scan",
        env={
            "GITHUB_STEP_SUMMARY": str(summary),
            "INPUTS_SECRETS_PATH": ".",
            "INPUTS_SECRETS_MAX_BYTES": "2000000",
            "INPUTS_SECRETS_EXCLUDE": "",
            "INPUTS_SECRETS_FAIL_ON_SKIP": value,
            "INPUTS_SECRETS_ANNOTATIONS": value,
        },
        replacements={"${{ github.action_path }}": str(_stub_dir(tmp_path))},
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads(summary.read_text(encoding="utf-8"))
    assert ("--fail-on-skip" in argv) is expected
    assert ("--github-annotations" in argv) is expected


@pytest.mark.parametrize("value,expected", [("True", True), ("false", False)])
def test_zizmor_offline_ignores_case(run_action_step, tmp_path, value, expected):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "zizmor"
    fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    fake.chmod(0o755)
    summary = tmp_path / "summary.md"
    proc = run_action_step(
        "zizmor",
        env={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_STEP_SUMMARY": str(summary),
            "INPUTS_ZIZMOR_OFFLINE": value,
            "INPUTS_ZIZMOR_PERSONA": "auditor",
            "INPUTS_ZIZMOR_MIN_SEVERITY": "medium",
            "INPUTS_ZIZMOR_PATH": ".",
        },
    )
    assert proc.returncode == 0, proc.stderr
    args = summary.read_text(encoding="utf-8").splitlines()
    assert ("--offline" in args) is expected


def test_action_yml_avoids_bash_4_case_conversion():
    # bash 3.2, still macOS's /bin/bash, has no ${X,,} or ${X^^}.
    text = (Path(__file__).resolve().parent.parent / "action.yml").read_text(encoding="utf-8")
    assert ",,}" not in text and "^^}" not in text
