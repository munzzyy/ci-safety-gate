"""Run action.yml's "Detect skill-shaped content" step for real.

The step is pulled out of action.yml and run under the exact shell
GitHub uses for composite steps (`bash --noprofile --norc -e -o
pipefail`), so a fixture that should be scanned has to come out as
`target=<root>`. Anything else means skillxray is skipped and the gate
reports a pass on content nobody scanned.
"""

from __future__ import annotations

import os

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
