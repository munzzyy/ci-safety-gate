import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# scan_secrets.py lives at the repo root, not inside a package, since this
# repo ships an action, not an installable library.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ci_safety_gate import action_defaults  # noqa: E402

# The shell GitHub runs a composite step's `shell: bash` with.
GITHUB_BASH = ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"]


def step_run_body(step_name: str) -> str:
    """The literal `run: |` script of one action.yml step, dedented."""
    lines = action_defaults.step_block(step_name).splitlines()
    for i, line in enumerate(lines):
        match = re.match(r"^(\s*)run: \|\s*$", line)
        if match:
            break
    else:
        raise AssertionError(f"step {step_name!r} has no `run: |` block")
    key_indent = len(match.group(1))
    body = []
    for line in lines[i + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


@pytest.fixture
def run_action_step(tmp_path_factory):
    """Run an action.yml step's real bash under GitHub's own shell flags.

    `replacements` swaps each `${{ ... }}` for something bash can expand;
    any left over fails the test instead of reaching bash.
    """
    def run(step_name: str, env: dict, replacements: dict | None = None):
        script = step_run_body(step_name)
        for old, new in (replacements or {}).items():
            script = script.replace(old, new)
        assert "${{" not in script, f"unreplaced expression left in {step_name!r}"
        path = tmp_path_factory.mktemp("step") / "step.sh"
        path.write_text(script, encoding="utf-8")
        return subprocess.run(
            GITHUB_BASH + [str(path)],
            env={**os.environ, **env}, capture_output=True, text=True,
        )
    return run
