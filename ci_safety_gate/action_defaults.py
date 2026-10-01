"""Read tool defaults and step commands straight out of action.yml.

evaluate_gate.py is already the one place the verdict logic lives; this
module gives `--local` the same discipline for the *other* thing that must
not fork into a second, driftable copy -- which checks run, with which
flags, at which defaults. Rather than hardcoding "zizmor-min-severity" (or
any other default) a second time in this package, every default a check
function needs is parsed out of the real action.yml at import time, so a
version bump or a threshold change in action.yml is picked up here for
free. What can't be avoided without rewriting the composite action into
something that calls Python instead of inline bash is the *flag spelling*
(`--min-severity`, `--fail-on`, ...) -- checks.py owns a second copy of
those, and tests/test_checks.py asserts each one is still literally present
in the corresponding action.yml step's `run:` block, so a flag renamed in
one place and not the other fails CI instead of drifting quietly.

An installed copy (pre-commit's hook environment, any non-editable
`pip install`) has no action.yml next to it, so the package also ships
_action_defaults.json, generated from action.yml with
`python3 -m ci_safety_gate.action_defaults > ci_safety_gate/_action_defaults.json`
and held equal to it by tests/test_action_defaults.py. An action.yml in
the current directory is never read: that is the user's file, not ours.

This is a small regex-based reader, not a YAML parser. action.yml's
`inputs:` block is flat, unquoted-key, double-quoted-scalar YAML by
construction (see CONTRIBUTING.md); pulling in a real YAML dependency for
one file would break the zero-dependency floor every sibling tool in this
family holds to. If action.yml ever grows a shape this can't read, the
parity test in tests/test_action_defaults.py will fail loudly rather than
silently returning the wrong default.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_ACTION_YML = Path(__file__).resolve().parent.parent / "action.yml"
_PACKAGED_DEFAULTS = Path(__file__).resolve().parent / "_action_defaults.json"

_INPUT_NAME_RE = re.compile(r"^  ([a-z][a-z0-9\-]*):\n", re.MULTILINE)
_DEFAULT_RE = re.compile(r'^\s*default:\s*"(.*)"\s*$', re.MULTILINE)
_STEP_NAME_RE = re.compile(r"^    - name: (.+)\n", re.MULTILINE)


class ActionYamlNotFound(RuntimeError):
    """Neither action.yml nor the packaged copy of its defaults was found.

    action.yml sits next to this package in a checkout of
    munzzyy/ci-safety-gate (a plain clone or `pip install -e .`), and
    _action_defaults.json ships inside it for every other install. Missing
    both means a broken install.
    """


def find_action_yml() -> Path:
    if _ACTION_YML.is_file():
        return _ACTION_YML
    raise ActionYamlNotFound(
        "could not find action.yml next to this ci-safety-gate install; "
        "it is only there in a checkout of munzzyy/ci-safety-gate"
    )


@lru_cache(maxsize=1)
def read_action_yml_text() -> str:
    return find_action_yml().read_text(encoding="utf-8")


def _inputs_section(text: str) -> str:
    match = re.search(r"^inputs:\n(.*?)^(?:outputs|runs):\n", text, re.DOTALL | re.MULTILINE)
    if not match:
        raise ActionYamlNotFound("action.yml has no inputs: section this reader recognizes")
    return match.group(1)


def parse_input_defaults(text: str) -> dict[str, str]:
    """Every `<name>: {..., default: "..."}` under an action.yml's inputs:."""
    section = _inputs_section(text)
    names = list(_INPUT_NAME_RE.finditer(section))
    defaults: dict[str, str] = {}
    for i, m in enumerate(names):
        start = m.end()
        end = names[i + 1].start() if i + 1 < len(names) else len(section)
        block = section[start:end]
        default_match = _DEFAULT_RE.search(block)
        if default_match:
            defaults[m.group(1)] = default_match.group(1)
    return defaults


def packaged_defaults() -> dict[str, str]:
    try:
        text = _PACKAGED_DEFAULTS.read_text(encoding="utf-8")
    except OSError:
        raise ActionYamlNotFound(
            "neither action.yml nor the packaged _action_defaults.json was found; "
            "reinstall ci-safety-gate"
        ) from None
    return json.loads(text)


@lru_cache(maxsize=1)
def input_defaults() -> dict[str, str]:
    """action.yml's input defaults: read from action.yml itself in a
    checkout, from the packaged copy everywhere else."""
    try:
        text = read_action_yml_text()
    except ActionYamlNotFound:
        return packaged_defaults()
    return parse_input_defaults(text)


def default(name: str) -> str:
    """One input's default value, e.g. default("zizmor-min-severity") == "medium"."""
    try:
        return input_defaults()[name]
    except KeyError:
        raise KeyError(f"action.yml has no input named {name!r} with a default") from None


@lru_cache(maxsize=1)
def step_blocks() -> dict[str, str]:
    """Each `runs.steps[].name` mapped to the raw text of everything after
    it, up to the next step -- used by tests/test_checks.py to confirm a
    flag checks.py builds is still literally present in the bash action.yml
    actually runs."""
    text = read_action_yml_text()
    runs_start = text.index("\nruns:\n")
    section = text[runs_start:]
    names = list(_STEP_NAME_RE.finditer(section))
    blocks: dict[str, str] = {}
    for i, m in enumerate(names):
        start = m.end()
        end = names[i + 1].start() if i + 1 < len(names) else len(section)
        blocks[m.group(1).strip()] = section[start:end]
    return blocks


def step_block(name: str) -> str:
    try:
        return step_blocks()[name]
    except KeyError:
        raise KeyError(f"action.yml has no step named {name!r}") from None


if __name__ == "__main__":
    print(json.dumps(parse_input_defaults(read_action_yml_text()), indent=2, sort_keys=True))
