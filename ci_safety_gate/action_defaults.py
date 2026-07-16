"""Read tool defaults and step commands straight out of action.yml.

evaluate_gate.py is already the one place the verdict logic lives; this
module gives `--local` the same discipline for the *other* thing that must
not fork into a second, driftable copy -- which checks run, with which
flags, at which defaults. Rather than hardcoding "noslop-lint==0.10.0" (or
any other default) a second time in this package, every default a check
function needs is parsed out of the real action.yml at import time, so a
version bump or a threshold change in action.yml is picked up here for
free. What can't be avoided without rewriting the composite action into
something that calls Python instead of inline bash is the *flag spelling*
(`--no-config`, `--min-severity`, ...) -- checks.py owns a second copy of
those, and tests/test_checks.py asserts each one is still literally present
in the corresponding action.yml step's `run:` block, so a flag renamed in
one place and not the other fails CI instead of drifting quietly.

This is a small regex-based reader, not a YAML parser. action.yml's
`inputs:` block is flat, unquoted-key, double-quoted-scalar YAML by
construction (see CONTRIBUTING.md); pulling in a real YAML dependency for
one file would break the zero-dependency floor every sibling tool in this
family holds to. If action.yml ever grows a shape this can't read, the
parity test in tests/test_action_defaults.py will fail loudly rather than
silently returning the wrong default.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# action.yml lives at the repo root, one directory up from this package --
# true both for a plain checkout and for `pip install -e .` against one,
# since neither changes the on-disk layout. A real (non-editable) wheel
# built for PyPI would need action.yml bundled as package data to keep this
# working; that's a known follow-up, not solved here since publishing this
# package isn't in scope yet (see README's "Known limitations").
_CANDIDATE_PATHS = (
    Path(__file__).resolve().parent.parent / "action.yml",
    Path.cwd() / "action.yml",
)

_INPUT_NAME_RE = re.compile(r"^  ([a-z][a-z0-9\-]*):\n", re.MULTILINE)
_DEFAULT_RE = re.compile(r'^\s*default:\s*"(.*)"\s*$', re.MULTILINE)
_STEP_NAME_RE = re.compile(r"^    - name: (.+)\n", re.MULTILINE)


class ActionYamlNotFound(RuntimeError):
    """action.yml couldn't be located next to this install.

    --local reads its defaults and its parity tests read the real step
    commands out of action.yml rather than a hardcoded second copy, so it
    needs the file on disk. That only works from a checkout of
    munzzyy/ci-safety-gate (a plain clone or `pip install -e .` against
    one) -- see README's "Known limitations".
    """


def find_action_yml() -> Path:
    for candidate in _CANDIDATE_PATHS:
        if candidate.is_file():
            return candidate
    raise ActionYamlNotFound(
        "could not find action.yml next to this ci-safety-gate install. "
        "--local currently only works from a checkout of "
        "munzzyy/ci-safety-gate (`git clone` + `pip install -e .`); "
        "see README.md's \"Known limitations\"."
    )


@lru_cache(maxsize=1)
def read_action_yml_text() -> str:
    return find_action_yml().read_text(encoding="utf-8")


def _inputs_section(text: str) -> str:
    match = re.search(r"^inputs:\n(.*?)^(?:outputs|runs):\n", text, re.DOTALL | re.MULTILINE)
    if not match:
        raise ActionYamlNotFound("action.yml has no inputs: section this reader recognizes")
    return match.group(1)


@lru_cache(maxsize=1)
def input_defaults() -> dict[str, str]:
    """Every `<name>: {..., default: "..."}` under action.yml's inputs:."""
    section = _inputs_section(read_action_yml_text())
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


def default(name: str) -> str:
    """One input's default value, e.g. default("noslop-version") == "0.10.0"."""
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
