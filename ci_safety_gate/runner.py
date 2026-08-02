"""Run each check the way action.yml's composite steps do, and hand the
same shape of result to evaluate_gate.evaluate() that the real action
would have. cli.py is the only caller; this module has no argparse in it
so it can be unit tested directly.

Every subprocess call here uses checks.py's argv builders, never a second,
inline copy of a tool's flags -- see checks.py's docstring and
tests/test_checks.py for how that's kept honest.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import checks

# Every run_*() function below returns (install_outcome, scan_outcome,
# summary_markdown). install_outcome is None for checks with nothing to
# install (secrets is stdlib-only), the same convention
# evaluate_gate.decide_check already uses for its own install_outcome
# parameter.


def _outcome_from_returncode(code: int) -> str:
    return "success" if code == 0 else "failure"


def _fenced_section(heading: str, body: str) -> str:
    body = body if body.strip() else "(no output)"
    return f"## {heading}\n\n```\n{body.rstrip()}\n```\n"


def _not_installed_section(heading: str, tool: str, install_hint: str) -> str:
    # This is the "fail loud, never a silent pass" case the plan calls
    # out by name: a missing scanner reads as a FAIL with a clear fix,
    # not a clean skip.
    return (
        f"## {heading}\n\n"
        f"{tool} did not run (not installed): install with `{install_hint}`, "
        "or re-run with --install-missing to do it automatically.\n"
    )


def _pip_install(pip_args: list[str]) -> bool:
    """The same install action.yml's own "Install X" steps run:
    `python3 -m pip install --quiet <pins>`. Only called when
    --install-missing is passed -- see README's "Known limitations" for
    why this isn't the default."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", *pip_args],
        capture_output=True,
    )
    return result.returncode == 0


# text=True decodes with the locale encoding, which is cp1252 on a Windows
# runner. zizmor's own output is not ASCII (its INFO lines carry an emoji,
# its findings are drawn with box characters), and several UTF-8 byte
# values have no cp1252 mapping at all, so the default would either
# mojibake the summary or raise UnicodeDecodeError and take the CLI down
# with a traceback. A scanner that crashes on its own tool's output is
# worse than one showing a replacement character.
_DECODE = {"encoding": "utf-8", "errors": "replace"}


def run_secrets(root: Path, path: str, max_bytes: int, excludes: list[str],
                fail_on_skip: bool = False) -> tuple[None, str, str]:
    """secrets is stdlib-only -- no install step, install_outcome is
    always None, matching decide_check's convention for it. When
    fail_on_skip is set, scan_secrets.py exits non-zero on any skipped file,
    so the returncode below turns a silent under-scan into a real FAIL."""
    script = Path(__file__).resolve().parent.parent / "scan_secrets.py"
    argv = [sys.executable, str(script), *checks.secrets_argv(path, max_bytes, excludes, fail_on_skip)]
    proc = subprocess.run(argv, cwd=str(root), capture_output=True, text=True, **_DECODE)
    # scan_secrets.py's own --summary output already starts with "## Secrets
    # scan", so its stdout *is* the section -- no extra wrapping needed.
    summary = proc.stdout if proc.stdout.strip() else "## Secrets scan\n\n(no output)\n"
    return None, _outcome_from_returncode(proc.returncode), summary


def run_checkout_safety(root: Path, path: str, fail_on: str) -> tuple[None, str, str]:
    """checkout_safety.py is stdlib-only like the secrets scan, so there is
    no install step and install_outcome is always None."""
    script = Path(__file__).resolve().parent.parent / "checkout_safety.py"
    argv = [sys.executable, str(script), *checks.checkout_safety_argv(path, fail_on)]
    proc = subprocess.run(argv, cwd=str(root), capture_output=True, text=True, **_DECODE)
    # Its --summary output already starts with "## Checkout safety".
    summary = proc.stdout if proc.stdout.strip() else "## Checkout safety\n\n(no output)\n"
    return None, _outcome_from_returncode(proc.returncode), summary


def run_zizmor(
    root: Path,
    path: str,
    min_severity: str,
    offline: bool,
    install_missing: bool,
    persona: str = "auditor",
    version: str = ">=1.28.0",
) -> tuple[str, str, str]:
    heading = "zizmor (GitHub Actions security audit)"
    pip_spec = checks.zizmor_pip_spec(version)
    if shutil.which("zizmor") is None:
        install_outcome = "failure"
        if install_missing:
            ok = _pip_install([pip_spec])
            install_outcome = "success" if ok and shutil.which("zizmor") else "failure"
        if install_outcome != "success":
            return install_outcome, "skipped", _not_installed_section(
                heading, "zizmor", f'pip install "{pip_spec}"'
            )
    else:
        install_outcome = "success"

    proc = subprocess.run(
        checks.zizmor_argv(path, min_severity, offline, persona),
        cwd=str(root), capture_output=True, text=True, **_DECODE,
    )
    summary = _fenced_section(heading, proc.stdout + proc.stderr)
    return install_outcome, _outcome_from_returncode(proc.returncode), summary


def detect_skillxray_target(root: Path, max_depth: int = 6) -> str:
    """Port of action.yml's "Detect skill-shaped content" find pipeline:
    prune .git/node_modules anywhere, and if a SKILL.md file or a skills/
    or .claude/ directory turns up within max_depth levels, the whole
    root is the target (skillxray scans the repo, not just the hit).
    A faithful-enough port for real repo layouts, not a byte-exact
    reimplementation of every GNU find edge case; tests/test_checks.py
    exercises it against realistic fixtures."""
    root = Path(root)
    if not root.is_dir():
        return ""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
        if depth >= max_depth:
            dirnames[:] = []
            continue
        if "SKILL.md" in filenames:
            return str(root)
        if any(d in ("skills", ".claude") for d in dirnames):
            return str(root)
    return ""


def run_skillxray(
    root: Path,
    configured_path: str,
    fail_on: str,
    skillxray_ref: str,
    install_missing: bool,
) -> tuple[str, str | None, str, str]:
    """Returns (target, install_outcome, scan_outcome, summary) -- target
    is returned alongside the rest so a caller never has to re-run
    detect_skillxray_target() itself just to pass the right value to
    evaluate_gate.evaluate()."""
    heading = "skillxray (agent-skill scanner)"
    target = configured_path or detect_skillxray_target(root)
    if not target:
        return target, None, "skipped", (
            f"## {heading}\n\nskipped: no SKILL.md, skills/, or .claude/ found\n"
        )

    if importlib.util.find_spec("skillxray") is None:
        install_outcome = "failure"
        install_hint = f'pip install "git+https://github.com/munzzyy/skillxray@{skillxray_ref}"'
        if install_missing:
            ok = _pip_install([f"git+https://github.com/munzzyy/skillxray@{skillxray_ref}"])
            install_outcome = "success" if ok and importlib.util.find_spec("skillxray") is not None else "failure"
        if install_outcome != "success":
            return target, install_outcome, "skipped", _not_installed_section(heading, "skillxray", install_hint)
    else:
        install_outcome = "success"

    proc = subprocess.run(
        checks.skillxray_argv(target, fail_on),
        cwd=str(root), capture_output=True, text=True, **_DECODE,
    )
    summary = _fenced_section(heading, proc.stdout + proc.stderr)
    return target, install_outcome, _outcome_from_returncode(proc.returncode), summary
