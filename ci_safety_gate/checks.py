"""Build the exact argv each check runs -- one place, reused by runner.py
and asserted against action.yml's real bash by tests/test_checks.py.

These functions return the tool's own argv (the binary name plus flags,
not the file list), since zizmor takes its path argument after the flags.
Keeping "which flags" separate from "which files" is what lets the parity
test check flags without needing a working git checkout.
"""

from __future__ import annotations

import sys


def secrets_argv(path: str, max_bytes: int, excludes: list[str],
                 fail_on_skip: bool = False, annotations: bool = False) -> list[str]:
    """Matches action.yml's "Secrets scan" step exactly: path, then
    --max-bytes, --summary, one --exclude per pattern, --fail-on-skip when
    the secrets-fail-on-skip input is on, and --github-annotations last.

    Annotations stay off by default here: they are GitHub workflow
    commands, so they are noise in a terminal and only mean anything in a
    job log."""
    argv = [path, "--max-bytes", str(max_bytes), "--summary"]
    for pattern in excludes:
        argv += ["--exclude", pattern]
    if fail_on_skip:
        argv.append("--fail-on-skip")
    if annotations:
        argv.append("--github-annotations")
    return argv


def zizmor_argv(path: str, min_severity: str, offline: bool,
                persona: str = "auditor") -> list[str]:
    """Matches action.yml's zizmor step exactly, including flag order."""
    argv = ["zizmor", "--no-progress", "--color", "never"]
    if offline:
        argv.append("--offline")
    argv += ["--persona", persona, "--min-severity", min_severity, path]
    return argv


def zizmor_pip_spec(version: str) -> str:
    """The exact string action.yml's "Install zizmor" step pip-installs:
    the package name with the zizmor-version specifier appended, e.g.
    "zizmor>=1.28.0". Keeping this next to the argv builders is what stops
    --install-missing from quietly installing an unpinned zizmor while the
    action installs a floored one."""
    return f"zizmor{version}"


def skillxray_argv(target: str, fail_on: str) -> list[str]:
    """Matches action.yml's skillxray step, which runs it as `python3 -m
    skillxray` rather than a standalone binary (it isn't on PyPI yet)."""
    return [sys.executable, "-m", "skillxray", target, "--fail-on", fail_on, "--no-color"]
