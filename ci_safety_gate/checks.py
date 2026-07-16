"""Build the exact argv each check runs -- one place, reused by runner.py
and asserted against action.yml's real bash by tests/test_checks.py.

These functions return the tool's own argv (the binary name plus flags,
not the file list), since noslop and zizmor take file/dir arguments after
their flags and runner.py appends those once it knows which files git
tracks. Keeping "which flags" separate from "which files" is what lets the
parity test check flags without needing a working git checkout.
"""

from __future__ import annotations

import sys


def secrets_argv(path: str, max_bytes: int, excludes: list[str]) -> list[str]:
    """Matches action.yml's "Secrets scan" step exactly: path, then
    --max-bytes, --summary, then one --exclude per pattern."""
    argv = [path, "--max-bytes", str(max_bytes), "--summary"]
    for pattern in excludes:
        argv += ["--exclude", pattern]
    return argv


def noslop_code_argv(threshold: str) -> list[str]:
    """Matches action.yml's noslop step's first invocation (--code)."""
    argv = ["noslop", "--no-config", "--code"]
    if threshold:
        argv += ["--threshold", threshold]
    return argv


def noslop_docs_argv(threshold: str) -> list[str]:
    """Matches action.yml's noslop step's second invocation (--markdown)."""
    argv = ["noslop", "--no-config", "--markdown"]
    if threshold:
        argv += ["--threshold", threshold]
    return argv


def zizmor_argv(path: str, min_severity: str, offline: bool) -> list[str]:
    """Matches action.yml's zizmor step exactly, including flag order."""
    argv = ["zizmor", "--no-progress", "--color", "never"]
    if offline:
        argv.append("--offline")
    argv += ["--min-severity", min_severity, path]
    return argv


def skillxray_argv(target: str, fail_on: str) -> list[str]:
    """Matches action.yml's skillxray step, which runs it as `python3 -m
    skillxray` rather than a standalone binary (it isn't on PyPI yet)."""
    return [sys.executable, "-m", "skillxray", target, "--fail-on", fail_on, "--no-color"]
