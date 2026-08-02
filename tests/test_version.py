"""The package version, pyproject's version and the changelog must agree.

`ci-safety-gate --version` printed 0.1.0 for a build fourteen commits past
the v0.1.0 tag that had removed a whole check, which is actively
misleading in a bug report.
"""

from __future__ import annotations

import re
from pathlib import Path

import ci_safety_gate

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml has no version this reader recognizes"
    return match.group(1)


def test_package_version_matches_pyproject():
    assert ci_safety_gate.__version__ == _pyproject_version()


def test_changelog_has_a_section_for_the_current_version():
    text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {ci_safety_gate.__version__}" in text
