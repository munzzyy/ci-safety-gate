"""The package version, pyproject's version, the changelog and the docs
that repeat them must agree.

`ci-safety-gate --version` printed 0.1.0 for a build fourteen commits past
the v0.1.0 tag that had removed a whole check, which is actively
misleading in a bug report.
"""

from __future__ import annotations

import re
from pathlib import Path

import ci_safety_gate
import scan_secrets

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


# A new secrets rule fails here until it has an entry and the README names it.
_README_WORD = {
    "AWS access key ID": "AWS",
    "GitHub token": "GitHub",
    "GitHub fine-grained PAT": "GitHub",
    "GitLab personal access token": "GitLab",
    "Anthropic API key": "Anthropic",
    "OpenAI API key": "OpenAI",
    "Stripe secret key": "Stripe",
    "Slack token": "Slack",
    "Google API key": "Google",
    "npm access token": "npm",
    "Twilio API key": "Twilio",
    "private key block": "private key",
}


def _readme_secrets_bullet() -> str:
    text = (_ROOT / "README.md").read_text(encoding="utf-8")
    start = text.index("- **secrets**")
    return text[start:text.index("\n\n", start)]


def test_the_readme_names_every_secrets_pattern():
    bullet = _readme_secrets_bullet()
    for rule, _ in scan_secrets.PATTERNS:
        assert rule in _README_WORD, f"add {rule!r} to _README_WORD and name it in the README"
        assert _README_WORD[rule] in bullet, f"README's secrets bullet doesn't name {rule!r}"


def test_usage_examples_pin_the_current_version():
    want = f"v{ci_safety_gate.__version__}"
    for name in ("README.md", "examples/workflow.yml"):
        text = (_ROOT / name).read_text(encoding="utf-8")
        refs = re.findall(r"munzzyy/ci-safety-gate@(v[^\s'\"#]+)", text)
        assert refs, f"{name} has no munzzyy/ci-safety-gate@v... reference"
        assert set(refs) == {want}, f"{name} pins {sorted(set(refs))}, package is {want}"
