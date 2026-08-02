#!/usr/bin/env python3
"""Grep a working tree for high-confidence hardcoded credentials.

Standard library only. Walks a directory (or checks a single file), skips
binaries and anything past a size cap, and matches a short list of
high-precision credential formats: AWS access key IDs, GitHub and GitLab
tokens, OpenAI/Anthropic/Stripe API keys, and PEM private key blocks.

Matched values are never printed in full. Exit code 0 means clean, 1 means
at least one credential-shaped string was found, 2 means the scan itself
could not run (bad path, bad argument). With --fail-on-skip, a run that
left any file unread (too large, unreadable, binary, a symlink) also exits
1, so an under-scan can't slip through as a clean pass.

Two different things get called a "skip" and they are kept apart on
purpose. A policy skip is a directory this tool refuses to walk by design
(.git, __pycache__, a real virtualenv) or a path the caller excluded: that
is the scan working as configured, so it is reported quietly and never
fails the run. A path that could not be read is the dangerous one, because
a credential could be sitting in it: that is reported prominently and is
what --fail-on-skip acts on.
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_BYTES = 2_000_000

# Directory names skipped everywhere, regardless of --exclude. Kept to
# unambiguous VCS/tool/cache dirs -- a committed secret never belongs in
# these, and skipping them keeps the scan fast. dist/ and build/ are
# deliberately NOT here: committed bundles are exactly where a leaked key
# lands, so they get scanned.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
}

# Names that get skipped only when the directory actually looks like a
# Python virtualenv. A real venv holds no committed secrets worth reading;
# a project directory that merely happens to be named "env" (a common
# non-virtualenv config dir) must still be scanned.
VENV_DIR_NAMES = {".venv", "venv", "env"}

# (rule name, compiled pattern). Kept small and specific so false positives
# stay rare, since a noisy scanner trains people to ignore it.
PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("GitLab personal access token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]


# A finding on a line carrying one of these markers, or on the line
# directly below one, is suppressed. Dumb substring matching keeps it
# language-agnostic: any comment syntax works. The second spelling is the
# de-facto standard detect-secrets uses, so a repo already annotated for
# that tool needs no second set of comments.
ALLOWLIST_MARKERS = ("ci-safety-gate: allow", "pragma: allowlist secret")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    redacted: str


@dataclass(frozen=True)
class ScanResult:
    """What one scan produced.

    `unread` and `policy_skips` are deliberately separate lists. `unread`
    is every path the scan could not read (too large, binary, a symlink,
    an OS error) -- a credential could be hiding in any of them, so it is
    the list --fail-on-skip acts on. `policy_skips` is the directories and
    globs the scan is configured to leave alone, which is normal operation
    and never a reason to fail.
    """

    findings: list[Finding]
    unread: list[tuple[str, str]]
    policy_skips: list[tuple[str, str]]
    scanned: int
    suppressed: int


def redact(value: str) -> str:
    """Show just enough to identify the finding without leaking the secret."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _line_number(newline_offsets: list[int], index: int) -> int:
    return bisect.bisect_right(newline_offsets, index) + 1


def _newline_offsets(text: str) -> list[int]:
    return [i for i, ch in enumerate(text) if ch == "\n"]


# A BOM is the reliable signal for "this is UTF-16 text", not "this is
# binary" -- ASCII-range UTF-16 is roughly half \x00 bytes by construction
# (each codepoint is stored as its byte plus a 0x00), which looks exactly
# like binary data to a raw null-byte check. Windows tooling (PowerShell,
# some .env writers) emits files this way.
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def is_utf16_bom(data: bytes) -> bool:
    return data[:2] in _UTF16_BOMS


def detect_utf16(data: bytes) -> str | None:
    """Return the codec to decode data with if it looks like UTF-16 text,
    else None.

    A BOM is the definitive signal. Without one, ASCII-range UTF-16 still
    gives itself away: every character's 0x00 byte lands at a consistent
    offset parity -- odd for little-endian, even for big-endian. Some
    Windows tooling writes UTF-16 with no BOM at all, so a raw null-byte
    check alone would wrongly call it binary and skip it.
    """
    if is_utf16_bom(data):
        return "utf-16"  # codec auto-detects LE/BE from the BOM and strips it
    sample = data[:8192]
    pairs = len(sample) // 2
    if pairs < 8:
        return None
    odd_nulls = sample[1::2].count(0)
    even_nulls = sample[0::2].count(0)
    if odd_nulls >= pairs * 0.9 and even_nulls == 0:
        return "utf-16-le"
    if even_nulls >= pairs * 0.9 and odd_nulls == 0:
        return "utf-16-be"
    return None


def is_binary(data: bytes) -> bool:
    if detect_utf16(data) is not None:
        return False
    return b"\x00" in data[:8192]


def _is_virtualenv(path: Path) -> bool:
    return (path / "pyvenv.cfg").exists() or (path / "bin" / "activate").exists()


def is_excluded(rel_posix: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel_posix, pat) for pat in patterns)


def iter_candidate_files(root: Path, excludes: list[str],
                          policy_skips: list | None = None,
                          unread: list | None = None):
    """Yield every file the scan should read.

    Anything not yielded lands in one of the two lists, never nowhere:
    directories and globs the scan is configured to leave alone go in
    `policy_skips`, and symlinks go in `unread` because they are content
    this tool chose not to follow but cannot claim to have checked.
    """
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for d in dirnames:
            full = Path(dirpath) / d
            rel_dir = Path(os.path.relpath(full, start=root)).as_posix() + "/"
            if d in SKIP_DIRS or (d in VENV_DIR_NAMES and _is_virtualenv(full)):
                if policy_skips is not None:
                    policy_skips.append((rel_dir, "default-skip dir"))
                continue
            if full.is_symlink():
                # os.walk(followlinks=False) would not descend into this
                # anyway. Recording it is the difference between "we chose
                # not to follow it" and "it vanished from the report".
                if unread is not None:
                    unread.append((rel_dir, "symlink (not followed)"))
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            fp = Path(dirpath) / name
            rel = os.path.relpath(fp, start=root)
            rel_posix = Path(rel).as_posix()
            if fp.is_symlink():
                # Following symlinks would let a committed link reach
                # outside the scanned root, so the file stays unread -- but
                # it gets reported, because a token behind a symlink is
                # still a token nobody looked at.
                if unread is not None:
                    unread.append((rel_posix, "symlink (not followed)"))
                continue
            if is_excluded(rel_posix, excludes):
                if policy_skips is not None:
                    policy_skips.append((rel_posix, "matched an exclude glob"))
                continue
            yield fp


def _is_allowlisted(lines: list[str], line_no: int) -> bool:
    """True when the finding's own line, or the line directly above it,
    carries an allowlist marker. Put another way: a marker covers the line
    it sits on and the one after it, which handles both
    `KEY = "..."  # ci-safety-gate: allow` and a comment above a line that
    has nowhere to put one (JSON, a YAML value). Two lines is the whole
    rule, so a marker can never quietly cover a block."""
    for candidate in (line_no, line_no - 1):
        if 1 <= candidate <= len(lines):
            line = lines[candidate - 1]
            if any(marker in line for marker in ALLOWLIST_MARKERS):
                return True
    return False


def scan_file(fp: Path, rel_label: str, max_bytes: int):
    """Return (findings, suppressed, skip_reason). skip_reason is None on a
    real scan; suppressed counts findings an inline allowlist marker hid."""
    try:
        size = fp.stat().st_size
    except OSError as exc:
        return [], 0, f"stat error: {exc}"
    if size > max_bytes:
        return [], 0, "too large"
    try:
        data = fp.read_bytes()
    except OSError as exc:
        return [], 0, f"read error: {exc}"
    if is_binary(data):
        return [], 0, "binary"

    # Decode UTF-16 (BOM or BOM-less) with the right codec so the credential
    # regexes see plain text rather than null-interleaved bytes; everything
    # else is treated as UTF-8.
    text = data.decode(detect_utf16(data) or "utf-8", errors="replace")
    offsets = _newline_offsets(text)
    lines = text.split("\n")
    findings = []
    suppressed = 0
    for rule, pattern in PATTERNS:
        for m in pattern.finditer(text):
            line_no = _line_number(offsets, m.start())
            if _is_allowlisted(lines, line_no):
                suppressed += 1
                continue
            findings.append(Finding(
                path=rel_label,
                line=line_no,
                rule=rule,
                redacted=redact(m.group(0)),
            ))
    return findings, suppressed, None


def scan(root: Path, excludes: list[str], max_bytes: int) -> ScanResult:
    findings: list[Finding] = []
    unread: list[tuple[str, str]] = []
    policy_skips: list[tuple[str, str]] = []
    scanned = 0
    suppressed = 0
    is_single_file = root.is_file()
    for fp in iter_candidate_files(root, excludes, policy_skips=policy_skips, unread=unread):
        rel_label = fp.name if is_single_file else Path(os.path.relpath(fp, start=root)).as_posix()
        file_findings, file_suppressed, reason = scan_file(fp, rel_label, max_bytes)
        if reason is not None:
            unread.append((rel_label, reason))
            continue
        scanned += 1
        suppressed += file_suppressed
        findings.extend(file_findings)
    return ScanResult(findings, unread, policy_skips, scanned, suppressed)


def _policy_skip_line(policy_skips) -> str:
    """One line, however many directories got pruned. A repo with fifty
    nested __pycache__ dirs used to print fifty lines above a PASS, which
    reads like the scan gave up rather than like it did its job."""
    names = [path for path, _ in policy_skips[:6]]
    more = len(policy_skips) - len(names)
    listed = ", ".join(names)
    if more > 0:
        listed += f", and {more} more"
    return f"{len(policy_skips)} path(s) skipped by policy: {listed}"


def render_human(result: ScanResult, fail_on_skip: bool = False) -> str:
    if not result.findings:
        if fail_on_skip and result.unread:
            lines = [
                "scan_secrets: no credentials found, but "
                f"{len(result.unread)} path(s) could not be read and --fail-on-skip "
                f"is set ({result.scanned} file(s) scanned)"
            ]
        else:
            lines = [f"scan_secrets: no credentials found ({result.scanned} file(s) scanned)"]
    else:
        lines = [f"scan_secrets: {len(result.findings)} potential credential(s) found:"]
        for f in result.findings:
            lines.append(f"  {f.path}:{f.line}: {f.rule} ({f.redacted})")
    if result.suppressed:
        lines.append(f"  {result.suppressed} finding(s) suppressed by an inline allowlist marker")
    if result.unread:
        lines.append(f"  {len(result.unread)} path(s) not scanned:")
        for path, reason in result.unread:
            lines.append(f"    {path}: {reason}")
    if result.policy_skips:
        lines.append("  " + _policy_skip_line(result.policy_skips))
    return "\n".join(lines)


def render_summary(result: ScanResult, fail_on_skip: bool = False) -> str:
    lines = ["## Secrets scan", ""]
    if not result.findings:
        if fail_on_skip and result.unread:
            lines.append(
                f"FAIL: no credentials found, but {len(result.unread)} path(s) could not "
                f"be read and --fail-on-skip is set ({result.scanned} file(s) scanned)"
            )
        else:
            lines.append(f"PASS: no credentials found ({result.scanned} file(s) scanned)")
    else:
        lines.append(
            f"FAIL: {len(result.findings)} potential credential(s) found "
            f"({result.scanned} file(s) scanned)"
        )
        lines.append("")
        lines.append("| file | line | type | value |")
        lines.append("|---|---|---|---|")
        for f in result.findings:
            lines.append(f"| `{f.path}` | {f.line} | {f.rule} | `{f.redacted}` |")
    if result.suppressed:
        # Suppression that nobody can see is just a blind spot with extra
        # steps, so the count is always on the report.
        lines.append("")
        lines.append(f"{result.suppressed} finding(s) suppressed by an inline allowlist marker")
    if result.unread:
        # An under-scan must never be silent: every path that could not be
        # read gets named with its reason, so a credential hiding in one of
        # them can't produce a clean-looking PASS with no trace.
        lines.append("")
        lines.append(f"Not scanned (could not be read): {len(result.unread)} path(s)")
        for path, reason in result.unread:
            lines.append(f"- `{path}`: {reason}")
    if result.policy_skips:
        lines.append("")
        lines.append("<details><summary>" + _policy_skip_line(result.policy_skips) + "</summary>")
        lines.append("")
        for path, reason in result.policy_skips:
            lines.append(f"- `{path}`: {reason}")
        lines.append("")
        lines.append("</details>")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult, fail_on_skip: bool = False) -> str:
    payload = {
        "scanned": result.scanned,
        "findings": [
            {"path": f.path, "line": f.line, "rule": f.rule, "redacted": f.redacted}
            for f in result.findings
        ],
        "skipped": [{"path": p, "reason": r} for p, r in result.unread],
        "skipped_by_policy": [{"path": p, "reason": r} for p, r in result.policy_skips],
        "suppressed": result.suppressed,
        "fail_on_skip": fail_on_skip,
    }
    return json.dumps(payload, indent=2)


def _escape_property(value: str) -> str:
    return (value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                 .replace(":", "%3A").replace(",", "%2C"))


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_annotations(result: ScanResult, fail_on_skip: bool = False) -> list[str]:
    """GitHub workflow commands, one per finding, so a reviewer sees the hit
    on the diff instead of having to open the job summary.

    These go to stderr, not stdout: the action pipes this script's stdout
    straight into $GITHUB_STEP_SUMMARY, and a workflow command buried in a
    markdown file does nothing at all.
    """
    lines = []
    for f in result.findings:
        lines.append(
            f"::error file={_escape_property(f.path)},line={f.line},"
            f"title=ci-safety-gate::{_escape_data(f.rule)} ({_escape_data(f.redacted)})"
        )
    if fail_on_skip:
        for path, reason in result.unread:
            lines.append(
                f"::warning file={_escape_property(path)},title=ci-safety-gate"
                f"::not scanned ({_escape_data(reason)}), and --fail-on-skip is set"
            )
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scan_secrets.py",
        description="Grep a working tree for high-confidence hardcoded credentials.",
    )
    p.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: .)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="glob (matched against the relative path) to skip; repeatable")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help=f"skip files larger than this (default: {DEFAULT_MAX_BYTES})")
    p.add_argument("--fail-on-skip", action="store_true",
                    help="exit non-zero if any file could not be read (too large, "
                         "unreadable, binary, a symlink), so an under-scan can't pass "
                         "silently; directories skipped by policy never fail the run")
    p.add_argument("--github-annotations", action="store_true",
                    help="write a GitHub workflow command per finding to stderr, so the "
                         "finding shows up on the diff in Files Changed")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--summary", action="store_true", help="markdown for GITHUB_STEP_SUMMARY")
    p.add_argument("--quiet", action="store_true", help="print nothing on a clean scan")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.max_bytes <= 0:
        print("scan_secrets: --max-bytes must be a positive integer", file=sys.stderr)
        return 2

    root = Path(args.path)
    if not root.exists():
        print(f"scan_secrets: no such path: {args.path}", file=sys.stderr)
        return 2

    result = scan(root, args.exclude, args.max_bytes)

    # Only an unread path can fail the run, and only when the caller asked
    # for it. A policy skip is the scan doing what it was told, so
    # --fail-on-skip against any real checkout (which always has a .git/)
    # has to stay usable rather than fail every time.
    failed = bool(result.findings) or (args.fail_on_skip and bool(result.unread))

    if args.github_annotations:
        for line in render_annotations(result, args.fail_on_skip):
            print(line, file=sys.stderr)

    if args.json:
        print(render_json(result, args.fail_on_skip))
    elif args.summary:
        print(render_summary(result, args.fail_on_skip), end="")
    elif not (args.quiet and not failed):
        print(render_human(result, args.fail_on_skip))

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
