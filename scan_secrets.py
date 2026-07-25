#!/usr/bin/env python3
"""Grep a working tree for high-confidence hardcoded credentials.

Standard library only. Walks a directory (or checks a single file), skips
binaries and anything past a size cap, and matches a short list of
high-precision credential formats: AWS access key IDs, GitHub and GitLab
tokens, OpenAI/Anthropic/Stripe API keys, and PEM private key blocks.

Matched values are never printed in full. Exit code 0 means clean, 1 means
at least one credential-shaped string was found, 2 means the scan itself
could not run (bad path, bad argument). With --fail-on-skip, a run that
skipped any file (too large, unreadable, binary) also exits 1, so an
under-scan can't slip through as a clean pass.
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


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    redacted: str


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


def iter_candidate_files(root: Path, excludes: list[str], pruned: list | None = None):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for d in dirnames:
            full = Path(dirpath) / d
            if d in SKIP_DIRS or (d in VENV_DIR_NAMES and _is_virtualenv(full)):
                if pruned is not None:
                    rel = Path(os.path.relpath(full, start=root)).as_posix()
                    pruned.append((rel + "/", "default-skip dir"))
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            fp = Path(dirpath) / name
            if fp.is_symlink():
                continue
            rel = os.path.relpath(fp, start=root)
            rel_posix = Path(rel).as_posix()
            if is_excluded(rel_posix, excludes):
                continue
            yield fp


def scan_file(fp: Path, rel_label: str, max_bytes: int):
    """Return (findings, skip_reason). skip_reason is None on a real scan."""
    try:
        size = fp.stat().st_size
    except OSError as exc:
        return [], f"stat error: {exc}"
    if size > max_bytes:
        return [], "too large"
    try:
        data = fp.read_bytes()
    except OSError as exc:
        return [], f"read error: {exc}"
    if is_binary(data):
        return [], "binary"

    # Decode UTF-16 (BOM or BOM-less) with the right codec so the credential
    # regexes see plain text rather than null-interleaved bytes; everything
    # else is treated as UTF-8.
    text = data.decode(detect_utf16(data) or "utf-8", errors="replace")
    offsets = _newline_offsets(text)
    findings = []
    for rule, pattern in PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding(
                path=rel_label,
                line=_line_number(offsets, m.start()),
                rule=rule,
                redacted=redact(m.group(0)),
            ))
    return findings, None


def scan(root: Path, excludes: list[str], max_bytes: int):
    findings: list[Finding] = []
    skipped: list[tuple[str, str]] = []
    scanned = 0
    is_single_file = root.is_file()
    for fp in iter_candidate_files(root, excludes, pruned=skipped):
        rel_label = fp.name if is_single_file else Path(os.path.relpath(fp, start=root)).as_posix()
        file_findings, reason = scan_file(fp, rel_label, max_bytes)
        if reason is not None:
            skipped.append((rel_label, reason))
            continue
        scanned += 1
        findings.extend(file_findings)
    return findings, skipped, scanned


def _skip_lines_human(skipped) -> list[str]:
    if not skipped:
        return []
    lines = [f"  {len(skipped)} path(s) not scanned:"]
    for path, reason in skipped:
        lines.append(f"    {path}: {reason}")
    return lines


def render_human(findings, skipped, scanned: int, fail_on_skip: bool = False) -> str:
    if not findings:
        if fail_on_skip and skipped:
            lines = [
                "scan_secrets: no credentials found, but "
                f"{len(skipped)} path(s) were skipped and --fail-on-skip is set "
                f"({scanned} file(s) scanned)"
            ]
        else:
            lines = [f"scan_secrets: no credentials found ({scanned} file(s) scanned)"]
    else:
        lines = [f"scan_secrets: {len(findings)} potential credential(s) found:"]
        for f in findings:
            lines.append(f"  {f.path}:{f.line}: {f.rule} ({f.redacted})")
    lines.extend(_skip_lines_human(skipped))
    return "\n".join(lines)


def render_summary(findings, skipped, scanned: int, fail_on_skip: bool = False) -> str:
    lines = ["## Secrets scan", ""]
    if not findings:
        if fail_on_skip and skipped:
            lines.append(
                f"FAIL: no credentials found, but {len(skipped)} path(s) were skipped "
                f"and --fail-on-skip is set ({scanned} file(s) scanned)"
            )
        else:
            lines.append(f"PASS: no credentials found ({scanned} file(s) scanned)")
    else:
        lines.append(f"FAIL: {len(findings)} potential credential(s) found ({scanned} file(s) scanned)")
        lines.append("")
        lines.append("| file | line | type | value |")
        lines.append("|---|---|---|---|")
        for f in findings:
            lines.append(f"| `{f.path}` | {f.line} | {f.rule} | `{f.redacted}` |")
    if skipped:
        # An under-scan must never be silent -- surface every path that was
        # not read (too large, binary, or a default-skip dir) and why, so a
        # credential hiding in one of them can't produce a clean-looking PASS
        # with no trace in the mode the action actually runs.
        lines.append("")
        lines.append(f"Skipped (not scanned): {len(skipped)} path(s)")
        for path, reason in skipped:
            lines.append(f"- `{path}`: {reason}")
    return "\n".join(lines) + "\n"


def render_json(findings, skipped, scanned: int, fail_on_skip: bool = False) -> str:
    payload = {
        "scanned": scanned,
        "findings": [
            {"path": f.path, "line": f.line, "rule": f.rule, "redacted": f.redacted}
            for f in findings
        ],
        "skipped": [{"path": p, "reason": r} for p, r in skipped],
        "fail_on_skip": fail_on_skip,
    }
    return json.dumps(payload, indent=2)


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
                    help="exit non-zero if any file was skipped (too large, unreadable, "
                         "binary), so an under-scan can't pass silently")
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

    findings, skipped, scanned = scan(root, args.exclude, args.max_bytes)

    # A skip only fails the run when the caller asked for it; the default
    # stays "report skips, but only findings fail" so existing callers keep
    # the exact same exit codes they had.
    failed = bool(findings) or (args.fail_on_skip and bool(skipped))

    if args.json:
        print(render_json(findings, skipped, scanned, args.fail_on_skip))
    elif args.summary:
        print(render_summary(findings, skipped, scanned, args.fail_on_skip), end="")
    elif not (args.quiet and not failed):
        print(render_human(findings, skipped, scanned, args.fail_on_skip))

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
