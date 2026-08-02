#!/usr/bin/env python3
"""Flag workflows that check out fork pull request code unsafely.

Standard library only, same as scan_secrets.py. Reads the workflow files
under a repo's .github/workflows and reports two things zizmor's
unpinned-uses audit cannot: an explicit `allow-unsafe-pr-checkout`, and an
actions/checkout pin that predates the safe-by-default change.

Background. actions/checkout v7 (2026-06-18) refuses by default to fetch
fork pull request code in a `pull_request_target` or `workflow_run`
workflow, and the opt-out input is deliberately named
`allow-unsafe-pr-checkout` so a reviewer or a linter can spot it. The
enforcement was backported to the supported majors on 2026-07-20, but a
workflow pinned to a specific SHA, minor or patch does NOT pick the
backport up. That is the awkward part: pinning by SHA is the right
supply-chain move and every hardening guide (this repo's own README
included) tells you to do it, so the repos following the best advice are
the ones still exposed.

Exit code 0 means nothing at or above the fail threshold, 1 means there
was, 2 means the scan itself could not run (bad path, bad argument). A
workflow file that cannot be read is reported as a high finding, never
passed over: a file nobody checked is not a file that is fine.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ("high", "medium", "low")
FAIL_ON_CHOICES = SEVERITIES + ("none",)

# A `pull_request_target` or `workflow_run` job runs with the base repo's
# permissions and secrets, which is what makes checking out fork code in
# one dangerous. Every other trigger is out of scope for this check.
RISKY_TRIGGERS = ("pull_request_target", "workflow_run")

_CHECKOUT_RE = re.compile(r"""uses:\s*['"]?actions/checkout@([^\s'"#]+)""")
_UNSAFE_INPUT_RE = re.compile(r"^\s*allow-unsafe-pr-checkout\s*:\s*(.+?)\s*$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_MAJOR_TAG_RE = re.compile(r"^v\d+$")
_EXACT_TAG_RE = re.compile(r"^v\d+\.\d+(\.\d+)?$")

# A `ref:` that resolves to the pull request's own head is the difference
# between "this job checked out my repo" and "this job ran the fork's
# code". It is what the safe-by-default change exists to block.
_PR_HEAD_HINTS = ("github.event.pull_request", "github.event.workflow_run",
                  "head.sha", "head.ref", "head_sha", "head_branch")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    severity: str
    rule: str
    message: str


def _severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def workflow_files(root: Path) -> list[Path]:
    """Every workflow file under .github/workflows, sorted.

    A file given directly on the command line is used as-is, so a single
    workflow can be checked without a repo around it.
    """
    if root.is_file():
        return [root]
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return []
    found = [p for p in workflows.iterdir()
             if p.is_file() and p.suffix in (".yml", ".yaml")]
    return sorted(found)


def trigger_block(lines: list[str]) -> str:
    """The text of the workflow's `on:` block, inline or indented form.

    A regex reader rather than a YAML parse, for the same reason
    action_defaults.py is one: this package holds a zero-dependency floor.
    It only has to answer one question, and it answers it conservatively.
    """
    for i, line in enumerate(lines):
        match = re.match(r"^(?:on|['\"]on['\"]|true)\s*:(.*)$", line)
        if not match:
            continue
        rest = match.group(1).strip()
        if rest and not rest.startswith("#"):
            return rest  # on: [push, pull_request_target]
        block = []
        for follow in lines[i + 1:]:
            if follow.strip() and not follow.startswith((" ", "\t")):
                break
            block.append(follow)
        return "\n".join(block)
    return ""


def has_risky_trigger(lines: list[str]) -> bool:
    block = trigger_block(lines)
    return any(re.search(rf"\b{trigger}\b", block) for trigger in RISKY_TRIGGERS)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def step_block(lines: list[str], index: int) -> str:
    """The lines belonging to the step whose `uses:` is at `index`.

    Used to see whether that same step also passes a `ref:`. Ends at the
    next list item at the same indent, or at any less-indented line.
    """
    base = _indent(lines[index])
    collected = [lines[index]]
    for line in lines[index + 1:]:
        if not line.strip():
            collected.append(line)
            continue
        indent = _indent(line)
        if indent < base:
            break
        if indent == base and line.lstrip().startswith("- "):
            break
        collected.append(line)
    return "\n".join(collected)


def checks_out_pr_head(block: str) -> bool:
    for line in block.splitlines():
        if re.match(r"^\s*ref\s*:", line) and any(h in line for h in _PR_HEAD_HINTS):
            return True
    return False


def pin_kind(ref: str) -> str:
    """How an actions/checkout ref is pinned.

    "sha" and "exact-tag" are the two the 2026-07-20 backport does not
    reach; "major-tag" and "moving" follow the action's default branch or
    a tag its maintainers move, so they got the fix automatically.
    """
    if _SHA_RE.match(ref):
        return "sha"
    if _MAJOR_TAG_RE.match(ref):
        return "major-tag"
    if _EXACT_TAG_RE.match(ref):
        return "exact-tag"
    return "moving"


def scan_text(rel_path: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []

    for i, line in enumerate(lines, start=1):
        match = _UNSAFE_INPUT_RE.match(line)
        if not match:
            continue
        value = match.group(1).split("#", 1)[0].strip().strip("'\"").lower()
        if value == "false":
            continue
        findings.append(Finding(
            path=rel_path, line=i, severity="high", rule="allow-unsafe-pr-checkout",
            message=(
                "this step opts out of actions/checkout's refusal to fetch fork "
                "pull request code. Anything the fork committed then runs in a job "
                f"holding this repo's secrets (value: {value!r})"
            ),
        ))

    if not has_risky_trigger(lines):
        return findings

    for i, line in enumerate(lines, start=1):
        match = _CHECKOUT_RE.search(line)
        if not match:
            continue
        ref = match.group(1)
        kind = pin_kind(ref)
        if kind in ("major-tag", "moving"):
            continue
        block = step_block(lines, i - 1)
        pr_head = checks_out_pr_head(block)
        findings.append(Finding(
            path=rel_path, line=i, severity="high" if pr_head else "medium",
            rule="stale-checkout-pin",
            message=(
                f"this workflow runs on {' or '.join(RISKY_TRIGGERS)} and pins "
                f"actions/checkout to {ref}. The safe-by-default refusal to fetch "
                "fork pull request code, backported 2026-07-20, does not reach a "
                "SHA, minor or patch pin"
                + (" and this step checks out the pull request head, so fork code "
                   "runs in a privileged job unless the pin already includes the fix"
                   if pr_head else
                   ". Move the pin forward, or check that this SHA is at or past "
                   "the fix")
            ),
        ))

    return sorted(findings, key=lambda f: f.line)


def scan(root: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    files = workflow_files(root)
    for path in files:
        try:
            rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        except ValueError:
            rel = path.as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # Fail loud: a workflow nobody could read is not a workflow
            # that passed.
            findings.append(Finding(
                path=rel, line=1, severity="high", rule="unreadable-workflow",
                message=f"could not read this workflow, so it was not checked ({exc})",
            ))
            continue
        findings.extend(scan_text(rel, text))
    return findings, len(files)


def failing(findings: list[Finding], fail_on: str) -> list[Finding]:
    if fail_on == "none":
        return []
    limit = _severity_rank(fail_on)
    return [f for f in findings if _severity_rank(f.severity) <= limit]


def _headline(findings: list[Finding], files: int) -> str:
    if not findings:
        return f"no unsafe fork checkout found ({files} workflow file(s) read)"
    return f"{len(findings)} checkout problem(s) found ({files} workflow file(s) read)"


def render_human(findings: list[Finding], files: int) -> str:
    lines = [f"checkout_safety: {_headline(findings, files)}"]
    for f in findings:
        lines.append(f"  {f.path}:{f.line}: [{f.severity}] {f.rule}: {f.message}")
    return "\n".join(lines)


def render_summary(findings: list[Finding], files: int, fail_on: str) -> str:
    lines = ["## Checkout safety", ""]
    verdict = "FAIL" if failing(findings, fail_on) else "PASS"
    lines.append(f"{verdict}: {_headline(findings, files)}")
    if findings:
        lines.append("")
        lines.append("| file | line | severity | check | detail |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            lines.append(
                f"| `{f.path}` | {f.line} | {f.severity} | {f.rule} | {f.message} |"
            )
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding], files: int, fail_on: str) -> str:
    payload = {
        "workflow_files": files,
        "fail_on": fail_on,
        "findings": [
            {"path": f.path, "line": f.line, "severity": f.severity,
             "rule": f.rule, "message": f.message}
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="checkout_safety.py",
        description="Flag workflows that check out fork pull request code unsafely.",
    )
    p.add_argument("path", nargs="?", default=".",
                    help="repo root, or a single workflow file (default: .)")
    p.add_argument("--fail-on", default="high", choices=FAIL_ON_CHOICES,
                    help="minimum severity that fails the run (default: high)")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--summary", action="store_true", help="markdown for GITHUB_STEP_SUMMARY")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"checkout_safety: no such path: {args.path}", file=sys.stderr)
        return 2

    findings, files = scan(root)
    failed = bool(failing(findings, args.fail_on))

    if args.json:
        print(render_json(findings, files, args.fail_on))
    elif args.summary:
        print(render_summary(findings, files, args.fail_on), end="")
    else:
        print(render_human(findings, files))

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
