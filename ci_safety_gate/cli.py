"""Command-line interface for ci_safety_gate.

`ci-safety-gate --local` runs the exact checks action.yml's composite
steps run -- same commands, same flags (checks.py), same defaults
(action_defaults.py reads them straight out of action.yml), and the same
verdict logic (evaluate_gate.py) -- against a directory on this machine,
and prints the combined summary to stdout instead of $GITHUB_STEP_SUMMARY.
That's what lets a PR author see the exact result CI will produce before
they ever push.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, action_defaults, runner


def _default(name: str, fallback: str) -> str:
    """action_defaults.default() straight from action.yml when it's found
    (a checkout or an editable install); a fixed fallback only so --help
    still renders something sane if it isn't (see action_defaults.py's
    docstring on why that can happen)."""
    try:
        return action_defaults.default(name)
    except action_defaults.ActionYamlNotFound:
        return fallback


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ci-safety-gate",
        description="Run munzzyy/ci-safety-gate's bundled checks locally, the same way CI runs them.",
    )
    p.add_argument("--local", action="store_true",
                    help="run the gate against a local directory (the only mode this CLI has today)")
    p.add_argument("path", nargs="?", default=".",
                    help="directory to gate, same as the workflow's checkout root (default: .)")
    p.add_argument("--install-missing", action="store_true",
                    help="pip install a missing tool the same way action.yml's own install steps do, "
                         "instead of just reporting it as not installed")
    p.add_argument("--version", action="version", version=f"ci-safety-gate {__version__}")

    p.add_argument("--no-secrets", action="store_true", help="skip the bundled secrets scan")
    p.add_argument("--secrets-path", default=_default("secrets-path", "."),
                    help="path the secrets scan walks, relative to `path`")
    p.add_argument("--secrets-exclude", action="append", default=[], metavar="GLOB",
                    help="glob to skip, relative to --secrets-path; repeatable")
    p.add_argument("--secrets-max-bytes", type=int,
                    default=int(_default("secrets-max-bytes", "2000000")),
                    help="skip files larger than this many bytes")

    p.add_argument("--no-noslop", action="store_true", help="skip noslop AI-slop detection")
    p.add_argument("--noslop-version", default=_default("noslop-version", "0.10.0"),
                    help="noslop-lint version to install with --install-missing")
    p.add_argument("--noslop-code-globs", default=_default("noslop-code-globs", "*.py *.js"),
                    help="space-separated git pathspec globs scored in code mode")
    p.add_argument("--noslop-docs-globs", default=_default("noslop-docs-globs", "*.md"),
                    help="space-separated git pathspec globs scored in prose mode")
    p.add_argument("--noslop-threshold", default=_default("noslop-threshold", ""),
                    help="score at/above which noslop fails (default: noslop's own default, 10)")

    p.add_argument("--no-zizmor", action="store_true", help="skip the zizmor GitHub Actions audit")
    p.add_argument("--zizmor-path", default=_default("zizmor-path", "."),
                    help="path zizmor audits, relative to `path`")
    p.add_argument("--zizmor-min-severity", default=_default("zizmor-min-severity", "medium"),
                    choices=("informational", "low", "medium", "high"),
                    help="minimum severity zizmor reports")
    p.add_argument("--zizmor-online", action="store_true",
                    help="allow zizmor's GitHub-API-backed checks (needs a token in the environment); "
                         "offline is the default, same as action.yml")

    p.add_argument("--no-skillxray", action="store_true", help="skip skillxray")
    p.add_argument("--skillxray-ref", default=_default("skillxray-ref", "v0.1.1"),
                    help="git tag of munzzyy/skillxray to install with --install-missing")
    p.add_argument("--skillxray-path", default=_default("skillxray-path", ""),
                    help="path to scan (default: auto-detect SKILL.md / skills/ / .claude, "
                         "skip cleanly if none exist)")
    p.add_argument("--skillxray-fail-on", default=_default("skillxray-fail-on", "high"),
                    choices=("critical", "high", "medium", "low", "none"),
                    help="minimum severity that fails skillxray")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.local:
        print("ci-safety-gate: nothing to do without --local (see --help)", file=sys.stderr)
        return 2

    try:
        import evaluate_gate  # top-level module shipped alongside this package (see pyproject.toml)
    except ImportError as exc:
        print(f"ci-safety-gate: can't import evaluate_gate.py: {exc}", file=sys.stderr)
        return 2

    root = Path(args.path)
    if not root.is_dir():
        print(f"ci-safety-gate: no such directory: {args.path}", file=sys.stderr)
        return 2

    sections = ["# CI Safety Gate\n"]

    secrets_outcome = "success"
    if not args.no_secrets:
        _, secrets_outcome, secrets_summary = runner.run_secrets(
            root, args.secrets_path, args.secrets_max_bytes, args.secrets_exclude,
        )
        sections.append(secrets_summary)

    install_noslop_outcome = noslop_outcome = "success"
    if not args.no_noslop:
        install_noslop_outcome, noslop_outcome, noslop_summary = runner.run_noslop(
            root, args.noslop_code_globs, args.noslop_docs_globs, args.noslop_threshold,
            args.noslop_version, args.install_missing,
        )
        sections.append(noslop_summary)

    install_zizmor_outcome = zizmor_outcome = "success"
    if not args.no_zizmor:
        install_zizmor_outcome, zizmor_outcome, zizmor_summary = runner.run_zizmor(
            root, args.zizmor_path, args.zizmor_min_severity, not args.zizmor_online,
            args.install_missing,
        )
        sections.append(zizmor_summary)

    skillxray_target = ""
    install_skillxray_outcome = skillxray_outcome = "success"
    if not args.no_skillxray:
        skillxray_target, install_skillxray_outcome, skillxray_outcome, skillxray_summary = runner.run_skillxray(
            root, args.skillxray_path, args.skillxray_fail_on, args.skillxray_ref, args.install_missing,
        )
        sections.append(skillxray_summary)

    results, passed = evaluate_gate.evaluate(
        secrets_enabled=not args.no_secrets,
        secrets_outcome=secrets_outcome,
        noslop_enabled=not args.no_noslop,
        install_noslop_outcome=install_noslop_outcome,
        noslop_outcome=noslop_outcome,
        zizmor_enabled=not args.no_zizmor,
        install_zizmor_outcome=install_zizmor_outcome,
        zizmor_outcome=zizmor_outcome,
        skillxray_enabled=not args.no_skillxray,
        skillxray_target=skillxray_target,
        install_skillxray_outcome=install_skillxray_outcome,
        skillxray_outcome=skillxray_outcome,
    )
    sections.append(evaluate_gate.render_summary(results, passed))

    print("\n".join(sections))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
