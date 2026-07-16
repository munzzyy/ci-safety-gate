# ci-safety-gate

[![CI](https://github.com/munzzyy/ci-safety-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/munzzyy/ci-safety-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

One GitHub Action that runs the checks an AI-era repo wants and reports them as a single
pass/fail gate with a combined summary. It bundles AI-slop detection, a GitHub Actions
security audit, an agent-skill scanner, and a bundled secrets grep, so a workflow adds one
step instead of wiring four.

You still get four separate reports; they just show up under one job instead of four, and
one bad finding anywhere fails the whole gate.

## Usage

```yaml
- uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
- uses: munzzyy/ci-safety-gate@v0.1.0
```

That's it. Every check defaults to on. A full example, including a hardened checkout step,
is at [`examples/workflow.yml`](examples/workflow.yml).

## What each check does

- **noslop** (`noslop-lint` on PyPI) — flags AI-written-code and AI-slop tells. Runs code
  mode over your source and prose mode over your docs.
- **zizmor** — audits `.github/workflows` and any `action.yml` for GitHub Actions
  vulnerabilities: template injection, unpinned third-party actions, missing
  `persist-credentials: false`, and the like.
- **skillxray** — scans `SKILL.md` files, Claude Code plugins, and MCP bundles for prompt
  injection, hidden Unicode, dangerous commands, and leaked secrets. If your repo has none
  of that, this step detects it and skips cleanly instead of failing on nothing to scan.
- **secrets** (bundled, `scan_secrets.py`, no dependency) — greps the working tree for
  AWS access key IDs, GitHub and GitLab tokens, OpenAI/Anthropic/Stripe keys, and PEM
  private key blocks. Matched values are redacted before they ever hit the log.

## Toggling checks

Every check is its own input, `"true"` by default:

```yaml
- uses: munzzyy/ci-safety-gate@v0.1.0
  with:
    skillxray: "false"    # skip if you know you have no skill/plugin content
    zizmor-min-severity: "high"
    noslop-code-globs: "*.py *.ts"
    secrets-exclude: "tests/fixtures/*"
```

Full input list is in [`action.yml`](action.yml): paths and globs per check, a fail
threshold for skillxray and zizmor, a score threshold for noslop, and a size cap for the
secrets scan.

## The combined summary

Every enabled check writes its own section to `$GITHUB_STEP_SUMMARY`, so a PR shows one
report with a heading per check, followed by a `## Result` section that lists pass/fail/
skipped per check and the overall verdict. The job step itself fails if any enabled check
failed; a skipped check (disabled, or skillxray finding nothing to scan) never fails it.

## What this does not do

- It's an orchestrator, not a detector. The actual detection quality is whatever noslop,
  zizmor, and skillxray ship; this action just installs them, runs them the same way every
  time, and merges the output. A finding a bundled tool misses, this gate misses too.
- skillxray installs from a pinned git tag (`git+https://github.com/munzzyy/skillxray@v0.1.1`),
  not from PyPI, because it isn't published there yet. Point `skillxray-ref` at a newer tag
  once one exists, or drop this once it's on PyPI.
- The bundled secrets scan is deliberately small: eight high-precision patterns, no entropy
  analysis, no git-history scan. It's a floor, not a replacement for gitleaks or a real
  secret manager.
- zizmor's default here is `--offline`, so its checks that need the GitHub API (like whether
  a pinned SHA still matches its tag) are off unless you set `zizmor-offline: "false"` and
  give the job a token.

## Exit codes

The action's own `result` output is `"pass"` or `"fail"`. The job step itself exits non-zero
on `"fail"`, which is what actually fails your workflow; the output exists for a caller that
wants to branch on it instead.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every `${{ }}` expression that touches repo content
has to go through an `env:` block, not a direct string interpolation; zizmor enforces this on
the action's own workflow.

## License

MIT — free to use, change, and ship, commercial or not. See [LICENSE](LICENSE).

## Support

If the gate caught something before it merged, [sponsoring](https://github.com/sponsors/munzzyy) is what keeps it maintained.
