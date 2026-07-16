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

The gate runs live on [munzzyy/munzzyy](https://github.com/munzzyy/munzzyy/actions/workflows/gate.yml):
noslop and the secrets scan over the repo, zizmor over its workflow, and skillxray skipping
cleanly because there's nothing skill-shaped to scan.

## Running the gate locally

This repo also ships a small Python package, so you can run the exact same checks on your
own machine before you open a PR, instead of finding out from a red CI run:

```
git clone https://github.com/munzzyy/ci-safety-gate
cd ci-safety-gate
pip install -e .

cd /path/to/your-repo
ci-safety-gate --local
```

(or, from inside this checkout with no install at all: `python -m ci_safety_gate --local`.)

`--local` runs the same commands action.yml's composite steps run — noslop and zizmor over
your tracked files, skillxray if it finds `SKILL.md` / `skills/` / `.claude`, the bundled
secrets scan — against a directory you point it at (default `.`), hands the result to the
same `evaluate_gate.py` the action itself calls, and prints the same combined summary to your
terminal instead of `$GITHUB_STEP_SUMMARY`. Same verdict, same exit code.

Every `action.yml` input has a matching flag — `--no-noslop`, `--zizmor-min-severity`,
`--secrets-exclude`, and so on. Run `ci-safety-gate --help` for the full list. Defaults come
straight out of `action.yml` at run time rather than a hand-copied second set, so a version
bump or threshold change there shows up here for free.

A scanner that isn't installed fails loud instead of skipping quietly:

```
## zizmor (GitHub Actions security audit)

zizmor did not run (not installed): install with `pip install zizmor`, or re-run with
--install-missing to do it automatically.
```

Pass `--install-missing` and it runs the exact `pip install` action.yml's own install steps
run (same pins, same skillxray git ref) instead of just naming the command.

### Known limitations

- `--local` only works from a checkout of this repo (`git clone` + `pip install -e .`), since
  it reads its defaults straight out of the real `action.yml` on disk instead of a bundled
  copy. A real, non-editable PyPI wheel would need `action.yml` shipped as package data for
  this to keep working — a follow-up for whenever this package is actually published, not
  solved yet.
- The flags mirror `action.yml`'s inputs, but the literal commands each check runs
  (`ci_safety_gate/checks.py`) are still a second, hand-written copy of the bash in
  `action.yml` — rewriting the composite action to call into this package would close that
  gap for good, but that's a bigger, riskier change than this pass makes.
  `tests/test_checks.py` asserts every flag `checks.py` builds is still literally present in
  `action.yml`'s own bash, so the two failing to match is a test failure, not a silent drift.
- `--local` uses whatever Python, noslop, zizmor, and skillxray are already on your `PATH`
  (or installs them with `--install-missing`); it doesn't manage a separate pinned
  `python-version` the way the composite action does.

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
