# ci-safety-gate

[![CI](https://github.com/munzzyy/ci-safety-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/munzzyy/ci-safety-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

One GitHub Action that runs the checks a modern repo wants and reports them as a single
pass/fail gate with a combined summary. It bundles a GitHub Actions security audit, an
agent-skill scanner, a fork pull request checkout check, and a bundled secrets grep, so a
workflow adds one step instead of wiring four.

You still get four separate reports; they just show up under one job instead of four, and
one bad finding anywhere fails the whole gate.

## Usage

```yaml
- uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
- uses: munzzyy/ci-safety-gate@v0.1.1
```

That's it. Every check defaults to on. A full example, including a hardened checkout step,
is at [`examples/workflow.yml`](examples/workflow.yml).

Do not use `v0.1.0`. That tag predates the removal of a check that pip-installed a package
name which no longer exists on PyPI, so the name is unclaimed and anyone can register it.

## What each check does

- **zizmor** audits `.github/workflows` and any `action.yml` for GitHub Actions
  vulnerabilities: template injection, unpinned third-party actions, missing
  `persist-credentials: false`, and the like. It runs under zizmor's `auditor` persona by
  default, because several audits (`secrets-outside-env` among them) only fire under it,
  and a gate that reports a pass while a class of findings is suppressed is worse than no
  gate. Set `zizmor-persona: "regular"` for the quieter default.
- **skillxray** scans `SKILL.md` files, Claude Code plugins, and MCP bundles for prompt
  injection, hidden Unicode, dangerous commands, and leaked secrets. If your repo has none
  of that, this step detects it and skips cleanly instead of failing on nothing to scan.
- **checkout-safety** (bundled, `checkout_safety.py`, no dependency) reads your workflows
  for the two ways fork pull request code gets run in a privileged job: an explicit
  `allow-unsafe-pr-checkout`, and an `actions/checkout` pinned to a SHA or an exact tag in
  a `pull_request_target` or `workflow_run` workflow. See below for why the second one
  matters.
- **secrets** (bundled, `scan_secrets.py`, no dependency) greps the working tree for
  AWS access key IDs, GitHub and GitLab tokens, OpenAI/Anthropic/Stripe keys, and PEM
  private key blocks. Matched values are redacted before they ever hit the log.

## The checkout-safety check

`actions/checkout` v7 refuses by default to fetch fork pull request code in a
`pull_request_target` or `workflow_run` workflow, and the opt-out is a named input,
`allow-unsafe-pr-checkout`, so it is easy to spot. The enforcement was backported to the
supported majors on 2026-07-20, but a workflow pinned to a specific SHA, minor or patch
does not pick the backport up.

That is the awkward part. Pinning by SHA is the right supply-chain move, and this README
tells you to do it two sections up, so the repos following the best advice are the ones
still exposed. zizmor's `unpinned-uses` will never mention it either, because the pin is
correct, it is just old.

The check reports a SHA or exact-tag pin under one of those triggers as medium, and raises
it to high when the same step also checks out the pull request head, which is the shape
that actually runs fork code. A major tag (`@v7`) or a branch is never flagged: those moved
with the fix. The default `checkout-safety-fail-on` is `high`, so a stale pin is reported
without failing your build; set it to `medium` to enforce.

## The secrets scan

A file it could not read (too large, unreadable, binary, or a symlink it will not follow)
is listed in the summary with the reason, so an under-scan is never silent. Set
`secrets-fail-on-skip: "true"` to make that fail the gate instead of only reporting it.
Directories the scan skips by policy (`.git`, `__pycache__`, a real virtualenv, anything
you excluded) are a separate, collapsed list and never fail the run.

For a credential-shaped string that is supposed to be there, put a marker on its line or
the line above it instead of excluding the whole file:

```python
FIXTURE_TOKEN = "ghp_notarealtokenatall..."  # ci-safety-gate: allow
```

`pragma: allowlist secret` works too, for repos already annotated for detect-secrets. The
count of suppressed findings is always printed, so suppression is never invisible.

Findings are also emitted as GitHub annotations, so they land on the diff in Files Changed
rather than only in the job summary. Turn that off with `secrets-annotations: "false"`.

## Toggling checks

Every check is its own input, `"true"` by default:

```yaml
- uses: munzzyy/ci-safety-gate@v0.1.1
  with:
    skillxray: "false"    # skip if you know you have no skill/plugin content
    zizmor-min-severity: "high"
    secrets-exclude: "tests/fixtures/*"
```

Full input list is in [`action.yml`](action.yml): paths and globs per check, a fail
threshold for skillxray, zizmor and checkout-safety, and a size cap for the secrets scan.

## The combined summary

Every enabled check writes its own section to `$GITHUB_STEP_SUMMARY`, so a PR shows one
report with a heading per check, followed by a `## Result` section that lists pass/fail/
skipped per check and the overall verdict. The job step itself fails if any enabled check
failed; a skipped check (disabled, or skillxray finding nothing to scan) never fails it.

The gate runs live on [munzzyy/munzzyy](https://github.com/munzzyy/munzzyy/actions/workflows/gate.yml):
the secrets scan over the repo, zizmor over its workflow, and skillxray skipping cleanly
because there's nothing skill-shaped to scan.

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

`--local` runs the same commands action.yml's composite steps run against a directory you
point it at (default `.`), hands the result to the same `evaluate_gate.py` the action
itself calls, and prints the same combined summary to your terminal instead of
`$GITHUB_STEP_SUMMARY`. Same verdict, same exit code.

Every `action.yml` input has a matching flag: `--no-zizmor`, `--zizmor-min-severity`,
`--secrets-exclude`, and so on. Run `ci-safety-gate --help` for the full list. Defaults come
straight out of `action.yml` at run time rather than a hand-copied second set, so a version
bump or threshold change there shows up here for free.

A scanner that isn't installed fails loud instead of skipping quietly:

```
## zizmor (GitHub Actions security audit)

zizmor did not run (not installed): install with `pip install "zizmor>=1.28.0"`, or re-run
with --install-missing to do it automatically.
```

Pass `--install-missing` and it runs the exact `pip install` action.yml's own install steps
run (same version floor, same skillxray commit) instead of just naming the command.

### Running as a pre-commit hook

This repo ships a `.pre-commit-hooks.yaml`, so any repo already using
[pre-commit](https://pre-commit.com) can wire the gate in as a local hook and find out
about a failure before it's a red PR instead of after:

```yaml
-   repo: https://github.com/munzzyy/ci-safety-gate
    rev: main  # pin to a tag once one exists
    hooks:
    -   id: ci-safety-gate
```

pre-commit clones this repo and installs it into its own hook environment, which is
exactly the checkout `--local` needs to find `action.yml` (see Known limitations below),
so there's nothing extra to set up. The hook runs `ci-safety-gate --local` and picks up
whatever flags you pass it with `args:`.

### Known limitations

- `--local` only works from a checkout of this repo (`git clone` + `pip install -e .`), since
  it reads its defaults straight out of the real `action.yml` on disk instead of a bundled
  copy. A real, non-editable PyPI wheel would need `action.yml` shipped as package data for
  this to keep working. That is a follow-up for whenever this package is actually published,
  not solved yet.
- The flags mirror `action.yml`'s inputs, but the literal commands each check runs
  (`ci_safety_gate/checks.py`) are still a second, hand-written copy of the bash in
  `action.yml`. Rewriting the composite action to call into this package would close that
  gap for good, but that's a bigger, riskier change than this pass makes.
  `tests/test_checks.py` asserts every flag `checks.py` builds is still literally present in
  `action.yml`'s own bash, so the two failing to match is a test failure, not a silent drift.
- `--local` uses whatever Python, zizmor, and skillxray are already on your `PATH`
  (or installs them with `--install-missing`); it doesn't manage a separate pinned
  `python-version` the way the composite action does.
- The composite action itself is only exercised on Linux in CI. The unit tests run on
  Linux, macOS and Windows, but the job that actually invokes `uses: ./` is
  `ubuntu-latest` only, so the bash steps are unproven on the other two.

## What this does not do

- It's an orchestrator, not a detector. The actual detection quality of the two wrapped
  tools is whatever zizmor and skillxray ship; this action just installs them, runs them
  the same way every time, and merges the output. A finding a bundled tool misses, this
  gate misses too.
- skillxray installs from a pinned commit of `munzzyy/skillxray`, not from PyPI, because it
  isn't published there yet. It is pinned by full SHA rather than by tag, since a tag can be
  moved. Point `skillxray-ref` at a newer commit when there is one, or drop this once it's
  on PyPI.
- zizmor is installed with a `>=1.28.0` floor rather than an exact pin, so a fix in zizmor
  reaches you without waiting on a release here. 1.28.0 is the first version without
  GHSA-f42p-wjw5-97qh. Pin it harder with `zizmor-version` if you'd rather.
- The bundled secrets scan is deliberately small: eight high-precision patterns, no entropy
  analysis, no git-history scan. It's a floor, not a replacement for gitleaks or a real
  secret manager.
- The checkout-safety check reads YAML with regexes, not a parser, to hold the
  zero-dependency floor. It reads the shapes people actually write; a workflow that nests
  its triggers in some exotic way could slip past it.
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

MIT, free to use, change, and ship, commercial or not. See [LICENSE](LICENSE).

## Support

If the gate caught something before it merged, [sponsoring](https://github.com/sponsors/munzzyy) is what keeps it maintained.
