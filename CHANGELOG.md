# Changelog

## Unreleased

### Fixed

- Hardened skill-content detection.
- The installed CLI, which is what the pre-commit hook runs, crashed with a
  `KeyError` in any repo with its own `action.yml`, because it read that file
  as if it were ours. Everywhere else it fell back to hand-copied defaults,
  one of which installed skillxray from a movable tag. The defaults now ship
  inside the package, and a repo's own `action.yml` is never read.
- checkout-safety lost a `pull_request_target` trigger that came after a
  comment at column 0, or that was written as a list at column 0
  (`- pull_request_target`). It rated several pull request head checkouts
  only medium, which passes at the default threshold: `github.head_ref` with
  the fork as `repository:`, `refs/pull/<number>/merge`, and a `ref:` inside a
  flow mapping. It also skipped `uses: Actions/Checkout@...` over the case.
- The secrets scan's OpenAI pattern missed any project key (`sk-proj-`) with
  a `-` or `_` early in its body, and never matched service account
  (`sk-svcacct-`) or admin (`sk-admin-`) keys.
- checkout-safety counted a checkout of the base ref
  (`github.event.pull_request.base.sha`) as a pull request head checkout, so
  the standard safe pattern failed the gate. It also flagged exact tags from
  v7.0.0 on, which shipped with the refusal, and commented-out `uses:` lines.
- A check toggle that was neither `true` nor `false`, like `secrets: "yes"`,
  switched the check off and showed it as skipped. That check fails now, and
  the summary names the value. `secrets-fail-on-skip`, `secrets-annotations`
  and `zizmor-offline` ignore case now, so `"True"` works there too.
- A Claude Code plugin repo (`.claude-plugin/`) had skillxray skipped and the
  gate passed, because detection only looked for `SKILL.md`, `skills/` and
  `.claude/`. A `.claude-plugin/` directory counts now, in the action and in
  `--local`.

### Added

- The secrets scan matches Slack, Google API, npm and Twilio keys.
- A pre-commit hook (`.pre-commit-hooks.yaml`) that runs
  `ci-safety-gate --local` on every commit.
- `--json` for `ci-safety-gate --local`. It prints the verdict and the status
  of each check as JSON.
- checkout-safety follows reusable workflows in the same repo. One called
  from a `pull_request_target` or `workflow_run` workflow, directly or
  through another reusable workflow, is checked as if it had that trigger,
  and the finding names the caller.

### Changed

- Relicensed to GPL-3.0-or-later. Releases up to v0.1.1 were under MIT.
- SECURITY.md left out checkout-safety and the README counted eight secrets
  patterns where the scan has twelve. Both name everything now. The usage
  examples pin `actions/checkout` v7.0.1 instead of v5.0.1, the same pin as
  the CI here.

## 0.1.1

Security fixes. If you are pinned to `v0.1.0`, move.

### Do not use v0.1.0

`v0.1.0` runs a check that pip-installs a package which was deleted from PyPI
on 2026-07-28. The name is unclaimed, so anyone can register it and have their
install hooks run inside your CI job, with that job's token and secrets in the
environment. The check itself was removed from the default
branch back in f1f0ca6, but the tag, the README and the example workflow all
still pointed at it. They point at `v0.1.1` now.

### Fixed

- `secrets-fail-on-skip: "true"` failed every repo, every time. Every
  `actions/checkout` leaves a `.git/` behind, `.git` is a default-skip
  directory, and any default-skip directory counted as a skip. Deliberate
  policy skips and paths that could not be read are separate lists now, and
  only the second kind can fail the run.
- Symlinked files were dropped silently: neither scanned nor reported, so a
  token behind one scanned clean and `--fail-on-skip` could not see it. They
  are still not followed, but they are reported.
- zizmor was installed unpinned. It now installs with a `>=1.28.0` floor,
  which is the first release without GHSA-f42p-wjw5-97qh (debug logging
  printed available GitHub credentials in cleartext).
- skillxray was installed from a git tag, which anyone with push on that repo
  can move. It is pinned to a full commit SHA now.
- `--local` decoded wrapped-tool output with the locale encoding, so on
  Windows it mojibaked the summary or died with a `UnicodeDecodeError` on
  zizmor's own non-ASCII output.
- SECURITY.md claimed the action installs exact pins. It describes what
  actually happens now, including why zizmor gets a floor and not a pin.

### Added

- A checkout-safety check: flags `allow-unsafe-pr-checkout`, and an
  `actions/checkout` pinned by SHA or exact tag in a `pull_request_target` or
  `workflow_run` workflow, which the 2026-07-20 safe-by-default backport does
  not reach.
- zizmor runs under the `auditor` persona by default. Several audits,
  `secrets-outside-env` among them, only fire under it, so the gate was
  reporting a pass with a class of findings never evaluated.
- Inline allowlist markers (`ci-safety-gate: allow`, `pragma: allowlist
  secret`) for the secrets scan, so a test fixture credential no longer
  requires excluding the whole file. The suppressed count is always reported.
- Secrets findings are emitted as GitHub annotations, so they land on the diff
  in Files Changed.

### Changed

- A clean run printed one line per pruned directory, under a heading reading
  "not scanned". Policy skips collapse to one line, with the detail behind a
  `<details>` block.
- The mirror job's deploy key lives in a dedicated environment.

## 0.1.0

First tagged release. Retired: see above.
