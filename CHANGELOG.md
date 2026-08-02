# Changelog

## 0.1.1

Security fixes. If you are pinned to `v0.1.0`, move.

### Do not use v0.1.0

`v0.1.0` runs a check that pip-installs `noslop-lint`, a package that was
deleted from PyPI on 2026-07-28. The name is unclaimed, so anyone can register
it and have their install hooks run inside your CI job, with that job's token
and secrets in the environment. The check itself was removed from the default
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
