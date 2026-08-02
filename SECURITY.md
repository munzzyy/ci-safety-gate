# Security

ci-safety-gate is a composite GitHub Action that runs three scanners (zizmor,
skillxray, and a bundled secrets grep) inside your CI job and combines
their verdicts into one gate. It runs with whatever permissions your workflow
gives the job - the recommended setup is `contents: read` and nothing else,
and nothing in the gate needs more.

Two surfaces matter. First, the supply chain: the action pip-installs the
tools it wraps into your job, so a compromise of one of those packages is a
compromise of your CI job. skillxray is pinned to a full commit SHA, because
a git tag can be moved under you and nothing would show it. zizmor is
installed with a minimum-version floor instead, currently `>=1.28.0`, the
first release without GHSA-f42p-wjw5-97qh (debug logging printed available
GitHub credentials in cleartext). A floor is a deliberate trade: a fix in
zizmor reaches you without waiting on a release here, and in exchange you
are trusting PyPI to serve an uncompromised zizmor. Both are inputs
(`zizmor-version` and `skillxray-ref`), so pin them harder than the defaults
do if that trade isn't one you want. Second, the gate parses repo content (workflows, skills, source files) that in
a fork-PR setting is attacker-controlled; a crafted file that crashes a
scanner, silently skips one, or flips the combined verdict to pass is a
vulnerability in this action.

## Reporting a vulnerability

Please don't open a public issue for security problems. Use GitHub's private
reporting instead:

https://github.com/munzzyy/ci-safety-gate/security/advisories/new

Include what you found, how to reproduce it, and the impact you'd expect.

## Supported versions

Fixes land on the latest tagged version; there's no backport policy.
