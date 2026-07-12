# Security

ci-safety-gate is a composite GitHub Action that runs four scanners (noslop,
zizmor, skillxray, and a bundled secrets grep) inside your CI job and combines
their verdicts into one gate. It runs with whatever permissions your workflow
gives the job - the recommended setup is `contents: read` and nothing else,
and nothing in the gate needs more.

Two surfaces matter. First, the supply chain: the action installs pinned
versions of the tools it wraps, so a compromise of one of those packages is a
compromise of your CI job - the pins are exact for that reason, and bumping
them is a reviewed change here, not something the action does on its own.
Second, the gate parses repo content (workflows, skills, source files) that in
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
