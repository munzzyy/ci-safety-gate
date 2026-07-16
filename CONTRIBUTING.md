# Contributing

Thanks for looking at this. It's a small, single-purpose action and contributions are welcome.

## Setup

```
git clone https://github.com/munzzyy/ci-safety-gate
cd ci-safety-gate
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
```

`scan_secrets.py` and `evaluate_gate.py` are stdlib-only scripts action.yml calls by path; the
`ci_safety_gate/` package wraps them into `ci-safety-gate --local`, the CLI that reproduces the
whole gate on your own machine (see the README's "Running the gate locally"). Everything else
is YAML and shells out to noslop, zizmor, and skillxray.

## Running the tests

```
python3 -m pytest tests/ -v
```

CI runs the same suite on Linux, macOS, and Windows, plus an integration job that invokes the
composite action against a fixture tree inside this repo (`examples/demo`) and against a planted
fake credential, so both the pass and the fail path are proven, not just claimed.

## Changing scan_secrets.py

Every credential pattern change lands with a test: a positive case that must be caught and, if
the change could over-match, a benign case that must stay clean. `redact()` must never let a full
matched value reach stdout, JSON, or the step summary; there's a test for that too.

## Changing action.yml

Any `${{ }}` expression that carries repo content (an `inputs.*` that isn't a fixed enum, any
`steps.*.outputs.*`) needs to go through an `env:` block rather than being interpolated straight
into a `run:` script. zizmor catches this if you forget:

```
zizmor --offline action.yml
```

Keep third-party actions pinned to a commit SHA, not a tag.

If you change a flag or default a check runs (noslop, zizmor, or skillxray), update it in both
`action.yml`'s bash and `ci_safety_gate/checks.py` — `tests/test_checks.py` asserts the two
still match, so a real drift fails CI rather than shipping quietly. Defaults themselves
(versions, globs, thresholds) only live in `action.yml`; `ci_safety_gate/action_defaults.py`
reads them from there at run time, so there's no second copy of those to keep in sync by hand.

## License

By opening a PR you agree your contribution is offered under the project's MIT license.
