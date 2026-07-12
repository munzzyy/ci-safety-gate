# Contributing

Thanks for looking at this. It's a small, single-purpose action and contributions are welcome.

## Setup

```
git clone https://github.com/munzzyy/ci-safety-gate
cd ci-safety-gate
python3 -m venv .venv && source .venv/bin/activate
pip install pytest
```

`scan_secrets.py` is the only piece of Python this repo owns; everything else is YAML and shells
out to noslop, zizmor, and skillxray.

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

## License

Contributions come in under the [Blue Oak Model License 1.0.0](https://blueoakcouncil.org/license/1.0.0). By opening a PR you agree your contribution is offered on those terms.
