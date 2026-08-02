"""Tests for checkout_safety.py.

The check exists because the two dangerous shapes are invisible to every
other tool in this gate: an explicit `allow-unsafe-pr-checkout`, and an
actions/checkout pinned to a SHA in a `pull_request_target` workflow,
which looks correct to a pin auditor and is exactly the population the
2026-07-20 safe-by-default backport does not reach.
"""

from __future__ import annotations

import json

import checkout_safety


def _repo(tmp_path, workflows: dict[str, str]):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    for name, text in workflows.items():
        (wf_dir / name).write_text(text, encoding="utf-8")
    return tmp_path


SAFE_PR = """\
name: ci
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
"""

RISKY_SHA_PIN = """\
name: label
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
"""

RISKY_PR_HEAD = """\
name: build
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""

OPT_OUT = """\
name: build
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          allow-unsafe-pr-checkout: true
"""


def test_clean_workflow_has_no_findings(tmp_path):
    findings, files = checkout_safety.scan(_repo(tmp_path, {"ci.yml": SAFE_PR}))
    assert findings == []
    assert files == 1


def test_sha_pin_under_a_risky_trigger_is_a_medium(tmp_path):
    findings, _ = checkout_safety.scan(_repo(tmp_path, {"label.yml": RISKY_SHA_PIN}))
    assert len(findings) == 1
    assert findings[0].rule == "stale-checkout-pin"
    assert findings[0].severity == "medium"
    assert findings[0].line == 9


def test_sha_pin_plus_a_pull_request_head_ref_is_a_high(tmp_path):
    # The pin is stale AND the step checks out the fork's own code, which
    # is the pwn-request shape the safe-by-default change blocks.
    findings, _ = checkout_safety.scan(_repo(tmp_path, {"build.yml": RISKY_PR_HEAD}))
    assert [f.severity for f in findings] == ["high"]
    assert "checks out the pull request head" in findings[0].message


def test_explicit_opt_out_is_a_high_even_on_a_current_major_pin(tmp_path):
    findings, _ = checkout_safety.scan(_repo(tmp_path, {"build.yml": OPT_OUT}))
    assert len(findings) == 1
    assert findings[0].rule == "allow-unsafe-pr-checkout"
    assert findings[0].severity == "high"


def test_opt_out_set_to_false_is_not_a_finding(tmp_path):
    findings, _ = checkout_safety.scan(_repo(tmp_path, {
        "build.yml": OPT_OUT.replace("allow-unsafe-pr-checkout: true",
                                     "allow-unsafe-pr-checkout: false"),
    }))
    assert findings == []


def test_opt_out_written_as_an_expression_is_still_flagged(tmp_path):
    # An expression can't be proven safe by reading the file, so it counts.
    findings, _ = checkout_safety.scan(_repo(tmp_path, {
        "build.yml": OPT_OUT.replace("allow-unsafe-pr-checkout: true",
                                     "allow-unsafe-pr-checkout: ${{ inputs.unsafe }}"),
    }))
    assert len(findings) == 1
    assert findings[0].rule == "allow-unsafe-pr-checkout"


def test_a_moving_major_tag_under_a_risky_trigger_is_fine(tmp_path):
    # v7 follows the tag its maintainers move, so it picked the fix up.
    findings, _ = checkout_safety.scan(_repo(tmp_path, {
        "label.yml": RISKY_SHA_PIN.replace(
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1",
            "actions/checkout@v7"),
    }))
    assert findings == []


def test_an_exact_minor_tag_under_a_risky_trigger_is_flagged(tmp_path):
    findings, _ = checkout_safety.scan(_repo(tmp_path, {
        "label.yml": RISKY_SHA_PIN.replace(
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1",
            "actions/checkout@v5.0.1"),
    }))
    assert len(findings) == 1
    assert findings[0].rule == "stale-checkout-pin"


def test_a_sha_pin_without_a_risky_trigger_is_not_flagged(tmp_path):
    # The whole point of the check: a SHA pin is good practice everywhere
    # else, and flagging it on a plain pull_request workflow would train
    # people to ignore this.
    findings, _ = checkout_safety.scan(_repo(tmp_path, {"ci.yml": SAFE_PR}))
    assert findings == []


def test_workflow_run_counts_as_a_risky_trigger(tmp_path):
    findings, _ = checkout_safety.scan(_repo(tmp_path, {
        "post.yml": RISKY_SHA_PIN.replace("pull_request_target:", "workflow_run:"),
    }))
    assert len(findings) == 1


def test_inline_trigger_list_is_read(tmp_path):
    findings, _ = checkout_safety.scan(_repo(tmp_path, {
        "label.yml": RISKY_SHA_PIN.replace(
            "on:\n  pull_request_target:\n    types: [opened]\n",
            "on: [push, pull_request_target]\n"),
    }))
    assert len(findings) == 1


def test_a_repo_with_no_workflows_dir_reads_nothing_and_passes(tmp_path):
    findings, files = checkout_safety.scan(tmp_path)
    assert findings == []
    assert files == 0


def test_unreadable_workflow_is_reported_not_passed_over(tmp_path, monkeypatch):
    # A scanner whose input it could not read must say so. Reporting a
    # clean verdict over a file nobody opened is the failure mode this
    # whole action exists to prevent.
    root = _repo(tmp_path, {"ci.yml": SAFE_PR})
    real_read = checkout_safety.Path.read_text

    def boom(self, *a, **kw):
        if self.name == "ci.yml":
            raise OSError("permission denied")
        return real_read(self, *a, **kw)

    monkeypatch.setattr(checkout_safety.Path, "read_text", boom)

    findings, _ = checkout_safety.scan(root)
    assert [f.rule for f in findings] == ["unreadable-workflow"]
    assert findings[0].severity == "high"


def test_fail_on_high_reports_a_medium_without_failing(tmp_path, capsys):
    root = _repo(tmp_path, {"label.yml": RISKY_SHA_PIN})
    code = checkout_safety.main([str(root), "--summary"])
    out = capsys.readouterr().out
    assert code == 0
    assert "PASS" in out
    assert "stale-checkout-pin" in out


def test_fail_on_medium_turns_the_same_finding_into_a_failure(tmp_path, capsys):
    root = _repo(tmp_path, {"label.yml": RISKY_SHA_PIN})
    code = checkout_safety.main([str(root), "--fail-on", "medium", "--summary"])
    out = capsys.readouterr().out
    assert code == 1
    assert "FAIL" in out


def test_fail_on_none_never_fails(tmp_path):
    root = _repo(tmp_path, {"build.yml": OPT_OUT})
    assert checkout_safety.main([str(root), "--fail-on", "none"]) == 0


def test_high_finding_fails_at_the_default_threshold(tmp_path):
    root = _repo(tmp_path, {"build.yml": OPT_OUT})
    assert checkout_safety.main([str(root)]) == 1


def test_summary_output_is_markdown_with_a_heading(tmp_path, capsys):
    root = _repo(tmp_path, {"build.yml": OPT_OUT})
    checkout_safety.main([str(root), "--summary"])
    out = capsys.readouterr().out
    assert out.startswith("## Checkout safety")
    assert "| file | line | severity | check | detail |" in out


def test_json_output_lists_every_finding(tmp_path, capsys):
    root = _repo(tmp_path, {"build.yml": RISKY_PR_HEAD, "label.yml": RISKY_SHA_PIN})
    code = checkout_safety.main([str(root), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["workflow_files"] == 2
    assert {f["severity"] for f in payload["findings"]} == {"high", "medium"}


def test_a_single_workflow_file_can_be_checked_directly(tmp_path):
    path = tmp_path / "build.yml"
    path.write_text(OPT_OUT, encoding="utf-8")
    findings, files = checkout_safety.scan(path)
    assert files == 1
    assert len(findings) == 1


def test_nonexistent_path_exits_two(capsys):
    code = checkout_safety.main(["/no/such/path/should/exist"])
    assert code == 2
    assert "no such path" in capsys.readouterr().err


def test_this_repos_own_workflows_are_clean():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    findings, files = checkout_safety.scan(root)
    assert files >= 1
    assert findings == [], f"this repo's own workflows have findings: {findings}"


def test_no_eval_or_exec_used_in_module_source():
    with open(checkout_safety.__file__, encoding="utf-8") as fh:
        source = fh.read()
    assert "eval(" not in source
    assert "exec(" not in source
    assert "shell=True" not in source
