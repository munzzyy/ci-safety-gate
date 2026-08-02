"""Tests for scan_secrets.py.

Credential-shaped fixture values are built by concatenating pieces at
runtime rather than sitting in this file as one contiguous literal. That
keeps a real-looking token out of the git blob (so a scanner reading this
source, including our own, doesn't flag the test suite itself) while still
exercising the exact string the regex has to match at runtime.
"""

from __future__ import annotations

import json
import os

import pytest

import scan_secrets


# credential id -> (expected rule name, full credential string)
CREDENTIALS = {
    "aws_access_key": ("AWS access key ID", "AKIA" + "IOSFODNN7EXAMPLE"),
    "aws_session_key": ("AWS access key ID", "ASIA" + "QWERTYUIOPASDFGH"),
    "github_classic": ("GitHub token", "ghp_" + "0" * 36),
    "github_oauth": ("GitHub token", "gho_" + "1" * 36),
    "github_fine_grained": ("GitHub fine-grained PAT", "github_pat_" + "0" * 60),
    "gitlab_pat": ("GitLab personal access token", "glpat-" + "0" * 20),
    "anthropic_key": ("Anthropic API key", "sk-ant-" + "0" * 20),
    "openai_key": ("OpenAI API key", "sk-" + "0" * 32),
    "openai_project_key": ("OpenAI API key", "sk-proj-" + "0" * 32),
    "stripe_secret": ("Stripe secret key", "sk_live_" + "0" * 20),
    "stripe_restricted": ("Stripe secret key", "rk_live_" + "0" * 20),
    "private_key_rsa": ("private key block", "-----BEGIN " + "RSA PRIVATE KEY" + "-----"),
    "private_key_generic": ("private key block", "-----BEGIN " + "PRIVATE KEY" + "-----"),
    "private_key_openssh": ("private key block", "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"),
}

BENIGN_SNIPPETS = {
    "env_lookup": "api_key = os.environ['OPENAI_API_KEY']\n",
    "short_github_prefix": "token = 'ghp_placeholder'\n",
    "short_openai_prefix": "key = 'sk-short'\n",
    "plain_password": "password = 'hunter2'\n",
    "angle_bracket_placeholder": "aws_access_key_id: <YOUR_KEY_HERE>\n",
    "ordinary_code": (
        "def greet(name):\n"
        "    return f'hello {name}'\n"
    ),
}


@pytest.mark.parametrize("cred_id", sorted(CREDENTIALS))
def test_positive_detects_each_credential_type(tmp_path, cred_id):
    rule, secret = CREDENTIALS[cred_id]
    target = tmp_path / "config.py"
    target.write_text(f"VALUE = \"{secret}\"\n", encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned

    assert scanned == 1
    assert not skipped
    assert len(findings) == 1
    assert findings[0].rule == rule
    assert findings[0].line == 1
    assert secret not in findings[0].redacted


@pytest.mark.parametrize("snippet_id", sorted(BENIGN_SNIPPETS))
def test_benign_snippets_produce_no_findings(tmp_path, snippet_id):
    target = tmp_path / "app.py"
    target.write_text(BENIGN_SNIPPETS[snippet_id], encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned

    assert scanned == 1
    assert findings == []


def test_redact_short_value_is_fully_masked():
    assert scan_secrets.redact("abcd1234") == "*" * 8


def test_redact_long_value_keeps_head_and_tail_only():
    _, secret = CREDENTIALS["aws_access_key"]
    redacted = scan_secrets.redact(secret)
    assert redacted == f"{secret[:4]}...{secret[-4:]}"
    assert secret not in redacted
    assert secret[4:-4] not in redacted


def test_full_secret_never_appears_in_human_output(tmp_path, capsys):
    rule, secret = CREDENTIALS["github_classic"]
    (tmp_path / "leak.txt").write_text(secret, encoding="utf-8")

    code = scan_secrets.main([str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 1
    assert secret not in out
    assert rule in out


def test_full_secret_never_appears_in_json_output(tmp_path, capsys):
    rule, secret = CREDENTIALS["stripe_secret"]
    (tmp_path / "leak.txt").write_text(secret, encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 1
    assert secret not in out
    assert payload["findings"][0]["rule"] == rule
    assert payload["scanned"] == 1


def test_summary_output_is_markdown_with_verdict(tmp_path, capsys):
    _, secret = CREDENTIALS["gitlab_pat"]
    (tmp_path / "leak.txt").write_text(secret, encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--summary"])
    out = capsys.readouterr().out

    assert code == 1
    assert out.startswith("## Secrets scan")
    assert "FAIL" in out
    assert "| file | line | type | value |" in out


def test_summary_output_pass_on_clean_tree(tmp_path, capsys):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--summary"])
    out = capsys.readouterr().out

    assert code == 0
    assert "PASS" in out


def test_clean_tree_exits_zero(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert scan_secrets.main([str(tmp_path)]) == 0


def test_nonexistent_path_exits_two(capsys):
    code = scan_secrets.main(["/no/such/path/should/exist"])
    err = capsys.readouterr().err
    assert code == 2
    assert "no such path" in err


def test_negative_max_bytes_exits_two(tmp_path, capsys):
    code = scan_secrets.main([str(tmp_path), "--max-bytes", "-5"])
    err = capsys.readouterr().err
    assert code == 2
    assert "--max-bytes" in err


def test_zero_max_bytes_exits_two(tmp_path):
    assert scan_secrets.main([str(tmp_path), "--max-bytes", "0"]) == 2


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        scan_secrets.main(["--help"])
    assert exc.value.code == 0


def test_exclude_glob_skips_matching_file(tmp_path):
    _, secret = CREDENTIALS["anthropic_key"]
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "leak.txt").write_text(secret, encoding="utf-8")

    findings = scan_secrets.scan(tmp_path, ["tests/fixtures/*"], scan_secrets.DEFAULT_MAX_BYTES).findings
    assert findings == []


def test_repeated_exclude_flags_both_apply(tmp_path, capsys):
    _, secret_a = CREDENTIALS["gitlab_pat"]
    _, secret_b = CREDENTIALS["stripe_secret"]
    (tmp_path / "a.txt").write_text(secret_a, encoding="utf-8")
    (tmp_path / "b.txt").write_text(secret_b, encoding="utf-8")

    code = scan_secrets.main([
        str(tmp_path), "--exclude", "a.txt", "--exclude", "b.txt",
    ])
    assert code == 0


def test_oversized_file_is_skipped_not_scanned(tmp_path):
    _, secret = CREDENTIALS["openai_key"]
    padded = ("x" * 200) + secret
    (tmp_path / "big.txt").write_text(padded, encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], max_bytes=50)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert findings == []
    assert scanned == 0
    assert skipped == [("big.txt", "too large")]


def test_binary_file_is_skipped(tmp_path):
    _, secret = CREDENTIALS["stripe_restricted"]
    data = b"\x00\x01\x02" + secret.encode("ascii")
    (tmp_path / "blob.bin").write_bytes(data)

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert findings == []
    assert scanned == 0
    assert skipped == [("blob.bin", "binary")]


def test_utf16_le_bom_file_is_scanned_not_skipped_as_binary(tmp_path):
    # Windows tooling (PowerShell, some .env writers) emits UTF-16LE with a
    # BOM. ASCII-range text encoded that way is ~50% \x00 bytes by
    # construction -- a raw null-byte check alone would wrongly call this
    # binary and skip it before the credential regexes ever run.
    _, secret = CREDENTIALS["aws_access_key"]
    content = f'$env:AWS_ACCESS_KEY_ID = "{secret}"\n'
    data = b"\xff\xfe" + content.encode("utf-16-le")
    (tmp_path / "secrets.env").write_bytes(data)

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned

    assert scanned == 1
    assert skipped == []
    assert len(findings) == 1
    assert findings[0].rule == "AWS access key ID"
    assert findings[0].line == 1


def test_utf16_be_bom_file_is_scanned_not_skipped_as_binary(tmp_path):
    _, secret = CREDENTIALS["github_classic"]
    content = f'token = "{secret}"\n'
    data = b"\xfe\xff" + content.encode("utf-16-be")
    (tmp_path / "secrets.env").write_bytes(data)

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned

    assert scanned == 1
    assert skipped == []
    assert len(findings) == 1
    assert findings[0].rule == "GitHub token"


def test_utf16_bom_file_without_a_secret_is_clean(tmp_path):
    data = b"\xff\xfe" + "just some ordinary text\n".encode("utf-16-le")
    (tmp_path / "notes.env").write_bytes(data)

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert scanned == 1
    assert skipped == []
    assert findings == []


def test_genuinely_binary_file_without_a_bom_is_still_skipped(tmp_path):
    # A real binary blob whose first two bytes happen to not be a UTF-16 BOM
    # must still be classified as binary -- the BOM check narrows the
    # exemption, it doesn't loosen the general null-byte heuristic.
    _, secret = CREDENTIALS["openai_key"]
    data = bytes(range(256)) * 8 + secret.encode("ascii")
    (tmp_path / "blob.bin").write_bytes(data)

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert findings == []
    assert scanned == 0
    assert skipped == [("blob.bin", "binary")]


def test_default_skip_dirs_are_never_walked(tmp_path):
    _, secret = CREDENTIALS["github_oauth"]
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(secret, encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, scanned = result.findings, result.scanned
    assert findings == []
    assert scanned == 1


def test_symlinked_file_is_not_followed(tmp_path):
    _, secret = CREDENTIALS["aws_access_key"]
    real = tmp_path / "real.txt"
    real.write_text(secret, encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("platform does not allow creating symlinks without elevated privilege")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    # the real file is still scanned and caught; the symlink is not followed,
    # but it is reported so the under-scan isn't silent
    assert result.scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].path == "real.txt"
    assert ("link.txt", "symlink (not followed)") in result.unread


def test_multiple_findings_have_correct_line_numbers(tmp_path):
    _, secret_a = CREDENTIALS["anthropic_key"]
    _, secret_b = CREDENTIALS["stripe_secret"]
    content = (
        f"line1 = 1\n"
        f"line2 = \"{secret_a}\"\n"
        f"line3 = 3\n"
        f"line4 = 4\n"
        f"line5 = \"{secret_b}\"\n"
    )
    (tmp_path / "multi.py").write_text(content, encoding="utf-8")

    findings = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES).findings
    findings_by_line = {f.line: f.rule for f in findings}
    assert findings_by_line[2] == "Anthropic API key"
    assert findings_by_line[5] == "Stripe secret key"


def test_empty_directory_scans_clean(tmp_path):
    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)
    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert findings == []
    assert skipped == []
    assert scanned == 0


def test_single_file_path_is_scanned_directly(tmp_path):
    _, secret = CREDENTIALS["github_classic"]
    target = tmp_path / "single.py"
    target.write_text(secret, encoding="utf-8")

    result = scan_secrets.scan(target, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, scanned = result.findings, result.scanned
    assert scanned == 1
    assert findings[0].path == "single.py"


def test_invalid_utf8_bytes_do_not_crash_the_scan(tmp_path):
    _, secret = CREDENTIALS["gitlab_pat"]
    data = b"prefix \xff\xfe garbage\n" + secret.encode("ascii")
    (tmp_path / "weird.txt").write_bytes(data)

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, scanned = result.findings, result.scanned
    assert scanned == 1
    assert len(findings) == 1


def test_quiet_suppresses_output_on_clean_scan(tmp_path, capsys):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--quiet"])
    out = capsys.readouterr().out
    assert code == 0
    assert out == ""


def test_quiet_still_reports_when_dirty(tmp_path, capsys):
    _, secret = CREDENTIALS["openai_key"]
    (tmp_path / "leak.txt").write_text(secret, encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--quiet"])
    out = capsys.readouterr().out
    assert code == 1
    assert out != ""


def test_default_path_scans_current_directory(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = scan_secrets.main([])
    assert code == 0


def test_relative_paths_used_as_finding_labels(tmp_path):
    nested = tmp_path / "src" / "pkg"
    nested.mkdir(parents=True)
    _, secret = CREDENTIALS["stripe_restricted"]
    (nested / "settings.py").write_text(secret, encoding="utf-8")

    findings = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES).findings
    assert findings[0].path == "src/pkg/settings.py"


def test_json_output_includes_skipped_files(tmp_path, capsys):
    (tmp_path / "big.txt").write_text("x" * 100, encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--max-bytes", "10", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["skipped"] == [{"path": "big.txt", "reason": "too large"}]


def test_summary_surfaces_skipped_files_so_underscan_is_not_silent(tmp_path, capsys):
    # A credential hiding in an oversized file must not produce a bare
    # "PASS" with no trace: --summary is the mode the action runs, and the
    # skip has to be visible there, not only in --json.
    _, secret = CREDENTIALS["aws_access_key"]
    padded = ("x" * 200) + secret
    (tmp_path / "big.py").write_text(padded, encoding="utf-8")
    (tmp_path / "ok.py").write_text("print('hi')\n", encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--max-bytes", "50", "--summary"])
    out = capsys.readouterr().out

    assert code == 0
    assert "Not scanned (could not be read)" in out
    assert "big.py" in out
    assert "too large" in out
    assert secret not in out


def test_human_output_surfaces_skipped_files(tmp_path, capsys):
    (tmp_path / "big.py").write_text("x" * 100, encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--max-bytes", "10"])
    out = capsys.readouterr().out
    assert code == 0
    assert "not scanned" in out
    assert "big.py" in out
    assert "too large" in out


def test_fail_on_skip_makes_an_oversized_file_fail_the_scan(tmp_path, capsys):
    # A credential hiding in an oversized file is exactly the fail-open the
    # flag closes: with --fail-on-skip the skip alone must exit non-zero,
    # even though no credential was actually read out of the tree.
    _, secret = CREDENTIALS["openai_key"]
    padded = ("x" * 200) + secret
    (tmp_path / "big.py").write_text(padded, encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--max-bytes", "50", "--fail-on-skip", "--summary"])
    out = capsys.readouterr().out

    assert code == 1
    assert "FAIL" in out
    assert "--fail-on-skip" in out
    assert "big.py" in out
    assert "too large" in out
    assert secret not in out


def test_default_does_not_fail_on_a_skip_without_the_flag(tmp_path, capsys):
    # Same oversized file, no flag: the skip is still reported but the exit
    # code stays 0, so existing callers see no change in behavior.
    (tmp_path / "big.py").write_text("x" * 200, encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--max-bytes", "50", "--summary"])
    out = capsys.readouterr().out

    assert code == 0
    assert "PASS" in out
    assert "big.py" in out
    assert "too large" in out


def test_fail_on_skip_is_a_clean_pass_when_nothing_was_skipped(tmp_path):
    # The flag only bites when something was actually skipped -- a fully
    # scanned clean tree still exits 0 with it set.
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert scan_secrets.main([str(tmp_path), "--fail-on-skip"]) == 0


def test_fail_on_skip_human_output_names_the_flag(tmp_path, capsys):
    (tmp_path / "big.py").write_text("x" * 100, encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--max-bytes", "10", "--fail-on-skip"])
    out = capsys.readouterr().out
    assert code == 1
    assert "--fail-on-skip" in out
    assert "big.py" in out


def test_fail_on_skip_json_reports_the_flag_state(tmp_path, capsys):
    (tmp_path / "big.py").write_text("x" * 100, encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--max-bytes", "10", "--fail-on-skip", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["fail_on_skip"] is True
    assert payload["skipped"] == [{"path": "big.py", "reason": "too large"}]


def test_json_reports_fail_on_skip_false_by_default(tmp_path, capsys):
    (tmp_path / "big.py").write_text("x" * 100, encoding="utf-8")
    code = scan_secrets.main([str(tmp_path), "--max-bytes", "10", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["fail_on_skip"] is False


def test_bomless_utf16_le_credential_is_scanned_not_skipped(tmp_path):
    # Some Windows tooling writes UTF-16 with no BOM at all. Half the bytes
    # are \x00 by construction, so a raw null-byte check would call it
    # binary and skip the credential silently. The offset-parity heuristic
    # has to catch it.
    _, secret = CREDENTIALS["aws_access_key"]
    content = f'AWS_ACCESS_KEY_ID = "{secret}"\n'
    (tmp_path / "secret.env").write_bytes(content.encode("utf-16-le"))

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert scanned == 1
    assert skipped == []
    assert len(findings) == 1
    assert findings[0].rule == "AWS access key ID"


def test_bomless_utf16_be_credential_is_scanned_not_skipped(tmp_path):
    _, secret = CREDENTIALS["github_classic"]
    content = f'token = "{secret}"\n'
    (tmp_path / "secret.env").write_bytes(content.encode("utf-16-be"))

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    assert scanned == 1
    assert skipped == []
    assert len(findings) == 1
    assert findings[0].rule == "GitHub token"


def test_dist_build_env_dirs_are_scanned_not_pruned(tmp_path):
    # Committed dist/build bundles and a non-virtualenv config dir named
    # env/ are exactly where a leaked key lands; they must be scanned, not
    # pruned as if they were tool caches.
    _, secret = CREDENTIALS["aws_access_key"]
    for sub in ("env", "dist", "build"):
        d = tmp_path / sub
        d.mkdir()
        (d / "config.txt").write_text(f'k = "{secret}"\n', encoding="utf-8")
    (tmp_path / "main.py").write_text("print('main')\n", encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    findings, skipped, scanned = result.findings, result.unread, result.scanned
    found_paths = {f.path for f in findings}
    assert found_paths == {"env/config.txt", "dist/config.txt", "build/config.txt"}
    assert scanned == 4


def test_real_virtualenv_named_env_is_pruned_and_listed_as_a_policy_skip(tmp_path):
    # A directory named env/ that actually looks like a virtualenv still
    # gets skipped, and the skip is recorded so it isn't invisible -- but it
    # is a policy skip, not something that could not be read.
    venv = tmp_path / "env"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    _, secret = CREDENTIALS["aws_access_key"]
    (venv / "leak.py").write_text(f'k = "{secret}"\n', encoding="utf-8")
    (tmp_path / "main.py").write_text("print('main')\n", encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    assert result.findings == []
    assert result.scanned == 1
    assert ("env/", "default-skip dir") in result.policy_skips
    assert result.unread == []


def test_default_skip_dir_is_listed_as_a_policy_skip(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("noise\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    assert result.scanned == 1
    assert (".git/", "default-skip dir") in result.policy_skips
    assert result.unread == []


def test_excluded_file_is_recorded_as_a_policy_skip(tmp_path):
    _, secret = CREDENTIALS["anthropic_key"]
    (tmp_path / "fixture.txt").write_text(secret, encoding="utf-8")

    result = scan_secrets.scan(tmp_path, ["fixture.txt"], scan_secrets.DEFAULT_MAX_BYTES)

    assert result.findings == []
    assert ("fixture.txt", "matched an exclude glob") in result.policy_skips


def test_fail_on_skip_passes_on_a_real_checkout_with_a_git_dir(tmp_path):
    # Every actions/checkout produces a .git/, and .git is a default-skip
    # dir. Counting that as a skip made secrets-fail-on-skip: "true" a
    # guaranteed failure on every repo, which is why the flag was unusable.
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    assert scan_secrets.main([str(tmp_path), "--fail-on-skip"]) == 0


def test_fail_on_skip_summary_passes_on_a_real_checkout(tmp_path, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "app.pyc").write_text("noise\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--fail-on-skip", "--summary"])
    out = capsys.readouterr().out

    assert code == 0
    assert "PASS" in out
    assert "Not scanned (could not be read)" not in out


def test_policy_skips_are_collapsed_into_one_line_not_one_per_directory(tmp_path):
    # The noise this fixes: a clean PASS followed by a dozen lines of
    # __pycache__ reads like the scan gave up.
    for name in (".git", "__pycache__", ".pytest_cache", ".mypy_cache",
                 ".ruff_cache", ".tox", "node_modules"):
        d = tmp_path / name
        d.mkdir()
        (d / "junk.txt").write_text("noise\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)
    human = scan_secrets.render_human(result)
    summary = scan_secrets.render_summary(result)

    assert len(result.policy_skips) == 7
    assert sum(1 for line in human.splitlines() if "skipped by policy" in line) == 1
    assert "and 1 more" in human
    # The detail is still one click away in the summary, not deleted.
    assert "<details>" in summary
    assert "`node_modules/`" in summary


def test_symlinked_file_is_reported_as_not_scanned(tmp_path):
    # The one under-scan the old code could not see: a symlink was dropped
    # with a bare continue, so a token behind one produced a clean PASS that
    # even --fail-on-skip could not catch.
    _, secret = CREDENTIALS["github_classic"]
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.env").write_text(secret, encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        os.symlink(outside / "real.env", root / ".env")
    except (OSError, NotImplementedError):
        pytest.skip("platform does not allow creating symlinks without elevated privilege")

    result = scan_secrets.scan(root, [], scan_secrets.DEFAULT_MAX_BYTES)

    assert result.findings == []
    assert result.scanned == 0
    assert (".env", "symlink (not followed)") in result.unread
    assert scan_secrets.main([str(root), "--fail-on-skip"]) == 1


def test_symlinked_directory_is_reported_as_not_scanned(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "config.txt").write_text("noise\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        os.symlink(outside, root / "linked")
    except (OSError, NotImplementedError):
        pytest.skip("platform does not allow creating symlinks without elevated privilege")

    result = scan_secrets.scan(root, [], scan_secrets.DEFAULT_MAX_BYTES)

    assert ("linked/", "symlink (not followed)") in result.unread


def test_inline_allowlist_marker_on_the_same_line_suppresses_the_finding(tmp_path, capsys):
    _, secret = CREDENTIALS["github_classic"]
    (tmp_path / "fixtures.py").write_text(
        f'TOKEN = "{secret}"  # ci-safety-gate: allow\n', encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--summary"])
    out = capsys.readouterr().out

    assert code == 0
    assert "PASS" in out
    assert "1 finding(s) suppressed by an inline allowlist marker" in out


def test_inline_allowlist_marker_on_the_line_above_suppresses_the_finding(tmp_path):
    _, secret = CREDENTIALS["stripe_secret"]
    (tmp_path / "fixtures.py").write_text(
        f'# pragma: allowlist secret\nTOKEN = "{secret}"\n', encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    assert result.findings == []
    assert result.suppressed == 1


def test_an_unmarked_credential_in_an_allowlisted_file_is_still_caught(tmp_path):
    # The whole point of an inline marker over --exclude: the rest of the
    # file keeps getting scanned.
    _, allowed = CREDENTIALS["github_classic"]
    _, real = CREDENTIALS["stripe_secret"]
    (tmp_path / "fixtures.py").write_text(
        f'FIXTURE = "{allowed}"  # ci-safety-gate: allow\n\nREAL = "{real}"\n',
        encoding="utf-8")

    result = scan_secrets.scan(tmp_path, [], scan_secrets.DEFAULT_MAX_BYTES)

    assert result.suppressed == 1
    assert len(result.findings) == 1
    assert result.findings[0].line == 3


def test_suppression_count_reaches_json_output(tmp_path, capsys):
    _, secret = CREDENTIALS["github_classic"]
    (tmp_path / "fixtures.py").write_text(
        f'TOKEN = "{secret}"  # ci-safety-gate: allow\n', encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["suppressed"] == 1
    assert payload["findings"] == []


def test_annotations_go_to_stderr_one_per_finding(tmp_path, capsys):
    _, secret = CREDENTIALS["github_classic"]
    (tmp_path / "leak.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")

    code = scan_secrets.main([str(tmp_path), "--summary", "--github-annotations"])
    captured = capsys.readouterr()

    assert code == 1
    # stdout is what the action redirects into the step summary, so a
    # workflow command must not land there.
    assert "::error" not in captured.out
    assert captured.err.startswith("::error file=leak.py,line=1,title=ci-safety-gate::")
    assert "GitHub token" in captured.err
    assert secret not in captured.err


def test_annotations_are_off_by_default(tmp_path, capsys):
    _, secret = CREDENTIALS["github_classic"]
    (tmp_path / "leak.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")

    scan_secrets.main([str(tmp_path), "--summary"])
    captured = capsys.readouterr()

    assert "::error" not in captured.err


def test_annotations_warn_about_unread_paths_when_fail_on_skip_is_set(tmp_path, capsys):
    (tmp_path / "big.py").write_text("x" * 200, encoding="utf-8")

    code = scan_secrets.main([
        str(tmp_path), "--max-bytes", "50", "--fail-on-skip", "--github-annotations",
    ])
    err = capsys.readouterr().err

    assert code == 1
    assert "::warning file=big.py,title=ci-safety-gate::not scanned (too large)" in err


def test_no_eval_or_exec_used_in_module_source():
    with open(scan_secrets.__file__, encoding="utf-8") as fh:
        source = fh.read()
    assert "eval(" not in source
    assert "exec(" not in source
    assert "shell=True" not in source
