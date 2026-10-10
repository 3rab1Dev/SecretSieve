"""Security: escape injection, redaction property, config abuse, symlink loops."""

import json
import os

import pytest

from secretsieve.cli import app as appmod
from tests.conftest import ALL_RAW_SECRETS


def _write_secret_tree(root):
    (root / "app.py").write_text(
        "GITHUB_TOKEN = '%s'\npassword = \"hunter2\"\n" % ALL_RAW_SECRETS[0], encoding="utf-8")
    (root / "creds.json").write_text(
        '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\\\nMIIE\\\\n"}',
        encoding="utf-8")


def test_escape_injection_neutralized(tmp_path, monkeypatch, capsys):
    evil_name = "evil\x1b[2J\x1b]0;pwned\x07r.py"
    try:
        (tmp_path / evil_name).write_text("GITHUB_TOKEN = '%s'\n" % ALL_RAW_SECRETS[0], encoding="utf-8")
    except OSError:
        pytest.skip("platform forbids control chars in filenames")
    monkeypatch.chdir(tmp_path)
    assert appmod.main([".", "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert ALL_RAW_SECRETS[0] not in out


def test_redaction_property_all_renderers(tmp_path, monkeypatch, capsys):
    _write_secret_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert appmod.main([".", "--no-color", "--verbose"]) == 1
    human = capsys.readouterr().out
    assert appmod.main([".", "--json"]) == 1
    blob = capsys.readouterr().out
    assert appmod.main([".", "--quiet", "--no-color"]) == 1
    quiet = capsys.readouterr().out
    for raw in ALL_RAW_SECRETS:
        assert raw not in human, raw[:12]
        assert raw not in blob, raw[:12]
        assert raw not in quiet, raw[:12]
    _report = json.loads(blob)  # must remain valid JSON
    assert "MIIE" not in blob


def test_escape_in_finding_path_neutralized_without_filesystem():
    # Same guarantee as above, but without needing an exotic filename on disk.
    from secretsieve.models.finding import build_finding
    from secretsieve.models.stats import ScanStats
    from secretsieve.reporting.human import render_human

    evil_path = "src/evil\x1b[2J\x1b]0;pwned\x07.py"
    f = build_finding(
        rule_id="SS-GENERIC-002", detector="generic", provider="generic",
        category="password", severity="LOW", confidence=45, path=evil_path,
        line=3, column=12, end_column=19, raw_value="hunter2",
        redacted="********", reason="secret assignment + credential context",
        reason_codes=["strong_context"], context_key="password",
    )
    text = render_human(findings=[f], stats=ScanStats(), version="t", targets=["."],
                        duration_ms=1, exit_code=1, use_color=False, quiet=False,
                        verbose=False, warnings=[], file_errors=[])
    # No attacker-controlled bytes survive (own color framing stays off here).
    assert "\x1b" not in text
    assert "hunter2" not in text
    assert "pwned" not in text


def test_config_abuse_is_exit_2(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    bad = tmp_path / "bad.toml"
    bad.write_text("[output]\nunknown_key_xyz = 1\n", encoding="utf-8")
    assert appmod.main([".", "--config", str(bad)]) == 2
    bad.write_text("[[custom_rule]]\nid='SS-CUSTOM-001'\n", encoding="utf-8")
    assert appmod.main([".", "--config", str(bad)]) == 2
    with pytest.raises(SystemExit):
        appmod.main([".", "--severity", "bogus"])


def test_symlink_loop_terminates(tmp_path, monkeypatch):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "ok.py").write_text("x = 1\n", encoding="utf-8")
    try:
        os.symlink(str(b), str(a / "loop"))
        os.symlink(str(a), str(b / "loop"))
    except OSError:
        pytest.skip("symlinks unavailable")
    monkeypatch.chdir(tmp_path)
    outcome_rc = appmod.main([".", "--no-config"])
    assert outcome_rc in (0, 1)


def test_no_shell_true_or_raw_prints_in_reporters():
    import pathlib

    hits = []
    for py in pathlib.Path("src/secretsieve/reporting").rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        if "shell=True" in text:
            hits.append(str(py))
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("print(") and "value" in s and "redact" not in s and "version" not in s:
                hits.append(f"{py}:{s[:80]}")
    assert hits == []
