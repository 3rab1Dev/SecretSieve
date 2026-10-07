"""CLI: exit codes, gates, display filters, output modes, helpers."""

import json

import pytest

from secretsieve.cli import app as appmod
from tests.conftest import FAKE_GITHUB_TOKEN


@pytest.fixture
def clean_tree(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def secret_tree(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    (tmp_path / "cfg.py").write_text('password = "hunter2"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_clean_is_zero(clean_tree):
    assert appmod.main(["."]) == 0
    assert appmod.main(["scan", "."]) == 0


def test_findings_is_one(secret_tree):
    assert appmod.main(["."]) == 1


def test_bad_path_is_two(clean_tree):
    assert appmod.main(["/no/such/path-xyz"]) == 2


def test_bad_config_is_two(clean_tree):
    bad = clean_tree / "bad.toml"
    bad.write_text("[output]\nfail_on = 'nope'\n", encoding="utf-8")
    assert appmod.main([".", "--config", str(bad)]) == 2


def test_fail_on_critical_ignores_low(secret_tree):
    # Tree has CRITICAL + LOW: gate on critical still fires...
    assert appmod.main([".", "--fail-on", "critical"]) == 1


def test_fail_on_high_with_only_low(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text('password = "hunter2"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert appmod.main([".", "--fail-on", "high"]) == 0
    assert appmod.main([".", "--fail-on", "low"]) == 1


def test_display_filter_does_not_change_gate(secret_tree, capsys):
    # --severity hides MEDIUM/LOW from display but the gate still fires.
    rc = appmod.main([".", "--severity", "critical", "--no-color"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "hunter2" not in out and "LOW" not in out


def test_min_confidence_display_only(secret_tree, capsys):
    rc = appmod.main([".", "--min-confidence", "99", "--no-color"])
    assert rc == 1  # gate still sees the CRITICAL 99 finding... and low is hidden
    out = capsys.readouterr().out
    assert "Generic Secret" not in out


def test_quiet_lists_findings(secret_tree, capsys):
    assert appmod.main([".", "--quiet", "--no-color"]) == 1
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2 and all("conf=" in ln for ln in lines)


def test_json_schema_and_redaction(secret_tree, capsys):
    assert appmod.main([".", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "secretsieve" and report["schema_version"] == 1
    assert report["exit_code"] == 1
    blob = json.dumps(report)
    assert FAKE_GITHUB_TOKEN not in blob
    finding = next(f for f in report["findings"] if f["rule_id"] == "SS-GITHUB-001")
    assert finding["severity"] == "CRITICAL" and finding["confidence"] == 99
    assert finding["value_hash"].startswith("sha256:")


def test_output_file(secret_tree, tmp_path, capsys):
    dest = tmp_path / "report.json"
    assert appmod.main([".", "--json", "--output", str(dest)]) == 1
    assert json.loads(dest.read_text(encoding="utf-8"))["tool"] == "secretsieve"


def test_output_requires_json(secret_tree, tmp_path):
    assert appmod.main([".", "--output", str(tmp_path / "r.json")]) == 2


def test_disable_rule(secret_tree, capsys):
    # Disabling the provider rule leaves the generic fallback (layered defense)...
    assert appmod.main([".", "--disable-rule", "SS-GITHUB-001", "--json", "--no-config"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert "SS-GITHUB-001" not in {f["rule_id"] for f in report["findings"]}
    assert "SS-GENERIC-001" in {f["rule_id"] for f in report["findings"]}
    # ...disabling the fallback too goes quiet.
    assert appmod.main([".", "--disable-rule", "SS-GITHUB-001", "--disable-rule",
                        "SS-GENERIC-001", "--disable-rule", "SS-GENERIC-002", "--no-color"]) == 0


def test_exclude_and_include(secret_tree):
    assert appmod.main([".", "--exclude", "app.py", "--exclude", "cfg.py"]) == 0
    assert appmod.main([".", "--include", "*.nomatch"]) == 0


def test_rules_and_explain(capsys):
    assert appmod.main(["rules", "--list"]) == 0
    assert "SS-GITHUB-001" in capsys.readouterr().out
    assert appmod.main(["explain", "SS-GITHUB-001"]) == 0
    assert appmod.main(["explain", "SS-NOPE-001"]) == 2
    assert appmod.main(["rules", "--show", "SS-JWT-001"]) == 0


def test_config_init_and_validate(capsys, clean_tree):
    assert appmod.main(["config", "--init"]) == 0
    assert "[scan]" in capsys.readouterr().out
    assert appmod.main(["config", "--validate"]) == 0


def test_no_config_flag(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text(f"t = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    (tmp_path / "secretsieve.toml").write_text('[rules]\ndisabled = ["SS-GITHUB-001"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert appmod.main(["."]) == 0  # file config disables the only rule
    assert appmod.main([".", "--no-config"]) == 1


def test_allowlist_fingerprint(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.py").write_text(f"t = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert appmod.main([".", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    fp = next(f for f in report["findings"] if f["rule_id"] == "SS-GITHUB-001")["fingerprint"]
    (tmp_path / "secretsieve.toml").write_text(
        '[[allow.fingerprint]]\nvalue = "' + fp + '"\n', encoding="utf-8")
    assert appmod.main(["."]) == 0


def test_inline_ignore(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text(f"t = '{FAKE_GITHUB_TOKEN}'  # secretsieve:ignore\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert appmod.main(["."]) == 0
