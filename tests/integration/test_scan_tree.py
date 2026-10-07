"""Integration: full-tree scan with mixed content, stats, ordering, redaction."""

import json

import pytest

from secretsieve.cli import app as appmod
from secretsieve.models.config import Config
from secretsieve.scanner.orchestrator import run_scan
from tests.conftest import (
    FAKE_AWS_KEY_ID, FAKE_AWS_SECRET, FAKE_DB_URL, FAKE_GITHUB_TOKEN, FAKE_JWT,
)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "src" / "app.py").write_text(f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    (tmp_path / "config" / "settings.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY_ID}"\naws_secret_access_key = "{FAKE_AWS_SECRET}"\n',
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(f'DATABASE_URL="{FAKE_DB_URL}"\n', encoding="utf-8")
    (tmp_path / "data.json").write_text('{"user": "app", "note": "nothing here"}', encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nENV APP_ENV=prod\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Demo\n\nUse `api_key = \"example-value\"` here.\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"fake")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text(f"var t = '{FAKE_JWT}';\n", encoding="utf-8")
    (tmp_path / "bundle.min.js").write_text("var chunk='9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d7e8f00112233';\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"": {"integrity": "sha512-9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d7e8f00112233445566778899aabbccddeeff"}}',
        encoding="utf-8",
    )
    try:
        import os
        os.symlink(str(tmp_path / "src" / "app.py"), str(tmp_path / "link_app.py"))
    except OSError:
        pass  # Windows without symlink privilege: skip link coverage
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_tree_findings_and_stats(tree):
    outcome = run_scan(["."], Config())
    by_rule = {}
    for f in outcome.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert "SS-GITHUB-001" in by_rule
    assert "SS-AWS-001" in by_rule and "SS-AWS-002" in by_rule
    assert "SS-DB-001" in by_rule
    # node_modules content must never surface.
    assert "SS-JWT-001" not in by_rule
    # Binary (extension pre-gate) + excluded counted, never scanned.
    assert outcome.stats.skip_binary + outcome.stats.skip_extension >= 1
    assert outcome.stats.skip_excluded >= 1
    assert outcome.stats.files_errored == 0
    # Deterministic ordering.
    keys = [f.sort_key() for f in outcome.findings]
    assert keys == sorted(keys)
    # Redaction: no raw secret in any rendered form.
    from secretsieve.reporting.human import render_human
    from secretsieve.reporting.json_report import build_report

    human = render_human(findings=outcome.findings, stats=outcome.stats, version="t",
                         targets=["."], duration_ms=1, exit_code=1, use_color=False,
                         quiet=False, verbose=True, warnings=[], file_errors=[])
    blob = json.dumps(build_report(version="t", scan_root=".", duration_ms=1, stats=outcome.stats,
                                   findings=outcome.findings, config_snapshot={}, exit_code=1, warnings=[]),
                      ensure_ascii=True)
    for raw in (FAKE_GITHUB_TOKEN, FAKE_AWS_SECRET, FAKE_DB_URL):
        assert raw not in human and raw not in blob


def test_tree_json_snapshot_keys(tree, capsys):
    rc = appmod.main(["scan", ".", "--json", "--no-config"])
    assert rc == 1
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["tool"] == "secretsieve" and report["schema_version"] == 1
    assert set(report["findings"][0].keys()) >= {
        "rule_id", "severity", "confidence", "path", "line", "redacted", "fingerprint", "value_hash",
    }
    assert "raw_value" not in json.dumps(report) and "value" not in report["findings"][0]


def test_oversize_and_extension_skips(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "small.txt").write_text("hello\n", encoding="utf-8")
    (tmp_path / "huge.txt").write_text("x" * 200, encoding="utf-8")
    cfg = Config(max_file_bytes=50)
    outcome = run_scan(["."], cfg)
    assert outcome.stats.skip_oversize >= 1
    assert outcome.stats.files_scanned >= 1
