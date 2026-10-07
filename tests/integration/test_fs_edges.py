"""Integration: filesystem edge cases never crash the scanner."""

import os

import pytest

from secretsieve.models.config import Config
from secretsieve.scanner.orchestrator import run_scan


def test_empty_tree(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outcome = run_scan(["."], Config())
    assert outcome.findings == [] and outcome.stats.files_scanned == 0


def test_git_dir_never_descended(tmp_path, monkeypatch):
    from tests.conftest import FAKE_GITHUB_TOKEN

    monkeypatch.chdir(tmp_path)
    gitd = tmp_path / ".git" / "objects"
    gitd.mkdir(parents=True)
    (gitd / "pack").write_text(f"token {FAKE_GITHUB_TOKEN}\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('clean')\n", encoding="utf-8")
    outcome = run_scan(["."], Config())
    assert outcome.findings == []


def test_bom_utf16_and_odd_bytes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfprint('bom')\n")
    (tmp_path / "utf16.py").write_bytes("print('utf16')\n".encode("utf-16"))
    (tmp_path / "latin1.py").write_bytes(b"pass = 'caf\xe9'\n")
    outcome = run_scan(["."], Config())
    assert outcome.stats.files_errored == 0
    assert outcome.stats.files_scanned == 3


def test_single_huge_line_bounded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "huge.py").write_text("x = '" + "A" * (1024 * 1024) + "'\n", encoding="utf-8")
    outcome = run_scan(["."], Config())
    assert outcome.stats.truncated_files == 1
    assert outcome.stats.files_errored == 0


def test_deep_nesting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    deep = tmp_path
    for i in range(30):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "leaf.py").write_text("print('leaf')\n", encoding="utf-8")
    outcome = run_scan(["."], Config())
    assert outcome.stats.files_scanned == 1


def test_broken_symlink_counted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    try:
        os.symlink(str(tmp_path / "missing.py"), str(tmp_path / "broken.py"))
    except OSError:
        pytest.skip("symlinks unavailable")
    outcome = run_scan(["."], Config())
    assert outcome.stats.files_errored >= 1
    assert outcome.stats.files_scanned == 1
    assert outcome.findings == []


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        run_scan(["/definitely/not/here-12345"], Config())


def test_single_file_arg(tmp_path, monkeypatch):
    from tests.conftest import FAKE_GITHUB_TOKEN

    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.py").write_text(f"t = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    outcome = run_scan(["a.py"], Config())
    assert any(f.rule_id == "SS-GITHUB-001" for f in outcome.findings)
