"""Regression: --staged scans Git index blobs, never working-tree bytes.

All secrets below are synthetic fixtures (non-sensitive by construction).
Each test builds an isolated temporary Git repository; nothing touches the
network. Git-dependent tests skip only when Git is genuinely unavailable.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from secretsieve import git as gitmod
from secretsieve.cli import app as appmod
from tests.conftest import FAKE_GITHUB_TOKEN

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git executable not available")

TOKEN_B = "glpat-abcdefghij1234567890xYzQ9f8e7d"


def vhash(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=60,
    )


@pytest.fixture
def repo(tmp_path, monkeypatch):
    if GIT is None:
        pytest.skip("git executable not available")
    root = tmp_path / "repo"
    root.mkdir()
    assert git("init", cwd=root).returncode == 0
    assert git("config", "user.email", "test@example.invalid", cwd=root).returncode == 0
    assert git("config", "user.name", "SecretSieve Test", cwd=root).returncode == 0
    assert git("config", "commit.gpgsign", "false", cwd=root).returncode == 0
    monkeypatch.chdir(root)
    return root


def add(repo: Path, name: str, content: str) -> None:
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    assert git("add", "--", name, cwd=repo).returncode == 0


def staged_report(capsys, *args: str) -> tuple[int, dict]:
    rc = appmod.main(["--staged", "--json", "--no-config", *args])
    return rc, json.loads(capsys.readouterr().out)


def hashes(report: dict) -> set[str]:
    return {f["value_hash"] for f in report["findings"]}


@needs_git
def test_secret_staged_but_removed_from_worktree(repo, capsys):
    """The original bug: index secret invisible to worktree reads must fire."""
    add(repo, "app.py", f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n")
    (repo / "app.py").write_text("print('cleaned up')\n", encoding="utf-8")
    rc, report = staged_report(capsys)
    assert rc == 1
    assert vhash(FAKE_GITHUB_TOKEN) in hashes(report)
    assert FAKE_GITHUB_TOKEN not in json.dumps(report)


@needs_git
def test_partially_staged_file_uses_index_exclusively(repo, capsys):
    add(repo, "app.py", f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n")
    (repo / "app.py").write_text(f"OTHER = '{TOKEN_B}'\n", encoding="utf-8")
    rc, report = staged_report(capsys)
    assert rc == 1
    found = hashes(report)
    assert vhash(FAKE_GITHUB_TOKEN) in found
    assert vhash(TOKEN_B) not in found


@needs_git
def test_worktree_only_secret_not_reported(repo, capsys):
    (repo / "app.py").write_text("print('base')\n", encoding="utf-8")
    assert git("add", "--", "app.py", cwd=repo).returncode == 0
    assert git("commit", "-m", "base", cwd=repo).returncode == 0
    (repo / "app.py").write_text(f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    rc, report = staged_report(capsys)
    assert rc == 0
    assert report["findings"] == []


@needs_git
def test_staged_clean_worktree_dirty_not_reported(repo, capsys):
    (repo / "app.py").write_text("print('clean')\n", encoding="utf-8")
    assert git("add", "--", "app.py", cwd=repo).returncode == 0
    (repo / "app.py").write_text(f"password = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    rc, report = staged_report(capsys)
    assert rc == 0
    assert report["findings"] == []


@needs_git
def test_multiple_staged_files_each_scanned(repo, capsys):
    add(repo, "a.py", f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n")
    add(repo, "sub/b.py", f"OTHER = '{TOKEN_B}'\n")
    rc, report = staged_report(capsys)
    assert rc == 1
    found = hashes(report)
    assert vhash(FAKE_GITHUB_TOKEN) in found
    assert vhash(TOKEN_B) in found
    paths = sorted(f["path"] for f in report["findings"])
    assert paths == ["a.py", "sub/b.py"]


@needs_git
def test_staged_deletion_is_safe(repo, capsys):
    (repo / "gone.py").write_text(f"GITHUB_TOKEN = '{FAKE_GITHUB_TOKEN}'\n", encoding="utf-8")
    assert git("add", "--", "gone.py", cwd=repo).returncode == 0
    assert git("commit", "-m", "add", cwd=repo).returncode == 0
    assert git("rm", "--", "gone.py", cwd=repo).returncode == 0
    rc, report = staged_report(capsys)
    assert rc == 0
    assert report["findings"] == []


@needs_git
def test_filename_with_spaces(repo, capsys):
    name = "my keys/secret file.env"
    add(repo, name, f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}\n")
    rc, report = staged_report(capsys)
    assert rc == 1
    assert report["findings"][0]["path"] == name
    assert vhash(FAKE_GITHUB_TOKEN) in hashes(report)


@needs_git
def test_unusual_filename_characters(repo, capsys):
    name = "sëcret-ünïcødé.py"
    try:
        add(repo, name, f"t = '{TOKEN_B}'\n")
    except (OSError, UnicodeError):
        pytest.skip("platform cannot represent this filename")
    rc, report = staged_report(capsys)
    assert rc == 1
    assert vhash(TOKEN_B) in hashes(report)


@needs_git
def test_missing_blob_is_actionable_not_silent(repo, capsys):
    add(repo, "app.py", "print('x')\n")
    assert git("rm", "--cached", "--", "app.py", cwd=repo).returncode == 0
    with pytest.raises(gitmod.GitError, match="app.py"):
        gitmod.read_staged_blob(repo, "app.py")
    with pytest.raises(gitmod.GitError, match="missing"):
        gitmod.read_staged_blob(repo, "missing-entirely.py")


@needs_git
def test_staged_exclusions_still_apply(repo, capsys):
    (repo / "node_modules").mkdir()
    add(repo, "node_modules/lib.js", f"t = '{FAKE_GITHUB_TOKEN}'\n")
    add(repo, "ok.py", "print('fine')\n")
    rc, report = staged_report(capsys)
    assert rc == 0
    assert report["findings"] == []
    assert report["stats"]["skip_breakdown"]["excluded"] >= 1


def test_parse_name_status_z_units():
    assert gitmod.parse_name_status_z(b"") == []
    simple = gitmod.parse_name_status_z(b"M\0a.py\0A\0b.py\0")
    assert [(e.path, e.status) for e in simple] == [("a.py", "M"), ("b.py", "A")]
    renamed = gitmod.parse_name_status_z(b"R100\0old.py\0new.py\0")
    assert [(e.path, e.status) for e in renamed] == [("new.py", "R")]
    spaced = gitmod.parse_name_status_z(b"A\0my dir/f o o.py\0")
    assert spaced[0].path == "my dir/f o o.py"


def test_not_a_repo_is_actionable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(gitmod.GitError):
        gitmod.get_staged_entries(tmp_path)
