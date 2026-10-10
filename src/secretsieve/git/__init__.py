"""Local Git file-list support (L1).

Working-tree scanning needs no Git at all. ``--unstaged`` resolves worktree
paths and reuses the file pipeline. ``--staged`` scans the exact blobs stored
in Git's index (via ``:<path>`` plumbing) — never working-tree bytes — so
partially staged files are evaluated as staged, exclusively.
History scanning (L2/L3) remains future work.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(Exception):
    """Clean Git failure (maps to exit code 2 with a one-line message)."""


def _run_git(args: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found (needed for --staged/--unstaged)") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git command timed out") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        hint = detail[0][:200] if detail else "unknown git error"
        raise GitError(f"git failed: {hint}")
    return proc.stdout


def _run_git_bytes(args: list[str], cwd: Path, what: str) -> bytes:
    """Run Git plumbing returning raw bytes (paths and blobs, NUL-separated)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            timeout=60,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found (needed for --staged/--unstaged)") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git command timed out") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        hint = detail[0][:200] if detail else "unknown git error"
        raise GitError(f"git failed while reading {what}: {hint}")
    return proc.stdout


@dataclass(frozen=True)
class StagedEntry:
    """One staged path with its index status (R entries carry the new path)."""

    path: str
    status: str  # A | C | M | R | T


def _decode_path(raw: bytes) -> str:
    # Git -z paths are raw bytes; non-UTF-8 bytes degrade to U+FFFD rather
    # than raising. Slashes are normalized for downstream matching.
    return raw.decode("utf-8", errors="replace").replace("\\", "/")


def parse_name_status_z(raw: bytes) -> list[StagedEntry]:
    """Parse ``git diff --name-status -z`` output (rename pairs included)."""
    fields = [f for f in raw.split(b"\0") if f]
    entries: list[StagedEntry] = []
    i = 0
    while i < len(fields):
        status = fields[i].decode("ascii", errors="replace")
        code = status[0] if status else "?"
        if code in ("R", "C") and i + 2 < len(fields):
            # Rename/copy: old path, then new path. The index content lives
            # under the new path.
            entries.append(StagedEntry(path=_decode_path(fields[i + 2]), status=code))
            i += 3
        elif i + 1 < len(fields):
            entries.append(StagedEntry(path=_decode_path(fields[i + 1]), status=code))
            i += 2
        else:
            i += 1
    return entries


def get_staged_entries(cwd: Path) -> list[StagedEntry]:
    """Staged additions, copies, modifications, renames, type-changes.

    Deletions carry no index content and are therefore absent by design
    (consistent with Git index semantics: there is nothing to scan).
    """
    raw = _run_git_bytes(
        ["diff", "--cached", "--name-status", "-z", "--diff-filter=ACMRT"], cwd, "staged changes"
    )
    return parse_name_status_z(raw)


def read_staged_blob(cwd: Path, path: str) -> bytes:
    """Read the exact index blob for ``path`` via ``:<path>`` plumbing.

    Raises :class:`GitError` when the blob cannot be read. Callers must NOT
    fall back to working-tree bytes (that would silently scan the wrong
    content for partially staged files).
    """
    try:
        proc = subprocess.run(
            ["git", "cat-file", "-p", f":{path}"],
            cwd=str(cwd),
            capture_output=True,
            timeout=60,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found (needed for --staged)") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git timed out reading staged blob '{path}'") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        hint = detail[0][:200] if detail else "blob not found in index"
        raise GitError(f"cannot read staged blob '{path}': {hint}")
    return proc.stdout


def get_staged_files(cwd: Path) -> list[str]:
    """Paths staged in the index (added/copied/modified/renamed; renames use the new path)."""
    return [e.path for e in get_staged_entries(cwd)]


def get_unstaged_files(cwd: Path) -> list[str]:
    """Tracked working-tree files with unstaged modifications + untracked (non-ignored)."""
    modified = _run_git(["diff", "--name-only", "-z", "--diff-filter=ACM"], cwd).split("\0")
    try:
        untracked = _run_git(["ls-files", "--others", "--exclude-standard", "-z"], cwd).split("\0")
    except GitError:
        untracked = []
    seen: list[str] = []
    for p in (*modified, *untracked):
        if p and p not in seen:
            seen.append(p)
    return seen
