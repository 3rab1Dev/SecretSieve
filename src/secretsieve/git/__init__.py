"""Local Git file-list support (L1, v1.0 scope).

Working-tree scanning needs no Git at all. ``--staged`` / ``--unstaged``
resolve ``git diff --name-only`` to a path list and reuse the same file
pipeline. Blobs are read from the working tree (point-in-time); history
scanning (L2/L3) remains future work.
"""

from __future__ import annotations

import subprocess
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


def get_staged_files(cwd: Path) -> list[str]:
    """Paths staged in the index (added/copied/modified)."""
    out = _run_git(["diff", "--name-only", "--cached", "-z", "--diff-filter=ACM"], cwd)
    return [p for p in out.split("\0") if p]


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
