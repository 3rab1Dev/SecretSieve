"""Path helpers: resolution, posix-relative display paths, glob matching."""

from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath


def resolve_root(path: str | Path) -> Path:
    """Resolve a scan root to an absolute, normalized path."""
    return Path(path).expanduser().resolve()


def rel_posix(abs_path: Path, root: Path) -> str:
    """Return ``abs_path`` relative to ``root`` with posix separators.

    Falls back to the absolute posix path when the file is outside the root
    (e.g. a symlink target).
    """
    try:
        return abs_path.relative_to(root).as_posix()
    except ValueError:
        return abs_path.as_posix()


def match_glob(rel_path: str, pattern: str) -> bool:
    """Match a relative posix path against a gitignore-style glob.

    Supports ``**``, ``*``, ``?`` and ``[...]`` via fnmatch on both the full
    relative path and its basename (so ``*.log`` matches at any depth and
    ``build/**`` matches everything under ``build/``).
    """
    pat = pattern.replace("\\", "/").strip()
    rel = rel_path.strip()
    if not pat:
        return False
    # Trailing "/**" also matches the bare directory itself.
    candidates = [rel, rel.split("/")[0] if "/" in rel else rel]
    name = rel.rsplit("/", 1)[-1]
    patterns = [pat]
    if pat.endswith("/**"):
        patterns.append(pat[:-3])
    for p in patterns:
        for cand in candidates:
            if fnmatch.fnmatchcase(cand, p):
                return True
        # PurePosixPath.match handles "**" more correctly for nested paths.
        try:
            if PurePosixPath(rel).match(p):
                return True
        except Exception:
            pass
        if fnmatch.fnmatchcase(name, p.lstrip("/")):
            return True
    return False


def matches_any(rel_path: str, patterns: list[str]) -> bool:
    return any(match_glob(rel_path, p) for p in patterns)
