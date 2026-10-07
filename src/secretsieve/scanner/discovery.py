"""Recursive path discovery (PLAN Sec. 17).

- Iterative ``os.scandir`` walk (no recursion-depth risk).
- Hidden files ARE included (``.env`` matters); ``.git/`` never descended.
- Directory symlinks not followed by default (``follow_symlinks`` opt-in).
- File symlinks scanned once under the link path; ``(st_dev, st_ino)``
  visited set prevents loops. Broken links -> ``files_errored``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from secretsieve.models.stats import ScanStats
from secretsieve.scanner import filters
from secretsieve.scanner import filetypes
from secretsieve.utils.paths import rel_posix


@dataclass
class FileRecord:
    abs_path: Path
    rel: str  # posix path relative to scan root
    is_explicit: bool = False
    generated: bool = False
    lockfile: bool = False


def _record_dir_skip(stats: ScanStats, reason: str) -> None:
    stats.files_skipped += 1
    if reason == "excluded":
        stats.skip_excluded += 1


def iter_files(
    roots: list[Path],
    scan_root: Path,
    *,
    extra_exclude: list[str],
    include: list[str],
    no_default_excludes: bool,
    follow_symlinks: bool,
    stats: ScanStats,
    warnings: list[str],
) -> list[FileRecord]:
    """Enumerate scannable files under ``roots`` (deterministic order)."""
    found: list[FileRecord] = []
    seen_inodes: set[tuple[int, int]] = set()

    def handle_file(path: Path, is_explicit: bool) -> None:
        try:
            rel = rel_posix(path, scan_root)
        except Exception:
            rel = path.as_posix()
        ok, reason = filters.should_scan_file(
            rel,
            extra_exclude=extra_exclude,
            include=include,
            no_default_excludes=no_default_excludes,
            is_explicit_arg=is_explicit,
        )
        if not ok:
            stats.files_skipped += 1
            if reason == "excluded":
                stats.skip_excluded += 1
            elif reason == "extension":
                stats.skip_extension += 1
            return
        # Loop / hardlink guard (best effort; missing stat -> scan anyway).
        try:
            st = path.stat() if follow_symlinks else os.lstat(path)
            key = (st.st_dev, st.st_ino)
            if key in seen_inodes:
                return
            seen_inodes.add(key)
        except OSError:
            pass
        found.append(
            FileRecord(
                abs_path=path,
                rel=rel,
                is_explicit=is_explicit,
                generated=filetypes.is_generated(rel),
                lockfile=filetypes.is_lockfile(rel),
            )
        )

    stack: list[tuple[Path, bool]] = [(r, True) for r in roots]
    while stack:
        current, is_root_arg = stack.pop()
        try:
            is_link = os.path.islink(current)
            if current.is_dir() and not (is_link and not follow_symlinks and not is_root_arg):
                if is_link and not follow_symlinks and not is_root_arg:
                    _record_dir_skip(stats, "excluded")
                    continue
                try:
                    with os.scandir(current) as it:
                        entries = sorted(it, key=lambda e: e.name)
                except OSError as exc:
                    stats.files_errored += 1
                    stats.errors.append(f"cannot list '{current}': {exc.strerror or exc}")
                    continue
                # Push in reverse so pop() yields sorted order.
                for entry in reversed(entries):
                    try:
                        name = entry.name
                        if entry.is_dir(follow_symlinks=False):
                            if filters.dir_is_always_excluded(name):
                                _record_dir_skip(stats, "excluded")
                                continue
                            child = Path(entry.path)
                            # Default-exclude check on the directory prefix.
                            try:
                                rel_dir = rel_posix(child, scan_root) + "/"
                            except Exception:
                                rel_dir = name + "/"
                            if (
                                not no_default_excludes
                                and filters.is_excluded_by_defaults(rel_dir.rstrip("/"))
                            ):
                                # Mark one skip for the directory itself.
                                _record_dir_skip(stats, "excluded")
                                continue
                            if os.path.islink(entry.path) and not follow_symlinks:
                                _record_dir_skip(stats, "excluded")
                                continue
                            stack.append((child, False))
                        elif entry.is_file(follow_symlinks=False) or os.path.islink(entry.path):
                            if os.path.islink(entry.path):
                                try:
                                    target = Path(entry.path).resolve()
                                    if target.is_dir():
                                        if not follow_symlinks:
                                            _record_dir_skip(stats, "excluded")
                                            continue
                                        stack.append((target, False))
                                        continue
                                except OSError:
                                    stats.files_errored += 1
                                    stats.errors.append(f"broken symlink: '{entry.path}'")
                                    continue
                            handle_file(Path(entry.path), False)
                        else:
                            continue
                    except OSError as exc:
                        stats.files_errored += 1
                        stats.errors.append(f"cannot access '{entry.path}': {exc.strerror or exc}")
            elif current.is_file() or os.path.islink(current):
                if os.path.islink(current) and not current.exists():
                    stats.files_errored += 1
                    stats.errors.append(f"broken symlink: '{current}'")
                    continue
                handle_file(current, True)
            else:
                stats.files_errored += 1
                stats.errors.append(f"not a file or directory: '{current}'")
        except OSError as exc:
            stats.files_errored += 1
            stats.errors.append(f"cannot access '{current}': {exc.strerror or exc}")

    found.sort(key=lambda r: r.rel)
    return found
