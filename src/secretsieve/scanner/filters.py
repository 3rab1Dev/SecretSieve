"""Include/exclude filtering (PLAN Sec. 19).

Precedence:
1. ``.git/`` is always excluded (cannot be overridden).
2. Default excluded dirs (unless ``--no-default-excludes`` or explicit path arg).
3. User ``--exclude`` globs (append to defaults).
4. User ``--include`` globs (allowlist applied after excludes).
5. An explicitly-passed path argument is scanned even if it would be
   excluded by descent rules (with a warning).
"""

from __future__ import annotations

from secretsieve.scanner import filetypes
from secretsieve.utils.paths import match_glob

ALWAYS_EXCLUDE_DIRS = frozenset({".git"})

DEFAULT_EXCLUDE_DIRS = (
    "node_modules/**",
    "dist/**",
    "build/**",
    "out/**",
    ".venv/**",
    "venv/**",
    "__pycache__/**",
    ".tox/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    "vendor/**",
    "target/**",
    ".idea/**",
    ".vscode/**",
)


def dir_is_always_excluded(dirname: str) -> bool:
    return dirname in ALWAYS_EXCLUDE_DIRS


def is_excluded_by_defaults(rel_path: str) -> bool:
    """Fast top-segment check: every default pattern is ``<dirname>/**``."""
    rel = rel_path.replace("\\", "/")
    first, _, _ = rel.partition("/")
    return first in _DEFAULT_TOP_DIRS


_DEFAULT_TOP_DIRS = frozenset(p.split("/")[0] for p in DEFAULT_EXCLUDE_DIRS)


def should_scan_file(
    rel_path: str,
    *,
    extra_exclude: list[str],
    include: list[str],
    no_default_excludes: bool,
    is_explicit_arg: bool = False,
) -> tuple[bool, str | None]:
    """Decide whether a file path should be scanned.

    Returns ``(True, None)`` or ``(False, reason)`` where reason is one of
    ``excluded`` / ``extension``.
    """
    rel = rel_path.replace("\\", "/")
    if is_explicit_arg:
        # Explicit args bypass directory exclusions but never binary skips.
        if filetypes.is_binary_extension(rel):
            return False, "extension"
        return True, None
    if not no_default_excludes and is_excluded_by_defaults(rel):
        return False, "excluded"
    for pat in extra_exclude:
        if match_glob(rel, pat):
            return False, "excluded"
    if include:
        from secretsieve.utils.paths import matches_any

        if not matches_any(rel, include):
            return False, "excluded"
    if filetypes.is_binary_extension(rel):
        return False, "extension"
    return True, None
