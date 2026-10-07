"""Output helpers: TTY color detection + renderer re-exports."""

from __future__ import annotations

import os
import sys

from secretsieve.reporting.human import render_human  # noqa: F401 - public re-export
from secretsieve.reporting.json_report import build_report  # noqa: F401 - public re-export


def should_use_color(no_color_flag: bool, json_mode: bool) -> bool:
    if no_color_flag or json_mode:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False
