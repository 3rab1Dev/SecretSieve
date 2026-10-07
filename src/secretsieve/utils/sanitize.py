"""Terminal sanitization against escape / control-character injection.

PLAN Sec. 32.4: file paths, key names, reasons, and any other
attacker-controlled strings must be sanitized before rendering to a
terminal. This strips C0/C1 controls and ANSI CSI/OSC sequences and
truncates overlong fields.
"""

from __future__ import annotations

import re
import unicodedata

_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_C1_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

MAX_DISPLAY_LEN = 500


def sanitize_for_terminal(text: str | None, max_len: int = MAX_DISPLAY_LEN) -> str:
    """Return a terminal-safe rendering of attacker-controlled text."""
    if text is None:
        return ""
    s = str(text)
    s = _OSC_RE.sub("", s)
    s = _CSI_RE.sub("", s)
    s = s.replace("\x1b", "")
    # Neutralize bidirectional-override / tag characters used for spoofing.
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cf",))
    s = _C1_RE.sub("", s)
    s = s.replace("\r", " ").replace("\n", " ")
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s
