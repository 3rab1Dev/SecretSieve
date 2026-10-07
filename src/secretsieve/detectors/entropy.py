"""Shannon entropy analysis (PLAN Sec. 11).

Slogan: "High entropy + suspicious context + useful structural signals =
strong candidate. High entropy alone = nothing."

Entropy is computed ONLY on candidate values (never whole lines/files) and
contributes additively to confidence - it can never fire a finding alone.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]+={0,2}$")

MIN_LEN_BASE64 = 20
MIN_LEN_HEX = 32
MIN_LEN_MIXED = 16


def shannon(text: str) -> float:
    """Shannon entropy in bits/char. ``shannon("aaaa") == 0.0``."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_classes(text: str) -> set[str]:
    """Character classes present: lower/upper/digit/symbol/whitespace/non_ascii."""
    classes: set[str] = set()
    for ch in text:
        o = ord(ch)
        if o > 127:
            classes.add("non_ascii")
        elif ch.islower():
            classes.add("lower")
        elif ch.isupper():
            classes.add("upper")
        elif ch.isdigit():
            classes.add("digit")
        elif ch.isspace():
            classes.add("whitespace")
        else:
            classes.add("symbol")
    return classes


def has_enough_variety(text: str) -> bool:
    """Reject trivial strings (``aaaa…``, ``1111…``) before entropy math."""
    classes = char_classes(text)
    core = classes - {"whitespace"}
    if len(core) >= 2:
        return True
    # Single-class alphabets need length to be meaningful (hex/base64 digests).
    return len(text) >= 32 and core in ({"lower"}, {"upper"}, {"digit"}, {"non_ascii"}, {"symbol"})


def guess_encoding(text: str) -> str:
    """Guess ``hex`` | ``base64`` | ``base64url`` | ``other``."""
    s = text.strip()
    if not s:
        return "other"
    if _HEX_RE.match(s) and len(s) >= 8 and any(c.isdigit() for c in s) and any(
        c in "abcdefABCDEF" for c in s
    ):
        return "hex"
    if _B64_RE.match(s) and len(s) % 4 == 0 and len(s) >= 16:
        # Distinguish real base64 use: needs mixed alphabet or padding.
        if any(c.isdigit() for c in s) or "+" in s or "/" in s or s.endswith("="):
            return "base64"
    if _B64URL_RE.match(s) and ("-" in s or "_" in s) and len(s) >= 16:
        return "base64url"
    # Long digit+alpha mixes without symbols still behave like base64.
    if len(s) >= 20 and re.match(r"^[A-Za-z0-9]+$", s):
        has_lower = any(c.islower() for c in s)
        has_upper = any(c.isupper() for c in s)
        has_digit = any(c.isdigit() for c in s)
        if sum((has_lower, has_upper, has_digit)) >= 2:
            return "base64"
    if _HEX_RE.match(s) and len(s) >= 32:
        return "hex"
    return "other"


@dataclass
class EntropyResult:
    value: float
    encoding: str
    threshold: float
    margin: float
    passed: bool
    bonus: int


def effective_threshold(
    profile: str,
    *,
    base64_threshold: float,
    hex_threshold: float,
    mixed_threshold: float,
    strong_context: bool = False,
    benign_context: bool = False,
    generated: bool = False,
) -> float:
    if profile == "base64":
        base = base64_threshold
    elif profile == "hex":
        base = hex_threshold
    elif profile == "none":
        return float("inf")
    else:
        base = mixed_threshold
    if strong_context:
        base -= 0.4
    if benign_context:
        base += 0.5
    if generated:
        base += 0.5
    return base


def entropy_bonus(margin: float) -> int:
    if margin < 0:
        return 0
    if margin < 0.5:
        return 5
    if margin < 1.0:
        return 10
    return 15


def analyze(
    candidate: str,
    profile: str,
    *,
    base64_threshold: float = 4.5,
    hex_threshold: float = 3.7,
    mixed_threshold: float = 4.0,
    min_length: int = 16,
    strong_context: bool = False,
    benign_context: bool = False,
    generated: bool = False,
) -> EntropyResult:
    """Score one candidate value; never raises."""
    value = candidate.strip().strip("\"'").strip()
    encoding = guess_encoding(value)
    # Minimum lengths follow the observed encoding (a 40-hex digest is judged
    # as hex even when the rule profile is generic)...
    if encoding == "hex":
        required = max(MIN_LEN_HEX, min_length)
    elif encoding in ("base64", "base64url"):
        required = max(MIN_LEN_BASE64, min_length)
    else:
        required = max(MIN_LEN_MIXED, min_length)
    # ...but the THRESHOLD follows the rule's declared profile: a hex-shaped
    # Twilio key must clear the hex bar, not the base64 bar.
    if profile == "base64":
        eff_profile = "base64"
    elif profile == "hex":
        eff_profile = "hex"
    elif profile == "none":
        eff_profile = "none"
    else:
        eff_profile = {"hex": "hex", "base64": "base64", "base64url": "base64"}.get(encoding, "mixed")
    threshold = effective_threshold(
        eff_profile,
        base64_threshold=base64_threshold,
        hex_threshold=hex_threshold,
        mixed_threshold=mixed_threshold,
        strong_context=strong_context,
        benign_context=benign_context,
        generated=generated,
    )
    if len(value) < required or not has_enough_variety(value):
        return EntropyResult(0.0, encoding, threshold, -99.0, False, 0)
    h = shannon(value)
    margin = h - threshold
    passed = margin >= 0
    return EntropyResult(h, encoding, threshold, margin, passed, entropy_bonus(margin) if passed else 0)
