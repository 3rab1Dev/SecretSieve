"""False-positive gates (PLAN Sec. 16). Ordered: first match wins.

Every suppression is counted in ``stats.suppressed`` for ``--verbose``
audit. Nothing is silently dropped.
"""

from __future__ import annotations

import re

# Case-insensitive placeholder fragments (whole value or substring).
PLACEHOLDER_FRAGMENTS = (
    "example", "sample", "placeholder", "dummy", "changeme", "change_me",
    "yourkeyhere", "your_key_here", "insert_key_here", "replace_me", "replace-me",
    "testkey", "test_key", "fake", "mock", "todo", "lorem", "abcdef",
    "password123", "123456", "qwerty", "asdfgh", "redacted",
    "xxx", "***",
)

PLACEHOLDER_EXACT = frozenset(
    {"", "null", "none", "undefined", "nil", "nil;", "n/a", "na", "tbd", "changeme", "password", "test", "secret"}
)

EMPTY_DEFAULTS = frozenset({"", "null", "none", "undefined", "nil", "n/a", "na", "<empty>"})

_HASH_RES = (
    re.compile(r"^[0-9a-fA-F]{32}$"),
    re.compile(r"^[0-9a-fA-F]{40}$"),
    re.compile(r"^[0-9a-fA-F]{64}$"),
)
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_REPEATED_RE = re.compile(r"^(.)\1{7,}$")
_DATA_URI_RE = re.compile(r"(?i)data:(?:image|font|video|audio)/[^;,]+;base64,")
_CSS_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+[-+.\w]*$")
_ARN_RE = re.compile(r"^arn:aws:[a-z0-9\-]*:\d{0,12}:")
_STRIPE_PUBLIC_ID_RE = re.compile(r"^(cus|price|prod|sub|evt|ch|in|acct)_[A-Za-z0-9]+$")

IGNORE_TOKEN = "secretsieve:ignore"


def _strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"', "`"):
        v = v[1:-1]
    return v.strip()


def is_placeholder(value: str, extra: list[str] | tuple[str, ...] = ()) -> bool:
    v = _strip_quotes(value)
    low = v.casefold()
    if low in PLACEHOLDER_EXACT:
        return True
    if _REPEATED_RE.match(v):
        return True
    # Uppercase docs marker (AWS AKIA...EXAMPLE, ghp_EXAMPLE..., Stripe docs).
    # Real random secrets essentially never contain a literal "EXAMPLE".
    if "EXAMPLE" in v:
        return True
    frags: list[str] = list(PLACEHOLDER_FRAGMENTS)
    if extra:
        frags.extend(extra)
    fragments = [f.casefold() for f in frags if f]
    for frag in fragments:
        if not frag:
            continue
        if frag == low:
            return True  # whole-value dummy (e.g. "password123", "changeme")
        if frag not in low:
            continue
        # Short fragments (abcdef, xxx, 123456, ...) only count when they
        # dominate the value; otherwise any 36-char token containing an
        # incidental "abcdef" run would be wrongly suppressed.
        if len(frag) >= 8 or len(v) <= 16 or len(frag) * 2 >= len(v):
            return True
    return False


def is_empty_or_default(value: str, key: str | None = None) -> bool:
    v = _strip_quotes(value)
    if v.casefold() in EMPTY_DEFAULTS:
        return True
    if key and key.casefold() in ("admin", "root", "user") and v.casefold() in ("admin", "root", "user", "password"):
        return True
    return False


def is_hash(value: str) -> bool:
    v = _strip_quotes(value)
    return any(r.match(v) for r in _HASH_RES)


def is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(_strip_quotes(value)))


def is_css_color(value: str) -> bool:
    return bool(_CSS_COLOR_RE.match(_strip_quotes(value)))


def is_version_string(value: str) -> bool:
    return bool(_VERSION_RE.match(_strip_quotes(value)))


def is_public_identifier(value: str) -> bool:
    v = _strip_quotes(value)
    return bool(_ARN_RE.match(v) or _STRIPE_PUBLIC_ID_RE.match(v))


def has_data_uri(line: str) -> bool:
    return bool(_DATA_URI_RE.search(line))


def has_inline_ignore(line: str) -> bool:
    return IGNORE_TOKEN in line


def is_test_prefixed_value(value: str) -> bool:
    v = _strip_quotes(value).casefold()
    return v.startswith(("test_", "mock_", "fake_", "sample_", "example_", "dummy_"))


def is_template_value(value: str) -> bool:
    """Values with whitespace or {placeholders} are templates/prose, not secrets."""
    v = _strip_quotes(value)
    return any(ch.isspace() for ch in v) or ("{" in v or "}" in v)


def looks_like_jwt_unsigned_placeholder(token: str) -> bool:
    # Unsigned test JWTs widely pasted in docs are still flagged (unsigned is
    # meaningful) - this helper exists for reason-code clarity only.
    return False
