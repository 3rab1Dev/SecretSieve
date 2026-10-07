"""Secret redaction helpers.

Security contract (PLAN Sec. 25.2):
- The raw secret value must NEVER appear in terminal output, JSON output,
  logs, errors, or debug messages.
- Redaction happens at Finding construction time so reporters physically
  cannot leak the value (they only receive the redacted preview).
- Mask length is FIXED (16 stars) regardless of true value length so the
  preview does not disclose the real length.
"""

from __future__ import annotations

import hashlib

_MASK = "*" * 16


def hash_value(raw: str) -> str:
    """Return ``sha256:<hex>`` of the raw value for correlation without storage."""
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def redact(raw: str) -> str:
    """Redact a generic secret value.

    - len <= 8  -> ``********`` (fully masked)
    - else      -> first 4 chars + 16 stars + last 4 chars
    """
    if not raw:
        return "********"
    text = raw.strip().strip("\"'").strip()
    if len(text) <= 8:
        return "********"
    return f"{text[:4]}{_MASK}{text[-4:]}"


def redact_pem(header_line: str, body_bytes: int) -> str:
    """Redact a PEM block: show the header line only plus redacted size."""
    header = header_line.strip()
    return f"{header} [redacted {int(body_bytes)} bytes]"


def redact_db_url(url: str) -> str:
    """Redact the password segment of a database connection URL.

    Returns the URL with the password segment replaced by eight stars.
    Falls back to :func:`redact` when the URL has no parseable password.
    (Doc example uses an EXAMPLE marker so this source stays scan-clean.)
    """
    try:
        scheme, _, rest = url.partition("://")
        if not rest or "@" not in rest:
            return redact(url)
        userinfo, _, hostpart = rest.partition("@")
        if ":" not in userinfo:
            return redact(url)
        user, _, _password = userinfo.partition(":")
        return f"{scheme}://{user}:********@{hostpart}"
    except Exception:
        return redact(url)
