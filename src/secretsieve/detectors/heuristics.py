"""Deterministic structural validators (PLAN Sec. 13).

All validators are cheap, total, and side-effect free: JWT header decode,
database-URL parse, PEM framing. No network, no exceptions escaping.
"""

from __future__ import annotations

import base64
import json
import re

PEM_HEADER_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
PEM_FOOTER_RE = re.compile(r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
DB_SCHEMES = ("postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "amqp", "amqps")


def _b64url_decode(segment: str) -> dict | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def validate_jwt(token: str) -> tuple[bool, bool]:
    """Return ``(structurally_valid, is_unsigned_alg_none)``."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False, False
    header_b64, _payload_b64, signature = parts
    if not header_b64 or not parts[1]:
        return False, False
    if not re.fullmatch(r"[A-Za-z0-9\-_]+", header_b64) or not re.fullmatch(r"[A-Za-z0-9\-_]+", parts[1]):
        return False, False
    if signature and not re.fullmatch(r"[A-Za-z0-9\-_]+", signature):
        return False, False
    header = _b64url_decode(header_b64)
    if header is None:
        return False, False
    alg = str(header.get("alg", ""))
    if not alg:
        return False, False
    return True, alg.lower() == "none"


def parse_db_url(url: str) -> tuple[bool, str, str]:
    """Return ``(has_user_and_pass_and_host, user, host)``."""
    try:
        scheme, _, rest = url.partition("://")
        if scheme.lower().rstrip("ql") not in ("postgres", "postgre", "mysql", "mongodb", "mongodb+srv", "redis", "amqp", "amqps") and scheme.lower() not in DB_SCHEMES:
            # Accept any scheme here; the rule regex already gated the scheme.
            pass
        if "@" not in rest:
            return False, "", ""
        userinfo, _, hostpart = rest.partition("@")
        if ":" not in userinfo or not hostpart:
            return False, "", ""
        user, _, password = userinfo.partition(":")
        host = hostpart.split("/")[0].split("?")[0].split(";")[0]
        if not user or not password or not host:
            return False, "", ""
        return True, user, host
    except Exception:
        return False, "", ""


def stripe_variant(value: str) -> str:
    if value.startswith("sk_live_"):
        return "sk_live"
    if value.startswith("sk_test_"):
        return "sk_test"
    if value.startswith("pk_live_"):
        return "pk_live"
    if value.startswith("pk_test_"):
        return "pk_test"
    return "unknown"
