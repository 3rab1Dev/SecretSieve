"""Binary / size / encoding gates (PLAN Sec. 17).

- Binary: first 8 KiB contains NUL -> ``skipped_binary``.
- Size: ``st_size > max_file_bytes`` -> ``skipped_oversize`` (stat before open).
- Encoding: explicit BOM table (utf-8-sig, utf-16 le/be, utf-32 le/be),
  else UTF-8 with ``errors=replace``. Never raises on decode.
"""

from __future__ import annotations

SNIFF_BYTES = 8192


def sniff_is_binary(head: bytes) -> bool:
    return b"\x00" in head


def detect_decode(raw: bytes) -> tuple[str, str]:
    """Return ``(text, encoding_name)`` for bounded file bytes."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if raw.startswith(b"\xff\xfe\x00\x00") or raw.startswith(b"\x00\x00\xfe\xff"):
        try:
            return raw.decode("utf-32", errors="replace"), "utf-32"
        except Exception:
            pass
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            return raw.decode("utf-16", errors="replace"), "utf-16"
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace"), "utf-8"
