"""Bounded text reading: whole-file bytes (size-gated) -> decoded lines."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secretsieve.scanner.gating import SNIFF_BYTES, detect_decode, sniff_is_binary

# Byte-order marks that prove text intent: a UTF-16/32 file full of NUL
# bytes is still text, so BOM wins over the binary sniff below.
_KNOWN_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")


@dataclass
class ReadResult:
    lines: list[tuple[int, str, bool]]  # (lineno, text, truncated)
    encoding: str
    truncated: bool  # any line truncated
    skipped_reason: str | None = None  # binary | oversize | unreadable


def read_lines(
    abs_path: Path,
    *,
    max_file_bytes: int,
    max_line_len: int,
) -> ReadResult:
    try:
        size = abs_path.stat().st_size
    except OSError:
        return ReadResult([], "unknown", False, skipped_reason="unreadable")
    if size > max_file_bytes:
        return ReadResult([], "unknown", False, skipped_reason="oversize")
    try:
        with open(abs_path, "rb") as fh:
            head = fh.read(SNIFF_BYTES + 1)
            if sniff_is_binary(head) and not head.startswith(_KNOWN_BOMS):
                return ReadResult([], "binary", False, skipped_reason="binary")
            rest = fh.read(max_file_bytes - len(head) + 1)
            raw = head + rest
    except OSError:
        return ReadResult([], "unknown", False, skipped_reason="unreadable")
    text, encoding = detect_decode(raw)
    out: list[tuple[int, str, bool]] = []
    truncated_any = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        # Strip a trailing \r left over from CRLF splitting edge cases.
        if line.endswith("\r"):
            line = line[:-1]
        if len(line) > max_line_len:
            out.append((lineno, line[:max_line_len], True))
            truncated_any = True
        else:
            out.append((lineno, line, False))
    return ReadResult(out, encoding, truncated_any)
