"""Finding model: immutable, redacted at construction, stable fingerprint."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

from secretsieve.models.rule import SEVERITY_RANK
from secretsieve.utils.redact import hash_value


def confidence_band(confidence: int) -> str:
    if confidence >= 90:
        return "very-high"
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def make_fingerprint(rule_id: str, norm_path: str, line: int, column: int, value_hash: str) -> str:
    """Stable dedup key per PLAN Sec. 20.1 (reveals nothing about the secret)."""
    norm = norm_path.replace("\\", "/")
    blob = f"{rule_id}\x00{norm}\x00{line}\x00{column}\x00{value_hash}"
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class Finding:
    id: str
    fingerprint: str
    rule_id: str
    detector: str  # signature | generic
    provider: str
    category: str
    severity: str
    confidence: int
    confidence_band: str
    path: str  # posix path relative to scan root
    line: int
    column: int
    end_column: int | None
    redacted: str
    value_hash: str
    reason: str
    reason_codes: tuple[str, ...]
    context_key: str | None
    generated: bool = False
    truncated: bool = False

    def sort_key(self) -> tuple[int, int, str, int, int, str]:
        return (
            SEVERITY_RANK.get(self.severity, 99),
            -self.confidence,
            self.path,
            self.line,
            self.column,
            self.rule_id,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "detector": self.detector,
            "provider": self.provider,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_band": self.confidence_band,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_column": self.end_column,
            "redacted": self.redacted,
            "value_hash": self.value_hash,
            "reason": self.reason,
            "reason_codes": list(self.reason_codes),
            "context_key": self.context_key,
            "generated": self.generated,
            "truncated": self.truncated,
        }


def build_finding(
    *,
    rule_id: str,
    detector: str,
    provider: str,
    category: str,
    severity: str,
    confidence: int,
    path: str,
    line: int,
    column: int,
    end_column: int | None,
    raw_value: str,
    redacted: str,
    reason: str,
    reason_codes: list[str],
    context_key: str | None,
    generated: bool = False,
    truncated: bool = False,
) -> Finding:
    """Construct a Finding; the raw value is hashed, never stored."""
    confidence = max(0, min(99, int(confidence)))
    vhash = hash_value(raw_value)
    norm = path.replace("\\", "/")
    return Finding(
        id="f-" + uuid.uuid4().hex[:12],
        fingerprint=make_fingerprint(rule_id, norm, line, column, vhash),
        rule_id=rule_id,
        detector=detector,
        provider=provider,
        category=category,
        severity=severity,
        confidence=confidence,
        confidence_band=confidence_band(confidence),
        path=norm,
        line=line,
        column=column,
        end_column=end_column,
        redacted=redacted,
        value_hash=vhash,
        reason=reason,
        reason_codes=tuple(reason_codes),
        context_key=context_key,
        generated=generated,
        truncated=truncated,
    )
