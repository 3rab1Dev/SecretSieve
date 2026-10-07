"""JSON report builder - schema version 1 (PLAN Sec. 26.2).

Schema is additive-only within major version 1. Raw secret values MUST NOT
appear anywhere in this document (only ``redacted`` + ``value_hash``).
"""

from __future__ import annotations

from datetime import datetime, timezone

from secretsieve.models.finding import Finding
from secretsieve.models.stats import ScanStats


def build_report(
    *,
    version: str,
    scan_root: str,
    duration_ms: int,
    stats: ScanStats,
    findings: list[Finding],
    config_snapshot: dict,
    exit_code: int,
    warnings: list[str],
) -> dict:
    return {
        "tool": "secretsieve",
        "version": version,
        "schema_version": 1,
        "scan_root": scan_root,
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_ms": duration_ms,
        "stats": stats.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "config_snapshot": config_snapshot,
        "warnings": list(warnings),
        "exit_code": exit_code,
    }


# Canonical field order lock (tests assert exact key sets, not order).
TOP_LEVEL_KEYS = frozenset(
    {"tool", "version", "schema_version", "scan_root", "started_at",
     "duration_ms", "stats", "findings", "config_snapshot", "warnings", "exit_code"}
)

FINDING_KEYS = frozenset(
    {"id", "fingerprint", "rule_id", "detector", "provider", "category",
     "severity", "confidence", "confidence_band", "path", "line", "column",
     "end_column", "redacted", "value_hash", "reason", "reason_codes",
     "context_key", "generated", "truncated"}
)
