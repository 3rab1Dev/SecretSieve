"""Confidence + severity scoring (PLAN Sec. 14-15).

Confidence = "is it real?" (0-99, deterministic, explainable).
Severity   = "how bad if real?" (intrinsic to rule + deployment context).

The two axes are orthogonal by construction: severity is NEVER a function
of confidence or entropy.
"""

from __future__ import annotations

from secretsieve.detectors import context as context_mod
from secretsieve.models.rule import SEVERITY_RANK


def confidence_band(confidence: int) -> str:
    if confidence >= 90:
        return "very-high"
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def compute_confidence(
    *,
    base: int,
    tier: str,
    entropy_bonus_pts: int = 0,
    struct_bonus: int = 0,
    pair_bonus: int = 0,
    penalties: int = 0,
) -> int:
    total = base + context_mod.context_confidence_delta(tier) + entropy_bonus_pts + struct_bonus + pair_bonus - penalties
    return max(0, min(99, total))


def demote(severity: str) -> str:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    try:
        idx = order.index(severity)
    except ValueError:
        return severity
    return order[min(idx + 1, len(order) - 1)]


def adjust_severity(
    base_severity: str,
    *,
    is_test: bool,
    is_docs: bool,
    is_example: bool,
    generated: bool,
    is_private_key: bool = False,
) -> tuple[str, list[str]]:
    """Apply deployment-context demotion caps. Returns (severity, cap_codes)."""
    sev = base_severity
    caps: list[str] = []
    if is_test or is_example:
        if sev != "INFO":
            sev = demote(sev)
            caps.append("test_or_example_demoted")
    if is_docs and not is_private_key:
        if sev != "INFO":
            sev = demote(sev)
            caps.append("docs_demoted")
    if generated:
        if sev != "INFO":
            sev = demote(sev)
            caps.append("generated_demoted")
    return sev, caps


def meets_fail_on(severity: str, fail_on: str) -> bool:
    """INFO never triggers a failure exit regardless of ``fail_on``."""
    if severity == "INFO":
        return False
    order = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    try:
        return order.index(severity) >= order.index(fail_on.upper())
    except ValueError:
        return False


def meets_floor(severity: str, floor: str) -> bool:
    order = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    try:
        return order.index(severity) >= order.index(floor.upper())
    except ValueError:
        return True


def severity_sort_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 99)
