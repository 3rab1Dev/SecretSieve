"""Rule model: frozen dataclass + severity/category vocabularies."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

CATEGORIES = (
    "api_token",
    "api_key",
    "private_key",
    "db_credential",
    "connection_string",
    "password",
    "webhook_secret",
    "bearer",
    "jwt",
    "env_secret",
    "oauth_secret",
)


@dataclass(frozen=True)
class Rule:
    """A single detection rule.

    ``pattern`` is a precompiled regex with exactly one "value" capture
    intent: either group 0 (whole match is the secret, e.g. ``ghp_...``)
    or a named group ``value`` / group 1 holding the secret portion of an
    assignment match. The engine resolves this via :func:`extract_secret`.
    """

    id: str
    name: str
    provider: str
    category: str
    severity: str
    base_confidence: int
    pattern_src: str
    pattern: re.Pattern[str] = field(compare=False, repr=False)
    validator: str | None = None
    context_required: bool = False
    entropy_profile: str = "mixed"  # base64 | hex | mixed | none
    keywords: tuple[str, ...] = ()
    description: str = ""
    remediation: str = ""
    fp_notes: str = ""
    version: int = 1
    flags: int = 0  # re flags used at compile time

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"bad severity: {self.severity}")
        if not (0 <= self.base_confidence <= 99):
            raise ValueError(f"bad base_confidence: {self.base_confidence}")


def compile_rule(
    rule_id: str,
    name: str,
    provider: str,
    category: str,
    severity: str,
    pattern: str,
    base_confidence: int,
    validator: str | None = None,
    context_required: bool = False,
    entropy_profile: str = "mixed",
    keywords: tuple[str, ...] = (),
    description: str = "",
    remediation: str = "",
    fp_notes: str = "",
    ignore_case: bool = False,
) -> Rule:
    flags = re.ASCII
    if ignore_case:
        flags |= re.IGNORECASE
    return Rule(
        id=rule_id,
        name=name,
        provider=provider,
        category=category,
        severity=severity,
        base_confidence=base_confidence,
        pattern_src=pattern,
        pattern=re.compile(pattern, flags),
        validator=validator,
        context_required=context_required,
        entropy_profile=entropy_profile,
        keywords=tuple(keywords),
        description=description,
        remediation=remediation,
        fp_notes=fp_notes,
    )


def extract_secret(rule: Rule, match: re.Match[str]) -> tuple[str, int, int]:
    """Return ``(secret_value, span_start, span_end)`` for a rule match.

    Prefers a ``value`` named group, then group 1 (when the rule has more
    than one group), else the whole match.
    """
    try:
        gd = match.groupdict()
        if "value" in gd and gd["value"]:
            return gd["value"], match.start("value"), match.end("value")
    except Exception:
        pass
    try:
        if match.lastindex and match.lastindex >= 1:
            g1 = match.group(1)
            if g1:
                return g1, match.start(1), match.end(1)
    except Exception:
        pass
    return match.group(0), match.start(), match.end()
