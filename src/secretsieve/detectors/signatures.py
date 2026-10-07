"""Signature matching loop: prefilter gate + per-rule regex scan.

Linear-time discipline: all patterns bounded, precompiled once, `re.ASCII`
where set. No nested quantifiers anywhere in rule patterns.
"""

from __future__ import annotations

import re

from secretsieve.models.rule import Rule, extract_secret
from secretsieve.rules import RULE_REGISTRY, SECRET_PREFILTER


def line_needs_full_scan(
    line: str,
    rel_path: str,
    *,
    is_dotenv: bool = False,
    is_secret_file: bool = False,
) -> bool:
    """True when the cheap prefilter hits or the file type demands full scan."""
    # Dotenv / secret-named files always run the full rule set: their
    # KEY=value lines often lack trigger words (e.g. ``DB=mongodb://...``).
    if is_dotenv or is_secret_file:
        return True
    # Fast literal pre-gate (C-speed substring checks) before the regex:
    # every Tier-1/2 true-positive line carries at least one of these.
    if not _has_literal(line):
        return False
    return bool(SECRET_PREFILTER.search(line))


# Lowercase literals; checked against ``line.casefold()``. Kept in a tuple
# (faster iteration than a set for short-circuit ``in`` scans).
_LITERALS = (
    "akia", "ghp_", "gho_", "github_pat_", "glpat-", "xoxb-", "xoxp-",
    "xoxa-", "xoxs-", "sk_live_", "sk_test_", "pk_live_", "pk_test_",
    "sk-", "-----begin", "eyj", "bearer", "password", "passwd", "pwd",
    "secret", "api_key", "apikey", "api-key", "api_token", "access_token",
    "auth_token", "token", "aiza", "service_account", "accountkey", "npm_",
    "pypi-", "sg.", "://", "webhook", "client_secret", "database_url",
    "connection_string", "export ", "discord", "twilio", "stripe", "slack",
    "github", "gitlab", "azure", "openai", "sendgrid", "private_key", "pem",
)


def _has_literal(line: str) -> bool:
    low = line.casefold()
    for lit in _LITERALS:
        if lit in low:
            return True
    return False


def iter_matches(
    line: str,
    rules: list[Rule],
    *,
    max_per_line: int = 20,
) -> list[tuple[Rule, re.Match[str]]]:
    """Yield ``(rule, match)`` pairs for one line (bounded)."""
    out: list[tuple[Rule, re.Match[str]]] = []
    for rule in rules:
        try:
            for match in rule.pattern.finditer(line):
                out.append((rule, match))
                if len(out) >= max_per_line:
                    return out
        except Exception:
            continue
    return out


__all__ = ["RULE_REGISTRY", "SECRET_PREFILTER", "line_needs_full_scan", "iter_matches", "extract_secret"]
