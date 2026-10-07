"""Generic rules: SS-GENERIC-001/002/003/004 (context-gated catch-alls)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-GENERIC-001",
        name="Generic API Key Assignment",
        provider="generic",
        category="api_key",
        severity="MEDIUM",
        pattern=r"(?i)(?<![A-Za-z0-9_])(?:[A-Za-z0-9]+[_-])?(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|auth[_-]?token|token|secret|password|passwd|pwd)(?:[_-][A-Za-z0-9]+)?\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9_\-+=]{16,256})['\"]?",
        base_confidence=30,
        context_required=True,
        entropy_profile="mixed",
        keywords=("api_key", "apikey", "api_token", "access_token", "token"),
        description="api_key/api_token-style assignment with a random-looking value.",
        remediation="Move the key to environment/config management and rotate it.",
        fp_notes="Requires entropy threshold + non-placeholder value; never above MEDIUM alone. "
        "Whole-word token match only (monkey/keyboard style keys never match).",
    ),
    compile_rule(
        rule_id="SS-GENERIC-002",
        name="Generic Secret/Password Assignment",
        provider="generic",
        category="password",
        severity="MEDIUM",
        pattern=r"(?i)(?<![A-Za-z0-9_])(?:[A-Za-z0-9]+[_-])?(?:secret|passwd|password|pwd|pass)(?:[_-][A-Za-z0-9]+)?(?![A-Za-z0-9_])\s*[:=]\s*['\"](?P<value>[^'\"\r\n]{6,256})['\"]",
        base_confidence=30,
        context_required=True,
        entropy_profile="mixed",
        keywords=("secret", "password", "passwd", "pwd"),
        description="password/secret-style assignment. Short weak values land at LOW.",
        remediation="Replace hardcoded passwords with vault/env references and rotate.",
        fp_notes="Empty/dummy values suppressed; short weak passwords reported at LOW. "
        "Quoted values containing whitespace or {placeholders} are treated as "
        "templates/prose, never secrets.",
    ),
    compile_rule(
        rule_id="SS-GENERIC-003",
        name="Bearer Token",
        provider="generic",
        category="bearer",
        severity="HIGH",
        pattern=r"(?i)bearer\s+([A-Za-z0-9_\-.~+/=]{20,256})",
        base_confidence=80,
        validator="bearer_token",
        entropy_profile="base64",
        keywords=("bearer", "authorization", "token"),
        description="HTTP Authorization: Bearer credential.",
        remediation="Revoke/shorten the token lifetime; prefer short-lived tokens.",
        fp_notes="The Bearer keyword is itself the context; placeholder tokens suppressed.",
    ),
    compile_rule(
        rule_id="SS-GENERIC-004",
        name="Webhook/Client Secret",
        provider="generic",
        category="webhook_secret",
        severity="HIGH",
        pattern=r"(?i)(webhook[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9_\-+=]{8,256})['\"]?",
        base_confidence=45,
        context_required=True,
        entropy_profile="mixed",
        keywords=("webhook_secret", "client_secret"),
        description="Webhook signing secret or OAuth client secret assignment.",
        remediation="Rotate the secret at the provider and update the webhook endpoint.",
        fp_notes="Context-required; placeholders and short dummies suppressed.",
    ),
]
