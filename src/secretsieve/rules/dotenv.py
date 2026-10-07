"""Dotenv rules: SS-ENV-001 (file-gated secret-like KEY=value assignments)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-ENV-001",
        name="Environment File Secret",
        provider="generic",
        category="env_secret",
        severity="MEDIUM",
        pattern=r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]{1,80})\s*=\s*(.+?)\s*$",
        base_confidence=40,
        validator="env_assignment",
        context_required=True,
        entropy_profile="mixed",
        keywords=("secret", "password", "token", "key", "env"),
        description="Secret-like assignment inside a dotenv-style file. "
        "Only evaluated in *.env / .env* files (plus KEY=value lines with "
        "secret-like names elsewhere at reduced confidence).",
        remediation="Keep .env out of version control; use .env.example with placeholders.",
        fp_notes=".env.example shapes are capped at INFO. Empty/dummy values suppressed. "
        "Requires a secret-like key name and a value of length >= 8.",
    ),
]
