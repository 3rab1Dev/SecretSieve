"""Google / GCP rules: SS-GOOGLE-001 (API key), SS-GCP-001 (service account). Tier 2."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-GOOGLE-001",
        name="Google API Key",
        provider="google",
        category="api_token",
        severity="HIGH",
        pattern=r"AIza[A-Za-z0-9_\-]{35}",
        base_confidence=88,
        entropy_profile="base64",
        keywords=("google", "AIza", "api_key"),
        description="Google Cloud API key (AIza prefix, 39 chars).",
        remediation="Restrict the key in Google Cloud Console and rotate it.",
        fp_notes="Fixed prefix + length; high precision.",
    ),
    compile_rule(
        rule_id="SS-GCP-001",
        name="GCP Service Account Key",
        provider="gcp",
        category="api_token",
        severity="CRITICAL",
        pattern=r'"type"\s*:\s*"service_account"',
        base_confidence=80,
        validator="gcp_service_account",
        entropy_profile="none",
        keywords=("service_account", "private_key", "gcp", "google"),
        description="GCP service-account JSON key file marker. The embedded "
        "private_key block is additionally reported as SS-PRIVATE-KEY-001.",
        remediation="Delete the key in IAM, rotate, and never commit service-account JSON.",
        fp_notes="Only fires in JSON files mentioning service_account.",
    ),
]
