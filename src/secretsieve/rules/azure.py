"""Azure rules: SS-AZURE-001 (storage/service-bus connection string key). Tier 2."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-AZURE-001",
        name="Azure Connection String Key",
        provider="azure",
        category="connection_string",
        severity="HIGH",
        pattern=r"(?i)AccountKey=[A-Za-z0-9+/=]{32,88}",
        base_confidence=88,
        entropy_profile="base64",
        keywords=("azure", "accountkey", "connection_string"),
        description="Azure storage/service-bus connection string embedded key.",
        remediation="Regenerate the storage account keys and move to Managed Identity/Key Vault.",
        fp_notes="Requires the AccountKey= marker; placeholders suppressed.",
    ),
]
