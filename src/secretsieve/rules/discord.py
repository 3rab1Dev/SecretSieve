"""Discord rules: SS-DISCORD-001 (narrow classic-token shape, FP-prone gate)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-DISCORD-001",
        name="Discord Bot/User Token",
        provider="discord",
        category="api_token",
        severity="HIGH",
        pattern=r"[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}",
        base_confidence=70,
        context_required=True,
        entropy_profile="base64",
        keywords=("discord", "token"),
        description="Classic Discord token (24.6.27 shape).",
        remediation="Regenerate the token in the Discord developer portal.",
        fp_notes="Known FP-prone shape: requires secret/token context or strong entropy to fire.",
    ),
]
