"""Slack rules: SS-SLACK-001."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-SLACK-001",
        name="Slack Token",
        provider="slack",
        category="api_token",
        severity="HIGH",
        pattern=r"xox[bpas]-[A-Za-z0-9\-]{10,80}",
        base_confidence=90,
        entropy_profile="base64",
        keywords=("slack", "xoxb", "xoxp", "xoxa", "xoxs"),
        description="Slack bot/user/app token (xoxb/xoxp/xoxa/xoxs).",
        remediation="Revoke in the Slack app dashboard and rotate webhooks.",
        fp_notes="Prefix-anchored; low false-positive rate.",
    ),
]
