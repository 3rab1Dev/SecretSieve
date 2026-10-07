"""GitLab rules: SS-GITLAB-001 (Tier 2, v1.0 scope)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-GITLAB-001",
        name="GitLab Personal Access Token",
        provider="gitlab",
        category="api_token",
        severity="CRITICAL",
        pattern=r"glpat-[A-Za-z0-9_\-]{20,64}",
        base_confidence=90,
        entropy_profile="base64",
        keywords=("gitlab", "glpat"),
        description="GitLab personal/project access token.",
        remediation="Revoke in GitLab user settings and review audit events.",
        fp_notes="Rare in prose; requires the glpat- prefix so precision is high.",
    ),
]
