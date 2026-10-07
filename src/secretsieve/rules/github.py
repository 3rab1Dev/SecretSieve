"""GitHub rules: SS-GITHUB-001."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-GITHUB-001",
        name="GitHub Token",
        provider="github",
        category="api_token",
        severity="CRITICAL",
        pattern=r"(?:ghp_[A-Za-z0-9]{36,80}|gho_[A-Za-z0-9]{36,80}|github_pat_[A-Za-z0-9_]{22,100})",
        base_confidence=90,
        entropy_profile="base64",
        keywords=("github", "ghp", "gho", "github_pat"),
        description="GitHub personal access token / OAuth token / fine-grained PAT.",
        remediation="Revoke at github.com/settings/tokens and audit repository access logs.",
        fp_notes="Docs examples containing 'example' are suppressed as placeholders.",
    ),
]
