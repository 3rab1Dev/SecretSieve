"""Shell / Dockerfile rules: SS-SHELL-001 (export/ENV/ARG secret assignment). Tier 2."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-SHELL-001",
        name="Shell/Docker Secret Assignment",
        provider="generic",
        category="env_secret",
        severity="MEDIUM",
        pattern=r"(?i)^\s*(?:export\s+|ENV\s+|ARG\s+)([A-Za-z_][A-Za-z0-9_]{1,80})\s*=\s*(.+?)\s*$",
        base_confidence=40,
        validator="shell_secret",
        context_required=True,
        entropy_profile="mixed",
        keywords=("secret", "password", "token", "key", "export", "ENV", "ARG"),
        description="Secret-like KEY=value in shell scripts / Dockerfiles / compose-adjacent files.",
        remediation="Use build secrets / mounted env files instead of baked-in values.",
        fp_notes="Only evaluated in shell/Dockerfile-ish files with a secret-like key name; "
        "empty/dummy values suppressed.",
    ),
]
