"""AWS rules: SS-AWS-001 (access key ID), SS-AWS-002 (secret access key)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-AWS-001",
        name="AWS Access Key ID",
        provider="aws",
        category="api_token",
        severity="HIGH",
        pattern=r"AKIA[0-9A-Z]{16}",
        base_confidence=90,
        entropy_profile="none",
        keywords=("aws", "AKIA", "access"),
        description="AWS IAM access key ID (20 chars, AKIA prefix).",
        remediation="Revoke the key in IAM, rotate, and check CloudTrail for misuse.",
        fp_notes="AWS documents AKIAIOSFODNN7EXAMPLE as an example; it is suppressed as a placeholder.",
    ),
    compile_rule(
        rule_id="SS-AWS-002",
        name="AWS Secret Access Key",
        provider="aws",
        category="api_token",
        severity="CRITICAL",
        pattern=r"(?i)(?:aws[_-]?secret(?:[_-]?access[_-]?key)?|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9/+=]{40})['\"]?",
        base_confidence=75,
        validator="aws_secret",
        context_required=True,
        entropy_profile="base64",
        keywords=("aws", "secret", "secretaccesskey"),
        description="AWS secret access key: 40-char Base64-ish value bound to an AWS secret assignment.",
        remediation="Revoke the key pair in IAM immediately; the ID + secret together give full API access.",
        fp_notes="Never fires standalone: requires AWS-secret assignment context or a paired AKIA in the same file.",
    ),
]
