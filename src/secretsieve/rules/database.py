"""Database rules: SS-DB-001 (connection strings with embedded passwords)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-DB-001",
        name="Database Connection String",
        provider="generic",
        category="connection_string",
        severity="CRITICAL",
        pattern=r"(?i)(?P<value>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|amqps)://[^/\s:'\"]+:[^@\s/'\"]+@[^\s'\";]+)",
        base_confidence=88,
        validator="db_url",
        entropy_profile="none",
        keywords=("database_url", "connection_string", "postgres", "mysql", "mongodb", "redis"),
        description="Database/message-broker URL embedding user:password@host.",
        remediation="Rotate the database password, move credentials to a vault/env, "
        "and restrict network access to the database.",
        fp_notes="Requires non-empty user AND password AND host. "
        "localhost root:root style dev URLs are demoted to LOW.",
    ),
]
