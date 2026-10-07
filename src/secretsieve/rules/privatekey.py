"""Private-key rules: SS-PRIVATE-KEY-001 (PEM block header, multi-line)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-PRIVATE-KEY-001",
        name="PEM Private Key",
        provider="generic",
        category="private_key",
        severity="CRITICAL",
        pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        base_confidence=95,
        validator="pem_block",
        entropy_profile="none",
        keywords=("private_key", "privatekey", "pem", "rsa", "openssh"),
        description="PEM/PKCS/OpenSSH private key block. One finding per block, header only.",
        remediation="Remove the key from source, rotate it, and purge it from history; "
        "assume any committed private key is compromised.",
        fp_notes="Keys in docs stay CRITICAL (leaked docs leak). Never demoted for docs context.",
    ),
]
