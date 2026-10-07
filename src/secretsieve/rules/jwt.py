"""JWT rules: SS-JWT-001 (alias SS-GENERIC-JWT-001 per plan)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-JWT-001",
        name="JSON Web Token (JWT)",
        provider="generic",
        category="jwt",
        severity="HIGH",
        pattern=r"eyJ[A-Za-z0-9_\-]{8,512}\.[A-Za-z0-9_\-]{8,2048}\.[A-Za-z0-9_\-]{8,2048}",
        base_confidence=85,
        validator="jwt_structure",
        entropy_profile="base64",
        keywords=("jwt", "bearer", "token", "auth"),
        description="JSON Web Token (also catalogued as SS-GENERIC-JWT-001). "
        "Header must Base64URL-decode to JSON with an alg field.",
        remediation="Tokens are bearer credentials: shorten expiry, rotate signing keys, "
        "and never commit long-lived tokens.",
        fp_notes="Unsigned test tokens (alg:none) still flagged HIGH with reason unsigned_jwt. "
        "Non-decodable eyJ... strings are rejected by the validator.",
    ),
]
