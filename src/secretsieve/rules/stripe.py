"""Stripe rules: SS-STRIPE-001 (severity branches on live/test + secret/publishable)."""

from secretsieve.models.rule import compile_rule

RULES = [
    compile_rule(
        rule_id="SS-STRIPE-001",
        name="Stripe API Key",
        provider="stripe",
        category="api_token",
        severity="HIGH",  # branched per value in the engine: sk_live->CRITICAL, pk_*->MEDIUM
        pattern=r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,64}",
        base_confidence=90,
        validator="stripe_branch",
        entropy_profile="base64",
        keywords=("stripe", "sk_live", "sk_test", "pk_live", "pk_test"),
        description="Stripe secret or publishable key.",
        remediation="Roll the key in the Stripe dashboard; sk_live keys move money.",
        fp_notes="Stripe's documented pk_test_.../sk_test_... docs keys are public examples; "
        "'test' publishable keys are MEDIUM at most, never CRITICAL.",
    ),
]
