"""Explicit rule registry (no magic imports - every rule module listed here).

Tier 1 (MVP): aws, github, jwt, privatekey, generic, database, slack,
stripe, discord, dotenv.
Tier 2 (v1.0): gitlab, google, azure, registry (npm/pypi/openai/sendgrid/twilio),
shell (Dockerfile/shell-export).
"""

from __future__ import annotations

import re

from secretsieve.rules import (
    aws,
    azure,
    database,
    discord,
    dotenv,
    generic,
    github,
    gitlab,
    google,
    jwt,
    privatekey,
    registry,
    shell,
    slack,
    stripe,
)

RULE_REGISTRY = (
    aws.RULES
    + github.RULES
    + gitlab.RULES
    + slack.RULES
    + stripe.RULES
    + discord.RULES
    + jwt.RULES
    + privatekey.RULES
    + database.RULES
    + generic.RULES
    + dotenv.RULES
    + google.RULES
    + azure.RULES
    + registry.RULES
    + shell.RULES
)

RULES_BY_ID = {rule.id: rule for rule in RULE_REGISTRY}

# Cheap single-pass prefilter (PLAN Sec. 31.3). Lines failing this skip the
# expensive rule loop - except dotenv/secret-filename-boosted files, which
# always run the full set. Every positive fixture must match this (tested).
SECRET_PREFILTER = re.compile(
    r"AKIA|ghp_|gho_|github_pat_|glpat-|xox[bpas]-|sk_live_|sk_test_|"
    r"pk_live_|pk_test_|-----BEGIN|eyJ|bearer|password|passwd|pwd|"
    r"secret|api[_-]?key|apikey|token|passwd|"
    r"AIza|service_account|AccountKey|npm_|pypi-|SG\.|SK[0-9a-fA-F]{8}|sk-|"
    r"postgres://|postgresql://|mysql://|mongodb|redis://|amqp|"
    r"webhook[_-]?secret|client[_-]?secret|database_url|connection_string|"
    r"export\s+[A-Za-z_]|^\s*(?:ENV|ARG)\s+|^[A-Za-z_][A-Za-z0-9_]*=",
    re.IGNORECASE | re.ASCII,
)

__all__ = ["RULE_REGISTRY", "RULES_BY_ID", "SECRET_PREFILTER"]
