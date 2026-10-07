"""Unit: per-rule positives fire with the right ID; negatives stay silent.

All secrets below are synthetic fixtures (non-sensitive by construction).
"""

import time

import pytest

from secretsieve.models.config import Config
from secretsieve.models.stats import ScanStats
from secretsieve.detectors.engine import scan_file_content
from secretsieve.rules import RULE_REGISTRY, RULES_BY_ID, SECRET_PREFILTER
from tests.conftest import (
    FAKE_AWS_KEY_ID, FAKE_AWS_SECRET, FAKE_AZURE, FAKE_BEARER, FAKE_DB_URL,
    FAKE_DISCORD, FAKE_GITHUB_TOKEN, FAKE_GITLAB, FAKE_GOOGLE, FAKE_JWT,
    FAKE_NPM, FAKE_OPENAI, FAKE_PEM, FAKE_PYPI, FAKE_SENDGRID, FAKE_SLACK,
    FAKE_STRIPE_TEST, FAKE_TWILIO,
)


def scan_lines(path, *lines):
    cfg = Config()
    stats = ScanStats()
    numbered = [(i + 1, text, False) for i, text in enumerate(lines)]
    return scan_file_content(path, numbered, cfg, stats, generated=False, lockfile=False), stats


def ids(findings):
    return [f.rule_id for f in findings]


def test_aws_id_and_secret_pair_bonus():
    findings, _ = scan_lines(
        "config/aws.py",
        f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY_ID}"',
        f'aws_secret_access_key = "{FAKE_AWS_SECRET}"',
    )
    assert "SS-AWS-001" in ids(findings)
    assert "SS-AWS-002" in ids(findings)
    aws_id = next(f for f in findings if f.rule_id == "SS-AWS-001")
    assert aws_id.severity == "HIGH"
    secret = next(f for f in findings if f.rule_id == "SS-AWS-002")
    assert secret.severity == "CRITICAL"
    assert "paired_credential" in secret.reason_codes
    assert FAKE_AWS_SECRET not in secret.redacted


def test_aws_secret_requires_context():
    # A bare 40-char string with no AWS context must not fire SS-AWS-002.
    findings, _ = scan_lines("notes.txt", f'"{FAKE_AWS_SECRET}"')
    assert "SS-AWS-002" not in ids(findings)


def test_github_token_critical_99():
    findings, _ = scan_lines(".env", f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}")
    gh = next(f for f in findings if f.rule_id == "SS-GITHUB-001")
    assert (gh.severity, gh.confidence) == ("CRITICAL", 99)
    assert FAKE_GITHUB_TOKEN not in gh.redacted


def test_aws_example_suppressed():
    findings, stats = scan_lines("docs/example.md", 'KEY = "AKIAIOSFODNN7EXAMPLE"')
    assert findings == []
    assert stats.suppressed.get("placeholder", 0) >= 1


def test_jwt_valid_and_invalid():
    findings, _ = scan_lines("app.py", f"token = '{FAKE_JWT}'")
    assert "SS-JWT-001" in ids(findings)
    bad, _ = scan_lines("app.py", 'token = "eyJub3QtdmFsaWQdecode!!!"')
    assert "SS-JWT-001" not in ids(bad)


def test_private_key_block_is_single_finding():
    lines = FAKE_PEM.splitlines()
    findings, _ = scan_lines("deploy/id_rsa", *lines)
    pem = [f for f in findings if f.rule_id == "SS-PRIVATE-KEY-001"]
    assert len(pem) == 1
    assert pem[0].severity == "CRITICAL"
    assert "MIIE" not in pem[0].redacted


def test_db_url_and_localhost_demotion():
    findings, _ = scan_lines("app.py", f'DATABASE_URL="{FAKE_DB_URL}"')
    db = next(f for f in findings if f.rule_id == "SS-DB-001")
    assert db.severity == "CRITICAL"
    assert "s3cr3tPassw0rd" not in db.redacted
    assert "********" in db.redacted
    local, _ = scan_lines("app.py", 'DATABASE_URL="postgres://root:root@localhost/mydb"')
    assert next(f for f in local if f.rule_id == "SS-DB-001").severity == "LOW"


@pytest.mark.parametrize("token,rid", [
    (FAKE_SLACK, "SS-SLACK-001"),
    (FAKE_STRIPE_TEST, "SS-STRIPE-001"),
    (FAKE_GITLAB, "SS-GITLAB-001"),
    (FAKE_GOOGLE, "SS-GOOGLE-001"),
    (FAKE_NPM, "SS-NPM-001"),
    (FAKE_PYPI, "SS-PYPI-001"),
    (FAKE_OPENAI, "SS-OPENAI-001"),
    (FAKE_SENDGRID, "SS-SENDGRID-001"),
    (FAKE_AZURE, "SS-AZURE-001"),
])
def test_prefix_rules_fire(token, rid):
    findings, _ = scan_lines("app.py", f"value = '{token}'")
    assert rid in ids(findings), (rid, token)


def test_stripe_severity_branches():
    live, _ = scan_lines("app.py", "k = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc9f8e7d6c5b'")
    assert next(f for f in live if f.rule_id == "SS-STRIPE-001").severity == "CRITICAL"
    pub, _ = scan_lines("app.py", "k = 'pk_test_TYooMQauvdEDq54NiTphI7jx12ab'")
    assert next(f for f in pub if f.rule_id == "SS-STRIPE-001").severity == "LOW"


def test_discord_needs_context():
    noctx, _ = scan_lines("random.txt", FAKE_DISCORD)
    assert "SS-DISCORD-001" not in ids(noctx)
    yes, _ = scan_lines("bot.py", f"DISCORD_TOKEN = '{FAKE_DISCORD}'")
    assert "SS-DISCORD-001" in ids(yes)


def test_twilio_needs_context():
    noctx, _ = scan_lines("random.txt", FAKE_TWILIO)
    assert "SS-TWILIO-001" not in ids(noctx)
    yes, _ = scan_lines("sms.py", f"TWILIO_API_KEY = '{FAKE_TWILIO}'")
    assert "SS-TWILIO-001" in ids(yes)


def test_bearer_and_webhook():
    b, _ = scan_lines("server.py", FAKE_BEARER)
    assert "SS-GENERIC-003" in ids(b)
    w, _ = scan_lines("app.py", "webhook_secret = 'whsec_9f8e7d6c5b4a3928174656f7a8b9c0d'")
    assert "SS-GENERIC-004" in ids(w)


def test_generic_api_key_shapes():
    f, _ = scan_lines("app.py", 'api_key = "Ab3x9QwE7kLmN2pR5sT8uV0aBcDeF1"')
    assert "SS-GENERIC-001" in ids(f)
    assert next(x for x in f if x.rule_id == "SS-GENERIC-001").severity == "MEDIUM"


def test_negative_placeholders_hashes_uuids():
    cases = [
        ("app.py", 'api_key = "test123"'),  # too short for entropy: silent
        ("app.py", 'api_key = "example-value-here"'),
        ("app.py", 'password = ""'),
        ("app.py", 'token = "12345678901234567890123456789012"'),  # md5-shaped, no key context match
        ("app.py", 'session = "123e4567-e89b-12d3-a456-426614174000"'),
        ("app.py", 'color = "#ff0000"'),
        ("app.py", 'version = "1.2.3"'),
        ("app.py", 'monkey = "banana"'),
        ("app.py", 'keyboard_shortcut = "ctrl+k"'),
    ]
    for path, line in cases:
        findings, _ = scan_lines(path, line)
        assert [f for f in findings if f.severity in ("MEDIUM", "HIGH", "CRITICAL")] == [], line


def test_prefilter_recall_over_positives():
    positives = [
        FAKE_AWS_KEY_ID, FAKE_GITHUB_TOKEN, FAKE_JWT, FAKE_SLACK, FAKE_STRIPE_TEST,
        FAKE_DB_URL, 'password = "x"', 'api_key = "x"', "Bearer abc", FAKE_GITLAB,
        FAKE_GOOGLE, FAKE_NPM, FAKE_PYPI, FAKE_OPENAI, FAKE_SENDGRID, FAKE_AZURE,
        "service_account", "export MY_SECRET=x", "API_TOKEN=abc", "-----BEGIN RSA PRIVATE KEY-----",
    ]
    for p in positives:
        assert SECRET_PREFILTER.search(p), p


def test_line_prefilter_recall_over_full_lines():
    from secretsieve.detectors.signatures import line_needs_full_scan
    from tests.conftest import FAKE_AZURE as AZ, FAKE_BEARER as BE, FAKE_DISCORD as DI, FAKE_TWILIO as TW

    lines = [
        ("AWS_ACCESS_KEY_ID = '%s'" % FAKE_AWS_KEY_ID, "a.py"),
        ("aws_secret_access_key = '%s'" % "wJalrXUtnFEMI/K7MDENG/bPxRfiCYWXYZ1234ab", "a.py"),
        ("GITHUB_TOKEN=%s" % FAKE_GITHUB_TOKEN, ".env"),
        ("token = '%s'" % FAKE_JWT, "a.py"),
        ("x = '%s'" % FAKE_SLACK, "a.py"),
        ("k = '%s'" % FAKE_STRIPE_TEST, "a.py"),
        ("DISCORD_TOKEN = '%s'" % DI, "bot.py"),
        ("DATABASE_URL=\"%s\"" % FAKE_DB_URL, "a.py"),
        (BE, "server.py"),
        ("TWILIO_API_KEY = '%s'" % TW, "sms.py"),
        ("webhook_secret = 'whsec_9f8e7d6c5b4a3928174656f7a8b9c0d'", "a.py"),
        ("t = '%s'" % FAKE_GITLAB, "a.py"),
        ("k = '%s'" % FAKE_GOOGLE, "a.py"),
        ("t = '%s'" % FAKE_NPM, "a.py"),
        ("t = '%s'" % FAKE_PYPI, "a.py"),
        ("k = '%s'" % FAKE_OPENAI, "a.py"),
        ("k = '%s'" % FAKE_SENDGRID, "a.py"),
        ("conn = '%s'" % AZ, "a.py"),
        ("export DEPLOY_TOKEN=\"DpT8e7xK2mQvBzLp4R1sYw9N0cDfGhJkMnOpQrSt\"", "d.sh"),
        ("API_TOKEN_9 = \"9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d\"", "a.py"),
        ("PGPASS=whatever-no-keywords", ".env"),  # dotenv files always full-scan
    ]
    for text, path in lines:
        from secretsieve.scanner import filetypes as _ft
        assert line_needs_full_scan(
            text, path,
            is_dotenv=_ft.is_dotenv_file(path),
            is_secret_file=_ft.is_secret_filename(path),
        ), text[:60]


def test_redos_budget_per_pattern():
    evil = "a" * 10000 + "!"
    for rule in RULE_REGISTRY:
        start = time.perf_counter()
        try:
            list(rule.pattern.finditer(evil))
        except Exception:
            pass
        assert (time.perf_counter() - start) < 0.5, rule.id


def test_registry_ids_stable_and_unique():
    assert len(RULES_BY_ID) == len(RULE_REGISTRY) == 24
    assert all(r.id.startswith("SS-") for r in RULE_REGISTRY)
