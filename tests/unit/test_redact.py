"""Unit: redaction shapes + sanitization."""

from secretsieve.utils import redact as R
from secretsieve.utils.sanitize import sanitize_for_terminal


def test_default_mask_fixed_length():
    out = R.redact("AKIAIOSFODNN7T3STK3Y9")
    assert out == "AKIA" + "*" * 16 + "K3Y9"
    # Mask hides true length: different lengths, same star run.
    assert R.redact("a" * 20).count("*") == 16
    assert R.redact("b" * 60).count("*") == 16


def test_short_values_fully_masked():
    assert R.redact("hunter2") == "********"
    assert R.redact("12345678") == "********"
    assert R.redact("") == "********"


def test_github_style_prefix():
    out = R.redact("ghp_9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3")
    assert out.startswith("ghp_") and out.endswith("1e2f3") or out.endswith("e2f3")
    assert "*" * 16 in out


def test_pem_and_db_redaction():
    pem = R.redact_pem("-----BEGIN RSA PRIVATE KEY-----", 1679)
    assert "BEGIN RSA PRIVATE KEY" in pem and "1679" in pem
    assert "MIIE" not in pem
    db = R.redact_db_url("postgres://app:s3cr3t@db.internal:5432/appdb")
    assert "s3cr3t" not in db
    assert "app:" in db and "@db.internal" in db


def test_hash_is_stable_hex():
    h1 = R.hash_value("same-value")
    assert h1.startswith("sha256:") and h1 == R.hash_value("same-value")
    assert R.hash_value("other") != h1


def test_sanitize_strips_escapes():
    evil = "\x1b[2J\x1b]0;pwned\x07/etc/passwd\r\nOVERWRITE"
    clean = sanitize_for_terminal(evil)
    assert "\x1b" not in clean
    assert "\n" not in clean and "\r" not in clean
    assert "passwd" in clean
    assert sanitize_for_terminal(None) == ""
    long = sanitize_for_terminal("x" * 600)
    assert len(long) <= 501
