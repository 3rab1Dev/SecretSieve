"""Context analysis (PLAN Sec. 12): whole-token key matching + file signals.

Anti-naive rule: ``monkey`` != ``key``. Keys are normalized, split on
``_ - .``, and matched as whole tokens - never substring search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from secretsieve.scanner import filetypes

# Whole-token secret hints (matched after tokenization, NOT substring).
SECRET_TOKENS = frozenset(
    {
        "api_key", "apikey", "api-key", "secret", "secrets", "secret_key", "secretkey",
        "client_secret", "auth_token", "authtoken", "access_token", "accesstoken",
        "bearer", "token", "tokens", "password", "passwd", "pwd", "pass",
        "db_password", "database_url", "connection_string", "connectionstring",
        "private_key", "privatekey", "webhook_secret", "stripe_secret",
        "aws_secret", "aws_secret_access_key", "secretaccesskey",
        "github_token", "slack_token", "discord_token", "oauth_secret",
        "api_secret", "app_secret", "auth", "credentials", "credential",
        "db_pass", "dbpass", "dbpassword", "key", "keys",
    }
)

# Tokens that mark a key/value as benign (documentation, placeholders).
BENIGN_TOKENS = frozenset(
    {
        "example", "examples", "placeholder", "placeholders", "dummy", "dummies",
        "sample", "samples", "test", "tests", "fixture", "fixtures", "mock", "mocks",
        "template", "templates", "changeme", "lorem", "yourkeyhere", "your_key_here",
        "not_a_real_key", "fake", "invalid", " redacted",
    }
)

PROVIDER_WORDS = frozenset(
    {"aws", "github", "stripe", "slack", "discord", "google", "azure", "twilio", "openai", "npm", "pypi", "sendgrid", "gitlab"}
)

_KEY_RE = re.compile(
    r"""^\s*(?:export\s+|ENV\s+|ARG\s+)?["']?([A-Za-z_][\w.\-]{0,120})\s*[:=]"""
)
_QUOTED_KEY_RE = re.compile(r"""^\s*["']([A-Za-z_][\w.\-]{0,120})["']\s*[:=]""")
_TOKEN_SPLIT_RE = re.compile(r"[_\-.]+")

_AUTHISH_RE = re.compile(r"(?i)(authorization\s*:|bearer\s+|x-api-key\s*:|api[_-]?key\s*=)")


def tokenize_key(key: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT_RE.split(key.casefold()) if t]


def extract_assignment_key(line: str) -> str | None:
    """Return the normalized assignment key left of ``=``/``:``, if any."""
    m = _QUOTED_KEY_RE.match(line)
    if m:
        return m.group(1).casefold()
    m = _KEY_RE.match(line)
    if m:
        candidate = m.group(1)
        # Guard against URL-like lines ("https://...") being read as keys.
        if "://" in line[: len(candidate) + 8]:
            return None
        return candidate.casefold()
    # Flag style: --password SECRET / --api-key=SECRET
    flag = re.search(r"--([a-z][a-z\-_]{1,40})(?:\s*=|\s+)", line, re.IGNORECASE)
    if flag:
        return flag.group(1).replace("-", "_").casefold()
    return None


@dataclass
class ContextInfo:
    tier: str  # strong | weak | benign | benign_file | none
    context_key: str | None
    provider_hint: str | None = None
    secret_filename_boost: bool = False


def classify(
    line: str,
    rel_path: str,
    *,
    lockfile: bool = False,
    generated: bool = False,
) -> ContextInfo:
    """Classify the surrounding context of one line (never raises)."""
    key = extract_assignment_key(line)
    low_line = line.casefold()
    low_path = rel_path.replace("\\", "/").casefold()

    is_test = filetypes.is_test_path(rel_path)
    is_docs = filetypes.is_docs_path(rel_path)
    is_example = (
        filetypes.is_env_example(rel_path)
        or "example" in low_path
        or "sample" in low_path
        or "tutorial" in low_path
    )
    secret_file = filetypes.is_secret_filename(rel_path) or filetypes.is_dotenv_file(rel_path)

    if key:
        tokens = set(tokenize_key(key))
        if tokens & BENIGN_TOKENS:
            return ContextInfo("benign", key)
        if tokens & SECRET_TOKENS:
            return ContextInfo("strong", key, provider_hint=_provider_in(tokens, low_line))
        # Weak: auth-adjacent words near a non-secret key.
        if _AUTHISH_RE.search(line):
            return ContextInfo("weak", key, provider_hint=_provider_in(tokens, low_line))
        if secret_file:
            return ContextInfo("weak", key, provider_hint=_provider_in(tokens, low_line), secret_filename_boost=True)
        if is_test or is_docs or is_example:
            return ContextInfo("benign_file", key)
        return ContextInfo("none", key)
    # No assignment key: look at line-level signals.
    if _AUTHISH_RE.search(line):
        provider = next((w for w in PROVIDER_WORDS if w in low_line), None)
        if is_test or is_docs or is_example:
            return ContextInfo("benign_file", None, provider_hint=provider)
        return ContextInfo("weak", None, provider_hint=provider)
    if secret_file:
        return ContextInfo("weak", None, secret_filename_boost=True)
    if is_test or is_docs or is_example:
        return ContextInfo("benign_file", None)
    return ContextInfo("none", None)


def _provider_in(tokens: set[str], low_line: str) -> str | None:
    for tok in tokens:
        if tok in PROVIDER_WORDS:
            return tok
    for word in PROVIDER_WORDS:
        if word in low_line:
            return word
    return None


def context_confidence_delta(tier: str) -> int:
    if tier == "strong":
        return 15
    if tier == "weak":
        return 7
    if tier in ("benign", "benign_file"):
        return -20
    return 0
