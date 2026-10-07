"""Unit: context tokenization, tiers, anti-naive key matching."""

from secretsieve.detectors import context as ctx


def test_monkey_is_not_key():
    info = ctx.classify('monkey = "banana"', "app.py")
    assert info.tier == "none"
    assert info.context_key == "monkey"


def test_keyboard_shortcut_no_finding_context():
    info = ctx.classify('keyboard_shortcut = "ctrl+k"', "app.py")
    assert info.tier == "none"


def test_api_key_is_strong():
    info = ctx.classify('API_KEY = "Ab3x9QwE7kLmN2pR5sT8uV0aBcDeF"', "app.py")
    assert info.tier == "strong"
    assert info.context_key == "api_key"


def test_benign_key_tokens():
    info = ctx.classify('api_key_example = "whatever-value-here"', "app.py")
    assert info.tier == "benign"


def test_bearer_header_is_weak_without_assignment():
    info = ctx.classify("Authorization: Bearer sometokenvalue1234567890", "server.py")
    assert info.tier == "weak"


def test_test_path_is_benign_file():
    info = ctx.classify("something = 1", "tests/test_auth.py")
    assert info.tier == "benign_file"


def test_docs_path_is_benign_file():
    info = ctx.classify("something = 1", "docs/tokenize.md")
    assert info.tier == "benign_file"


def test_secret_filename_boost():
    info = ctx.classify("VALUE = 1", ".env")
    assert info.tier == "weak"
    assert info.secret_filename_boost


def test_quoted_json_key():
    info = ctx.classify('  "password": "hunter2",', "config.json")
    assert info.tier == "strong"
    assert info.context_key == "password"


def test_extract_assignment_key_guards_urls():
    assert ctx.extract_assignment_key("https://example.com/x") is None
    assert ctx.extract_assignment_key("API_KEY=abc") == "api_key"
    assert ctx.extract_assignment_key("export AWS_SECRET=abc") == "aws_secret"


def test_confidence_deltas():
    assert ctx.context_confidence_delta("strong") == 15
    assert ctx.context_confidence_delta("weak") == 7
    assert ctx.context_confidence_delta("none") == 0
    assert ctx.context_confidence_delta("benign") == -20
    assert ctx.context_confidence_delta("benign_file") == -20
