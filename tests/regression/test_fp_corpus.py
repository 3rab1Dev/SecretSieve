"""Regression: curated false-positive corpus yields nothing >= MEDIUM."""

from secretsieve.models.config import Config
from secretsieve.scanner.orchestrator import run_scan


FP_FILES = {
    "app.py": """
import uuid
SESSION = "123e4567-e89b-12d3-a456-426614174000"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
COLOR = "#ff0000"
VERSION = "2.4.1"
monkey = "banana"
keyboard_shortcut = "ctrl+k"
arn = "arn:aws:iam::123456789012:user/test"
customer = "cus_9f8e7d6c5b4a3928"
""",
    "docs/guide.md": """
# Tokens
Use api_key = "example-value-here" in tutorials.
Your github token goes in .env (never paste ghp_example123 here).
""",
    "tests/test_auth.py": """
TOKEN = "test_abcdef1234567890abcdef1234567890"
password = "mock_password_for_tests"
""",
    ".env.example": 'GITHUB_TOKEN=your_token_here\nAPI_KEY=example\n',
    "bundle.min.js": "var c='9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d7e8f00112233445566778899aabbccdd';\n",
    "package-lock.json": '{"integrity": "sha512-9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d7e8f00112233445566778899aabbccddeeff001122"}',
    "notes.txt": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==\n",
}


def test_fp_corpus_silent(tmp_path, monkeypatch):
    for name, content in FP_FILES.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    outcome = run_scan(["."], Config())
    loud = [f for f in outcome.findings if f.severity in ("MEDIUM", "HIGH", "CRITICAL")]
    assert loud == []
