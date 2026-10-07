"""File-type knowledge: categories, generated/lockfile markers, secret filenames.

Content-driven scanning (PLAN Sec. 18): the file type never decides *whether*
a signature may match - it only modulates context boosts and entropy gating.
Adding a type = one row here + tests. No engine change.
"""

from __future__ import annotations

# Extensions skipped before any read (binary artifacts + our own icon).
BINARY_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
        ".mp4", ".mp3", ".avi", ".mov", ".wav", ".flac",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib",
        ".pyc", ".pyo", ".class", ".jar",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".sqlite", ".db", ".dat", ".bin",
    }
)

GENERATED_SUFFIXES = (".min.js", ".bundle.js", ".map", ".snap")
GENERATED_DIRS = ("coverage",)
LOCKFILE_NAMES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "poetry.lock", "Cargo.lock", "Gemfile.lock"}
)

SECRET_FILENAMES = (
    "credentials.json", "secrets.yaml", "secrets.yml", "secrets.toml",
    ".env", ".envrc", "credentials", "secrets",
)
SECRET_SUFFIXES = (".pem", ".key", ".rsa", ".p12", ".pfx")
SECRET_BASENAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "service_account")

ENV_EXAMPLE_MARKERS = (".env.example", ".env.sample", ".example", ".sample")

TEST_DIR_MARKERS = ("test", "tests", "testing", "fixture", "fixtures", "mock", "mocks", "__tests__", "e2e", "spec")
DOCS_DIR_MARKERS = ("docs", "documentation", "examples", "example", "tutorial", "demo")

TEXTISH_EXTENSIONS = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
        ".properties", ".xml", ".html", ".htm", ".md", ".txt", ".rst",
        ".sh", ".bash", ".zsh", ".env", ".dockerfile",
        ".pem", ".key", ".rsa", ".pub", ".cnf", ".envrc",
    }
)


def _lower_name(path: str) -> str:
    return path.replace("\\", "/").lower()


def is_binary_extension(rel_path: str) -> bool:
    low = _lower_name(rel_path)
    base = low.rsplit("/", 1)[-1]
    # Multi-suffix archives like foo.tar.gz
    if base.endswith(".tar.gz") or base.endswith(".tar.bz2"):
        return True
    dot = base.rfind(".")
    if dot == -1:
        return False
    return base[dot:] in BINARY_EXTENSIONS


def is_generated(rel_path: str) -> bool:
    low = _lower_name(rel_path)
    if low.endswith(GENERATED_SUFFIXES):
        return True
    parts = low.split("/")
    return any(part in GENERATED_DIRS for part in parts[:-1])


def is_lockfile(rel_path: str) -> bool:
    base = _lower_name(rel_path).rsplit("/", 1)[-1]
    return base in LOCKFILE_NAMES


def is_env_example(rel_path: str) -> bool:
    low = _lower_name(rel_path)
    return any(marker in low for marker in ENV_EXAMPLE_MARKERS)


def is_test_path(rel_path: str) -> bool:
    parts = _lower_name(rel_path).split("/")
    if any(part in TEST_DIR_MARKERS for part in parts[:-1]):
        return True
    base = parts[-1]
    return base.startswith(("test_", "conftest")) or base.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))


def is_docs_path(rel_path: str) -> bool:
    low = _lower_name(rel_path)
    if low.endswith((".md", ".rst", ".txt")) and "/" in low:
        parts = low.split("/")
        if any(part in DOCS_DIR_MARKERS for part in parts[:-1]):
            return True
    if low.endswith((".md", ".rst")):
        return True
    parts = low.split("/")
    return any(part in DOCS_DIR_MARKERS for part in parts[:-1])


def is_secret_filename(rel_path: str) -> bool:
    low = _lower_name(rel_path)
    base = low.rsplit("/", 1)[-1]
    if base in SECRET_FILENAMES or base.startswith(".env"):
        return True
    if base.endswith(SECRET_SUFFIXES):
        return True
    return any(token in base for token in SECRET_BASENAMES)


def is_dotenv_file(rel_path: str) -> bool:
    low = _lower_name(rel_path)
    base = low.rsplit("/", 1)[-1]
    return base == ".env" or base.startswith(".env.") or base.endswith(".env")
