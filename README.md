# SecretSieve

![SecretSieve icon](assets/icon.webp)

**Sieve the secrets out of your source.**

SecretSieve is a professional, intelligent, local-first secret detection CLI written in Python.
It scans source code, configuration files, and project directories for accidentally exposed
credentials - API keys, tokens, private keys, passwords, and connection strings - using a
multi-signal engine (signatures + entropy + context + deterministic confidence/severity scoring),
not just regex.

Copyright © 3rabDev - https://3rabdev.online

> License: MIT - see [LICENSE](LICENSE). Copyright © 3rabDev.

## Privacy

- 100% local by default. No network I/O during scanning, no uploads, no telemetry.
- Secrets are never verified against third-party services (that would transmit them).
- All output is **redacted** by default (`AKIA****************9X2F`).

## Install

Requires Python 3.10+.

```bash
pip install secretsieve        # from PyPI
pipx install secretsieve       # isolated CLI install (recommended)
pip install -e .               # from source (developers)
```

## Quick start

```bash
secretsieve .                                  # scan the current project
secretsieve ./src config.py                    # scan specific paths
secretsieve scan . --json --fail-on high       # CI-friendly JSON gate
secretsieve rules --list                       # show all detection rules
secretsieve explain SS-GITHUB-001              # understand a rule
secretsieve config --init > secretsieve.toml   # starter config
```

## Exit codes (generic CI)

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` |
| `2` | Scanner / configuration error |

`--fail-on` defaults to `low` (any LOW+ fails; INFO never fails).
`--severity` only controls *display*; hidden findings still fail CI.

## Suppressing a false positive

Preferred order:

1. Verify it really is a false positive (placeholder? hash? test data?).
2. Suppress by fingerprint (stable, auditable) in `secretsieve.toml`:
   ```toml
   [[allow.fingerprint]]
   value = "sha256:..."
   ```
3. Or scope a rule+path:
   ```toml
   [[allow.path_rule]]
   rule = "SS-GENERIC-002"
   path = "tests/fixtures/**"
   ```
4. Or add a same-line comment (line scope only, visible in diffs):
   ```python
   password = "not-a-real-secret-for-tests"  # secretsieve:ignore
   ```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) · [CLI reference](docs/CLI-REFERENCE.md) ·
  [Install](docs/INSTALL.md) · [Quick start](docs/QUICKSTART.md) ·
  [Configuration](docs/CONFIGURATION.md) · [Detection coverage](docs/DETECTION-COVERAGE.md) ·
  [False positives](docs/FALSE-POSITIVES.md) · [Privacy](docs/PRIVACY.md) ·
  [Security](docs/SECURITY.md) · [Contributing](docs/CONTRIBUTING.md) ·
  [Release process](docs/RELEASE-PROCESS.md) · [Performance](docs/PERF.md)
- Master engineering blueprint: [PLAN.md](PLAN.md)
- Changes: [CHANGELOG.md](CHANGELOG.md)
