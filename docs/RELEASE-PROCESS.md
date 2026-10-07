# Release Process

Copyright (c) 3rabDev - https://3rabdev.online

1. Run the full suite: `python -m pytest tests` (must be green on Windows + Linux).
2. Re-run acceptance: triple-command parity (`secretsieve .`, `secretsieve scan .`, `python -m secretsieve .`), exit-code matrix, JSON field lock, offline scan, self-scan (`secretsieve scan . --fail-on medium --exclude "tests/**" --exclude "PLAN.md"` must be clean; `tests/` holds intentional positive fixtures and frozen `PLAN.md` holds illustrative examples - both excluded by documented command, never by shipped config, and `src/` itself must be scan-clean).
3. Update `CHANGELOG.md` (MINOR for rule loosening/threshold lowering; PATCH for tightening).
4. Bump `src/secretsieve/__init__.py` + `pyproject.toml` version (single source is `__init__.__version__`; keep them in sync).
5. Build: `python -m build` (sdist + wheel); verify offline install from the wheelhouse.
6. Tag `vX.Y.Z`.
7. **License: MIT.** A `LICENSE` file is present; keep the `license` field in `pyproject.toml` and the license notes in `README.md`/`docs/INSTALL.md` in sync on every release.

No GitHub Actions are used or shipped. Generic-CI instructions (exit codes + `--json`) live in `docs/CLI-REFERENCE.md`.
