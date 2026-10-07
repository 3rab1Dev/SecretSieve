# Install

Copyright (c) 3rabDev - https://3rabdev.online

Requires Python 3.10 or newer (`python --version`).

```bash
pip install secretsieve         # from PyPI (once released)
pipx install secretsieve        # isolated CLI install (recommended for users)
pip install -e .                # from source (developers; needs README.md + pyproject.toml present)
python -m build                 # build sdist + wheel locally (needs the `build` package)
```

Verify:

```bash
secretsieve --version
python -m secretsieve --version
secretsieve rules --list
```

Offline install: download the wheel once, then `pip install --no-index --find-links ./wheelhouse secretsieve`.
Zero runtime dependencies - nothing else is fetched.

> License: MIT - see `LICENSE` at the repo root. Copyright © 3rabDev.
