"""Entry point for ``python -m secretsieve``. Parity with the ``secretsieve`` console script."""

from secretsieve.cli.app import main

if __name__ == "__main__":
    raise SystemExit(main())
