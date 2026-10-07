# Quick Start

Copyright (c) 3rabDev - https://3rabdev.online

Five commands to value:

```bash
secretsieve .                                  # 1. scan this project
secretsieve scan ./src --severity high         # 2. focus on what matters
secretsieve explain SS-GITHUB-001              # 3. understand a finding
secretsieve config --init > secretsieve.toml  # 4. tune (excludes, thresholds, allowlist)
secretsieve scan . --json --fail-on high       # 5. gate CI (exit 1 on HIGH+)
```

Reading a finding:

```
CRITICAL  GitHub Token - .env:1  [SS-GITHUB-001 | conf 99% | very-high]
  ghp_****************e2f3          <- always masked, fixed-length stars
  Reason: prefix signature + credential context (github_token)
```

- **Severity** = how bad if real. **Confidence** = how likely real. They are independent.
- Fix = revoke/rotate at the provider, remove from source (and history), then re-scan.
- Not yours / test data? Suppress by fingerprint in `secretsieve.toml` (see `docs/FALSE-POSITIVES.md`).
