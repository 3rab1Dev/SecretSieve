# False Positives

Copyright (c) 3rabDev - https://3rabdev.online

Precision over volume: ten actionable findings beat one hundred noisy ones.
Gates run in order; every suppression is counted in `--verbose` stats.

1. **Placeholders** (`example`, `changeme`, `xxx`, `AKIA...EXAMPLE`, repeated chars, `EXAMPLE` marker, your `[allow].placeholder_values`).
2. **Empty/defaults** (`""`, `null`, `undefined`, `admin/admin`-style pairs).
3. **Hashes/UUIDs/versions/colors/public IDs** (MD5/SHA1/SHA256, UUIDs, `#fff`, `1.2.3`, `arn:...`, `cus_...`) - INFO at most, usually silent.
4. **Test/fixture/docs/example paths** - demoted one severity level, confidence capped; `test_`/`mock_` value prefixes suppressed.
5. **Generated files** (`*.min.js`, `*.bundle.js`, `*.map`, lockfiles, `coverage/`) - raised entropy bar, generic rules gated off in lockfiles.
6. **Data URIs** (`data:image/...;base64,`) skipped before entropy.
7. **Repeated values** (10+ occurrences in one file) collapse to the first 3.
8. **Allowlists** (config fingerprint preferred; rule+path scoped).
9. **Inline ignore**: trailing `# secretsieve:ignore` (or `//`) suppresses **one line**.

## Ignore safety notes

- Inline ignores are line-scoped, visible in diffs, and counted (`suppressed: ignore=N`).
- Prefer fingerprint allowlists: they survive line moves less, but they are explicit and reviewable in config.
- Never invent synonyms (`nolint`, `skip`) - only the exact token works, for auditability.
- A future `--strict` mode may fail CI when any ignore is present.
