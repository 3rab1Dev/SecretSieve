# Contributing

Copyright (c) 3rabDev - https://3rabdev.online

## Adding a rule

1. Pick the next stable ID in the family (`SS-<FAMILY>-<NNN>`; never reuse).
2. Add a `compile_rule(...)` entry in the matching `src/secretsieve/rules/*.py`
   (new family = new module + registry line in `rules/__init__.py` + prefilter word if needed).
3. Write description, remediation, and FP notes (required fields, reviewed like code).
4. Add positives (fires with expected ID/severity) and negatives (placeholders, hashes, prose) in `tests/unit/test_rules.py`.
5. Run the suite: `python -m pytest tests` - includes ReDoS budget, prefilter recall, and redaction property tests.
6. Update `docs/DETECTION-COVERAGE.md` and `CHANGELOG.md` (loosening = MINOR).

## Regex rules

- Bounded repetitions only (`{m,n}`, n <= 512). No `(x+)+`, no `.*.*` chains.
- Concrete classes (`[A-Za-z0-9_-]`), anchored affixes, `re.ASCII`.
- Validators (structure checks) beat broader regexes for precision.

## Test secrets

All fixture secrets must be synthetic and non-sensitive (reserved/example-shaped).
Never commit a real credential - if you do, rotate it immediately; scrubbing history is not enough.
