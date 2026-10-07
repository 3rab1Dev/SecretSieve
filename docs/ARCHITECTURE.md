# Architecture

Copyright (c) 3rabDev - https://3rabdev.online

SecretSieve is a line-oriented, single-pass, zero-dependency scanner.
Data flows one way; no cycles:

```
argv -> parser -> config merge -> discovery -> gating/reading
     -> signatures -> context + entropy -> FP gates
     -> confidence -> severity -> dedupe -> reporter -> exit code
```

## Packages (`src/secretsieve/`)

| Package | Responsibility | May import |
|---------|---------------|------------|
| `cli/` | argparse front end, scan controller, color policy | config, scanner, detectors (scoring only), reporting, rules (list/explain), git |
| `config/` | TOML load/validate/merge, `--init` template | models |
| `scanner/` | discovery, filters, binary/size/encoding gates, line reading, orchestration | models, detectors.engine, utils |
| `detectors/` | signatures, entropy, context, heuristics, FP filters, scoring, file-level engine | models, rules, scanner.filetypes, utils |
| `rules/` | one module per provider family exporting `RULES`; explicit registry, no magic imports | models |
| `models/` | frozen `Rule`, `Finding` (+fingerprint/sort), `Config`, `ScanStats` | utils |
| `reporting/` | human + JSON renderers (redacted only) | models, utils |
| `git/` | local `git diff` file lists for `--staged/--unstaged` (stdlib subprocess) | - |
| `utils/` | redact, terminal sanitize, paths/globs, timing | - |

Key invariants:

- `scanner/` never imports `detectors/` except the engine entry point in `orchestrator.py`.
- Detectors are pure functions over `(line, lineno, file_ctx)`; no I/O, no network.
- `Finding` objects never hold raw secrets (hashed at construction).
- Reporters only receive redacted previews.
- Rules are Python data + precompiled regexes; adding a provider = new module + registry line + tests.

## Detection pipeline order

Input resolution -> path discovery -> file filtering -> binary detection ->
text decoding -> candidate extraction -> signature detection -> context analysis ->
entropy analysis -> heuristics/FP filters -> confidence -> severity ->
deduplication -> finding creation -> reporting. See `PLAN.md` Sec. 8 for the
rationale of each stage position.
