# Security Model

Copyright (c) 3rabDev - https://3rabdev.online

The scanner routinely handles attacker-controlled content. Defenses:

- **No shell execution.** No `shell=True` anywhere; Git access is argv-list `subprocess` only.
- **Terminal escape sanitization.** All rendered paths/keys/reasons strip C0/C1 controls, CSI/OSC sequences, and bidi overrides; fields truncated at 500 chars.
- **JSON safety.** Only `json.dump(s)` with `ensure_ascii=True`; never hand-built JSON.
- **ReDoS discipline.** Bounded repetitions, no nested quantifiers, precompiled patterns, per-pattern adversarial timing test.
- **Resource bounds.** 5 MiB file cap, 100 KiB line truncation, per-line/per-file/total finding caps, iterative (non-recursive) walk, bounded PEM lookahead.
- **Symlink safety.** Directory symlinks not followed by default; `(st_dev, st_ino)` loop guard; broken links counted, never fatal.
- **Encoding safety.** Explicit BOM table, UTF-8 `errors=replace`, never raises on decode.
- **Config safety.** 1 MiB cap, stdlib TOML only, unknown keys rejected, no includes/eval/plugin paths.
- **Redaction everywhere.** Findings hash raw values at construction; reporters only see previews; `--verbose` and tracebacks never carry secrets (covered by property tests over all renderers).

If you find a bypass or leak, treat it as a security bug: minimal reproducible case, redacted logs, no real credentials in the report.
