# Configuration

Copyright (c) 3rabDev - https://3rabdev.online

Source precedence: `--config PATH` > `./secretsieve.toml` >
`./pyproject.toml [tool.secretsieve]` > defaults. `--no-config` ignores files.

Unknown sections/keys are **hard errors** (exit 2) to catch typos.
Run `secretsieve config --init` for the annotated template, or copy the
shipped `secretsieve.toml` example at the repo root.

```toml
[scan]
exclude = ["docs/drafts/**"]   # appended to defaults
include = []                   # non-empty = allowlist
follow_symlinks = false
max_file_bytes = 5242880
max_line_len = 102400
respect_gitignore = false      # reserved future; true warns and is ignored

[output]
format = "human"               # human | json
severity_floor = "low"
fail_on = "low"
min_confidence = 0
no_color = false

[entropy]
base64_threshold = 4.5
hex_threshold = 3.7
mixed_threshold = 4.0
min_length = 16

[rules]
disabled = ["SS-DISCORD-001"]

[allow]
placeholder_values = ["acme-internal-test"]
[[allow.fingerprint]]
value = "sha256:..."
[[allow.path_rule]]
rule = "SS-GENERIC-002"
path = "tests/fixtures/**"

[advanced]
max_candidates_per_file = 500
max_findings_per_file = 100
```

Notes:

- Config files are capped at 1 MiB and parsed with stdlib TOML only. No code execution.
- `[[allow.fingerprint]]` (stable across edits) is preferred over path rules.
- Inline `# secretsieve:ignore` suppresses one line; it is counted in `--verbose` stats.
