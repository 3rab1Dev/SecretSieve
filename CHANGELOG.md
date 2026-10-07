# Changelog

All notable changes to SecretSieve are recorded here. Versioning follows SemVer.
Rule-loosening or threshold-lowering changes bump MINOR with a note; rule
tightening (fewer false positives) bumps PATCH.

## [1.0.0] - 2026-10-07 - Released

Initial stable release:

* Working-tree scanner: recursive discovery, default exclusions, binary/size/encoding gates, symlink safety, bounded per-file budgets.
* Multi-signal detection: 24 signature rules (Tier 1 + Tier 2 providers), Shannon entropy with per-encoding thresholds, whole-token context analysis, structural validators.
* Deterministic confidence (0-99, never 100) and intrinsic severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) as orthogonal axes.
* False-positive system: placeholders, empty/defaults, hashes/UUIDs, test/fixture/docs/example demotion, generated-file handling, config allowlists, line-scoped `# secretsieve:ignore`.
* CLI: implicit `secretsieve [PATH]` + explicit `scan`, `rules --list/--show`, `explain`, `config --init/--validate`; `--json/--quiet/--verbose/--no-color/--severity/--fail-on/--min-confidence/--exclude/--include/--no-default-excludes/--follow-symlinks/--staged/--unstaged/--config/--no-config/--disable-rule/--max-file-bytes/--output`.
* Redacted human + JSON schema-v1 output (`schemas/report-v1.json`); exit codes 0/1/2 for generic CI.
* `secretsieve.toml` (+ `[tool.secretsieve]` in `pyproject.toml`) with strict unknown-key rejection.
* Local Git file-list modes (`--staged/--unstaged`); `.git/` never descended.
* Test suite: unit, integration, CLI, FP regression, determinism, privacy/offline, security.
* Docs: README + `docs/` set; performance corpus generator in `tools/`.

Copyright (c) 3rabDev - https://3rabdev.online
