# Changelog

All notable changes to SecretSieve are recorded here. Versioning follows SemVer.
Rule-loosening or threshold-lowering changes bump MINOR with a note; rule
tightening (fewer false positives) bumps PATCH.

## [1.0.1] - 2026-10-10

### Fixed

* Fixed `--staged` scanning to inspect Git index blob contents rather than working-tree contents.
* Added regression coverage for partially staged files and other staged-index edge cases.

Details:

* `--staged` now reads each staged path with `git cat-file -p :<path>` plumbing (NUL-delimited status parsing, rename pairs, spaces in filenames). Partially staged files scan as staged, exclusively.
* Staged deletions carry no index content and are skipped by design (no crash, no worktree fallback).
* A missing or unreadable staged blob is an actionable exit-2 error; the scanner never silently falls back to working-tree bytes.
* Staged blobs go through the same pipeline as disk scans: exclusions, binary/size gates, redaction, confidence/severity, deterministic ordering, JSON schema v1.
* Removed dead code flagged by lint (unused imports/variables).

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
