"""Emit an annotated ``secretsieve.toml`` starter template (``config --init``)."""

TEMPLATE = """# SecretSieve configuration - https://3rabdev.online
# Copyright (c) 3rabDev. Licensed under the MIT License; see LICENSE.

[scan]
# Extra globs (relative to scan root) appended to the default exclusions.
exclude = []
# If non-empty, only matching paths are scanned (after exclusions).
include = []
# Never follow directory symlinks unless you explicitly opt in.
follow_symlinks = false
# Files larger than this are skipped (bytes).
max_file_bytes = 5242880
# Lines longer than this are truncated (bytes).
max_line_len = 102400
# Reserved for the future; setting it warns and is ignored.
respect_gitignore = false

[output]
# human | json
format = "human"
# info | low | medium | high | critical - display floor only.
severity_floor = "low"
# low | medium | high | critical - CI failure gate (INFO never fails).
fail_on = "low"
# Hide findings below this confidence (0-99).
min_confidence = 0
no_color = false

[entropy]
base64_threshold = 4.5
hex_threshold = 3.7
mixed_threshold = 4.0
min_length = 16

[rules]
# Rule IDs to disable, e.g. ["SS-DISCORD-001"].
disabled = []

[allow]
# Extra case-insensitive placeholder values for your org.
placeholder_values = []
# Stable suppressions by finding fingerprint (preferred):
# [[allow.fingerprint]]
# value = "sha256:..."
# Scoped suppressions by rule + path glob:
# [[allow.path_rule]]
# rule = "SS-GENERIC-002"
# path = "tests/fixtures/**"

[advanced]
max_candidates_per_file = 500
max_findings_per_file = 100
"""
