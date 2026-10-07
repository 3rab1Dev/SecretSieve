"""Effective scan configuration (defaults + file + CLI merge result)."""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_LINE_LEN = 100 * 1024


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    include: list[str] = field(default_factory=list)
    no_default_excludes: bool = False
    follow_symlinks: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_line_len: int = DEFAULT_MAX_LINE_LEN
    severity_floor: str = "low"
    fail_on: str = "low"
    min_confidence: int = 0
    no_color: bool = False
    as_json: bool = False
    quiet: bool = False
    verbose: bool = False
    disabled_rules: list[str] = field(default_factory=list)
    base64_threshold: float = 4.5
    hex_threshold: float = 3.7
    mixed_threshold: float = 4.0
    entropy_min_length: int = 16
    placeholder_values: list[str] = field(default_factory=list)
    allow_fingerprints: list[str] = field(default_factory=list)
    allow_path_rules: list[dict] = field(default_factory=list)
    max_candidates_per_file: int = 500
    max_findings_per_file: int = 100
    max_findings_total: int = 10000
    output_path: str | None = None
    config_path: str | None = None

    def snapshot(self) -> dict:
        return {
            "severity_floor": self.severity_floor,
            "fail_on": self.fail_on,
            "min_confidence": self.min_confidence,
            "max_file_bytes": self.max_file_bytes,
        }
