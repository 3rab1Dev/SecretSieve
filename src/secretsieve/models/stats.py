"""Scan counters (files, skips, suppressions). Nothing secret-bearing here."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    skip_binary: int = 0
    skip_excluded: int = 0
    skip_oversize: int = 0
    skip_extension: int = 0
    skip_generated: int = 0  # informational only; generated files are still scanned
    files_errored: int = 0
    candidates: int = 0
    truncated_files: int = 0
    suppressed: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def note_suppressed(self, reason: str) -> None:
        self.suppressed[reason] = self.suppressed.get(reason, 0) + 1

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "skip_breakdown": {
                "binary": self.skip_binary,
                "excluded": self.skip_excluded,
                "oversize": self.skip_oversize,
                "extension": self.skip_extension,
            },
            "files_errored": self.files_errored,
            "candidates": self.candidates,
            "suppressed": dict(self.suppressed),
            "truncated_files": self.truncated_files,
        }
