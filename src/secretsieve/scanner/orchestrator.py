"""Scan orchestration: discovery -> gating/reading -> detection engine.

One-way dependency: the scanner owns I/O and stats; detection lives in
``detectors.engine``. A failure in one file never aborts the scan.
"""

from __future__ import annotations

import time
from pathlib import Path

from secretsieve.detectors.engine import scan_file_content
from secretsieve.models.config import Config
from secretsieve.models.finding import Finding
from secretsieve.models.stats import ScanStats
from secretsieve.scanner.discovery import FileRecord, iter_files
from secretsieve.scanner.reader import read_lines
from secretsieve.utils.timing import StageTimer


class ScanOutcome:
    def __init__(
        self,
        findings: list[Finding],
        stats: ScanStats,
        warnings: list[str],
        scan_root: Path,
        duration_ms: int,
        timing: dict[str, float] | None = None,
    ) -> None:
        self.findings = findings
        self.stats = stats
        self.warnings = warnings
        self.scan_root = scan_root
        self.duration_ms = duration_ms
        self.timing = timing or {}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        out.append(f)
    return out


def run_scan(paths: list[str], cfg: Config) -> ScanOutcome:
    started = time.perf_counter()
    stats = ScanStats()
    warnings: list[str] = []
    timer = StageTimer()

    resolved: list[Path] = []
    for p in paths or ["."]:
        candidate = Path(p)
        if not candidate.exists():
            raise FileNotFoundError(f"path not found: '{p}'")
        resolved.append(candidate.resolve())

    # Scan root: common parent for display paths (cwd when scanning cwd).
    scan_root = Path.cwd().resolve()
    try:
        # If every input is under the cwd, report relative to cwd (stable CI paths).
        for r in resolved:
            r.relative_to(scan_root)
    except ValueError:
        # Mixed/absolute inputs outside cwd: use the common ancestor.
        scan_root = Path(*resolved[0].parts[:2]) if len(resolved) == 1 else Path.cwd().resolve()
        if len(resolved) == 1 and resolved[0].is_dir():
            scan_root = resolved[0]
        elif len(resolved) == 1 and resolved[0].is_file():
            scan_root = resolved[0].parent

    records: list[FileRecord] = []
    with timer.stage("discovery"):
        records = iter_files(
            resolved,
            scan_root,
            extra_exclude=cfg.exclude,
            include=cfg.include,
            no_default_excludes=cfg.no_default_excludes,
            follow_symlinks=cfg.follow_symlinks,
            stats=stats,
            warnings=warnings,
        )
    if cfg.include and not any(r.is_explicit for r in records):
        warnings.append("no files matched --include patterns (explicit path args still scanned)")

    findings: list[Finding] = []
    for record in records:
        if len(findings) >= cfg.max_findings_total:
            warnings.append(f"total finding cap reached ({cfg.max_findings_total}); remaining files skipped")
            break
        with timer.stage("gating_read"):
            result = read_lines(
                record.abs_path,
                max_file_bytes=cfg.max_file_bytes,
                max_line_len=cfg.max_line_len,
            )
        if result.skipped_reason == "binary":
            stats.files_skipped += 1
            stats.skip_binary += 1
            continue
        if result.skipped_reason == "oversize":
            stats.files_skipped += 1
            stats.skip_oversize += 1
            continue
        if result.skipped_reason == "unreadable":
            stats.files_errored += 1
            stats.errors.append(f"cannot read '{record.rel}'")
            continue
        stats.files_scanned += 1
        if result.truncated:
            stats.truncated_files += 1
        try:
            with timer.stage("detect"):
                file_findings = scan_file_content(
                    record.rel,
                    result.lines,
                    cfg,
                    stats,
                    generated=record.generated,
                    lockfile=record.lockfile,
                )
        except Exception as exc:  # never let one file kill the scan
            stats.files_errored += 1
            stats.errors.append(f"error scanning '{record.rel}': {type(exc).__name__}")
            continue
        # Per-file finding cap.
        if len(file_findings) > cfg.max_findings_per_file:
            file_findings = file_findings[: cfg.max_findings_per_file]
        findings.extend(file_findings)

    findings = _dedupe(findings)
    findings.sort(key=lambda f: f.sort_key())
    duration_ms = int((time.perf_counter() - started) * 1000)
    return ScanOutcome(findings, stats, warnings, scan_root, duration_ms, dict(timer.marks))
