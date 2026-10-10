"""Scan orchestration: discovery -> gating/reading -> detection engine.

One-way dependency: the scanner owns I/O and stats; detection lives in
``detectors.engine``. A failure in one file never aborts the scan.

Two entry points share one detection core:

- :func:`run_scan` — working-tree files discovered from disk.
- :func:`run_scan_blobs` — in-memory ``(rel_path, bytes)`` blobs (used for
  Git index contents, where the staged bytes — not the working tree — are
  authoritative). No temporary files are written.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from secretsieve.detectors.engine import scan_file_content
from secretsieve.models.config import Config
from secretsieve.models.finding import Finding
from secretsieve.models.stats import ScanStats
from secretsieve.scanner import filetypes
from secretsieve.scanner.discovery import FileRecord, iter_files
from secretsieve.scanner.filters import should_scan_file
from secretsieve.scanner.gating import SNIFF_BYTES, detect_decode, sniff_is_binary
from secretsieve.scanner.reader import _KNOWN_BOMS, read_lines
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


@dataclass
class BlobInput:
    """In-memory file content (e.g. a Git index blob) with its repo path."""

    rel: str  # posix path relative to the scan root, as Git reports it
    content: bytes


def _split_lines(text: str, max_line_len: int) -> tuple[list[tuple[int, str, bool]], bool]:
    out: list[tuple[int, str, bool]] = []
    truncated_any = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.endswith("\r"):
            line = line[:-1]
        if len(line) > max_line_len:
            out.append((lineno, line[:max_line_len], True))
            truncated_any = True
        else:
            out.append((lineno, line, False))
    return out, truncated_any


def _scan_decoded(
    rel: str,
    lines: list[tuple[int, str, bool]],
    cfg: Config,
    stats: ScanStats,
    timer: StageTimer,
    *,
    generated: bool,
    lockfile: bool,
    line_truncated: bool,
    findings: list[Finding],
) -> None:
    """Run the detection engine over one decoded file; appends findings."""
    stats.files_scanned += 1
    if line_truncated:
        stats.truncated_files += 1
    try:
        with timer.stage("detect"):
            file_findings = scan_file_content(
                rel, lines, cfg, stats, generated=generated, lockfile=lockfile,
            )
    except Exception as exc:  # never let one file kill the scan
        stats.files_errored += 1
        stats.errors.append(f"error scanning '{rel}': {type(exc).__name__}")
        return
    if len(file_findings) > cfg.max_findings_per_file:
        file_findings = file_findings[: cfg.max_findings_per_file]
    findings.extend(file_findings)


def _check_total_cap(findings: list[Finding], cfg: Config, warnings: list[str]) -> bool:
    if len(findings) >= cfg.max_findings_total:
        warnings.append(f"total finding cap reached ({cfg.max_findings_total}); remaining files skipped")
        return True
    return False


def _finish(
    findings: list[Finding],
    stats: ScanStats,
    warnings: list[str],
    scan_root: Path,
    started: float,
    timer: StageTimer,
) -> ScanOutcome:
    findings = _dedupe(findings)
    findings.sort(key=lambda f: f.sort_key())
    duration_ms = int((time.perf_counter() - started) * 1000)
    return ScanOutcome(findings, stats, warnings, scan_root, duration_ms, dict(timer.marks))


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
        if _check_total_cap(findings, cfg, warnings):
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
        _scan_decoded(
            record.rel, result.lines, cfg, stats, timer,
            generated=record.generated, lockfile=record.lockfile,
            line_truncated=result.truncated, findings=findings,
        )

    return _finish(findings, stats, warnings, scan_root, started, timer)


def run_scan_blobs(blobs: list[BlobInput], cfg: Config, scan_root: Path) -> ScanOutcome:
    """Scan in-memory blobs (Git index contents) with disk-scan semantics.

    Exclusions, binary/size gates, redaction, severity, and confidence behave
    exactly as in :func:`run_scan`. Blobs are treated as non-explicit paths so
    default exclusions apply.
    """
    started = time.perf_counter()
    stats = ScanStats()
    warnings: list[str] = []
    timer = StageTimer()
    findings: list[Finding] = []

    ordered = sorted(blobs, key=lambda b: b.rel)
    for blob in ordered:
        if _check_total_cap(findings, cfg, warnings):
            break
        rel = blob.rel.replace("\\", "/")
        ok, reason = should_scan_file(
            rel,
            extra_exclude=cfg.exclude,
            include=cfg.include,
            no_default_excludes=cfg.no_default_excludes,
            is_explicit_arg=False,
        )
        if not ok:
            stats.files_skipped += 1
            if reason == "excluded":
                stats.skip_excluded += 1
            elif reason == "extension":
                stats.skip_extension += 1
            continue
        raw = blob.content
        if len(raw) > cfg.max_file_bytes:
            stats.files_skipped += 1
            stats.skip_oversize += 1
            continue
        head = raw[: SNIFF_BYTES + 1]
        if sniff_is_binary(head) and not head.startswith(_KNOWN_BOMS):
            stats.files_skipped += 1
            stats.skip_binary += 1
            continue
        with timer.stage("gating_read"):
            text, _encoding = detect_decode(raw)
            lines, truncated = _split_lines(text, cfg.max_line_len)
        _scan_decoded(
            rel, lines, cfg, stats, timer,
            generated=filetypes.is_generated(rel),
            lockfile=filetypes.is_lockfile(rel),
            line_truncated=truncated, findings=findings,
        )

    return _finish(findings, stats, warnings, scan_root, started, timer)


def merge_outcomes(first: ScanOutcome, second: ScanOutcome) -> ScanOutcome:
    """Combine two outcomes (used for --staged + --unstaged unions)."""
    findings = _dedupe([*first.findings, *second.findings])
    findings.sort(key=lambda f: f.sort_key())
    stats = ScanStats(
        files_scanned=first.stats.files_scanned + second.stats.files_scanned,
        files_skipped=first.stats.files_skipped + second.stats.files_skipped,
        skip_binary=first.stats.skip_binary + second.stats.skip_binary,
        skip_excluded=first.stats.skip_excluded + second.stats.skip_excluded,
        skip_oversize=first.stats.skip_oversize + second.stats.skip_oversize,
        skip_extension=first.stats.skip_extension + second.stats.skip_extension,
        skip_generated=first.stats.skip_generated + second.stats.skip_generated,
        files_errored=first.stats.files_errored + second.stats.files_errored,
        candidates=first.stats.candidates + second.stats.candidates,
        truncated_files=first.stats.truncated_files + second.stats.truncated_files,
        suppressed={**first.stats.suppressed},
        errors=[*first.stats.errors, *second.stats.errors],
    )
    for key, value in second.stats.suppressed.items():
        stats.suppressed[key] = stats.suppressed.get(key, 0) + value
    timing = dict(first.timing)
    for key, value in second.timing.items():
        timing[key] = timing.get(key, 0.0) + value
    return ScanOutcome(
        findings, stats,
        [*first.warnings, *second.warnings],
        first.scan_root,
        first.duration_ms + second.duration_ms,
        timing,
    )
