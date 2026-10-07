"""Human-readable terminal renderer (PLAN Sec. 25.1).

Terse, factual, security-professional. No banners, no spinners, no raw values.
All attacker-controlled fields pass through ``sanitize_for_terminal``.
"""

from __future__ import annotations

from secretsieve.models.finding import Finding
from secretsieve.models.stats import ScanStats
from secretsieve.utils.sanitize import sanitize_for_terminal

_COLORS = {
    "CRITICAL": "\x1b[1;31m",
    "HIGH": "\x1b[31m",
    "MEDIUM": "\x1b[33m",
    "LOW": "\x1b[36m",
    "INFO": "\x1b[90m",
}
_RESET = "\x1b[0m"


def _sev(severity: str, color: bool) -> str:
    label = f"{severity:<8}"
    if not color:
        return label
    code = _COLORS.get(severity, "")
    if not code:
        return label
    return f"{code}{label}{_RESET}"


def render_human(
    *,
    findings: list[Finding],
    stats: ScanStats,
    version: str,
    targets: list[str],
    duration_ms: float,
    exit_code: int,
    use_color: bool,
    quiet: bool,
    verbose: bool,
    warnings: list[str],
    file_errors: list[str],
    timing: dict[str, float] | None = None,
) -> str:
    shown_targets = " ".join(sanitize_for_terminal(t) for t in targets) or "."
    if quiet:
        lines = []
        for f in findings:
            lines.append(
                f"{f.severity} {sanitize_for_terminal(f.path)}:{f.line} "
                f"{sanitize_for_terminal(f.rule_id)} conf={f.confidence}%"
            )
        return "\n".join(lines) + ("\n" if lines else "")

    out: list[str] = [f"SecretSieve v{version} - scan {shown_targets}", ""]
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    info = sum(1 for f in findings if f.severity == "INFO")
    out.append(f"Files scanned:        {stats.files_scanned}")
    skipped = stats.files_skipped
    out.append(
        f"Files skipped:         {skipped}  ({stats.skip_binary} binary, "
        f"{stats.skip_excluded} excluded, {stats.skip_oversize} oversize, "
        f"{stats.skip_extension} extension)"
    )
    out.append(f"Candidates evaluated: {stats.candidates}")
    parts = []
    if crit:
        parts.append(f"{crit} critical")
    if high:
        parts.append(f"{high} high")
    if med:
        parts.append(f"{med} medium")
    if low:
        parts.append(f"{low} low")
    if info:
        parts.append(f"{info} info")
    out.append(f"Findings:               {len(findings)}" + (f"  ({', '.join(parts)})" if parts else ""))
    out.append("")
    for f in findings:
        title = sanitize_for_terminal(_title_for(f))
        loc = f"{sanitize_for_terminal(f.path)}:{f.line}"
        meta = f"[{sanitize_for_terminal(f.rule_id)} | conf {f.confidence}% | {f.confidence_band}]"
        out.append(f"{_sev(f.severity, use_color)}  {title} - {loc}  {meta}")
        out.append(f"  {sanitize_for_terminal(f.redacted)}")
        reason = sanitize_for_terminal(f.reason)
        out.append(f"  Reason: {reason}")
        out.append("")
    secs = duration_ms / 1000
    summary_bits = []
    if crit:
        summary_bits.append(f"{crit} critical")
    if high:
        summary_bits.append(f"{high} high")
    if med:
        summary_bits.append(f"{med} medium")
    if low:
        summary_bits.append(f"{low} low")
    if info:
        summary_bits.append(f"{info} info")
    summary = f"{len(findings)} findings" + (f" ({' | '.join(summary_bits)})" if summary_bits else "")
    out.append(f"Summary: {summary} in {secs:.2f}s - exit {exit_code}")
    if warnings and verbose:
        out.append("")
        out.append("Warnings:")
        for w in warnings:
            out.append(f"  - {sanitize_for_terminal(w)}")
    if file_errors:
        shown = file_errors if verbose else file_errors[:5]
        out.append("")
        out.append("File errors:" if verbose else f"File errors (showing {len(shown)} of {len(file_errors)}; use --verbose):")
        for e in shown:
            out.append(f"  - {sanitize_for_terminal(e)}")
    if verbose:
        out.append("")
        out.append("Detail:")
        out.append(f"  files_errored: {stats.files_errored}")
        out.append(f"  truncated_files: {stats.truncated_files}")
        if stats.suppressed:
            supp = ", ".join(f"{k}={v}" for k, v in sorted(stats.suppressed.items()))
            out.append(f"  suppressed: {supp}")
        else:
            out.append("  suppressed: none")
        if timing:
            stages = ", ".join(f"{k}={v * 1000:.0f}ms" for k, v in sorted(timing.items()))
            out.append(f"  timing: {stages}")
    return "\n".join(out) + "\n"


def _title_for(f: Finding) -> str:
    from secretsieve.rules import RULES_BY_ID

    rule = RULES_BY_ID.get(f.rule_id)
    if rule is not None:
        return rule.name
    return f.rule_id
