"""Scan controller: argv -> config -> engine -> reporter -> exit code.

Copyright (c) 3rabDev - https://3rabdev.online
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

from secretsieve import __version__
from secretsieve.cli import output as outmod
from secretsieve.cli.parser import build_explicit_parser, build_scan_parser
from secretsieve.config import loader as config_loader
from secretsieve.config.template import TEMPLATE
from secretsieve.detectors import scoring
from secretsieve.scanner.orchestrator import run_scan

SUBCOMMANDS = ("scan", "rules", "explain", "config")


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    try:
        if args_list and args_list[0] in SUBCOMMANDS:
            return _run_subcommand(args_list)
        return _run_scan(args_list)
    except (config_loader.ConfigError, FileNotFoundError) as exc:
        print(f"secretsieve: error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 2


# ------------------------------------------------------------------ scanning

def _run_scan(argv: list[str]) -> int:
    parser = build_scan_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        _print_version()
        return 0
    return _execute_scan(args, targets=args.paths or ["."])


def _execute_scan(args: object, targets: list[str]) -> int:
    get = getattr
    cfg, cfg_warnings = config_loader.discover_config(
        get(args, "config", None), bool(get(args, "no_config", False)), Path.cwd()
    )
    cfg = config_loader.apply_cli(cfg, args)
    if get(args, "min_confidence", None) is not None and not 0 <= int(get(args, "min_confidence")) <= 99:
        print("secretsieve: error: --min-confidence must be 0-99", file=sys.stderr)
        return 2
    if get(args, "output", None) and not cfg.as_json:
        print("secretsieve: error: --output requires --json", file=sys.stderr)
        return 2

    scan_targets = list(targets)
    git_warnings: list[str] = []
    if get(args, "staged", False) or get(args, "unstaged", False):
        from secretsieve import git as gitmod

        cwd = Path.cwd()
        selected: list[str] = []
        try:
            if get(args, "staged", False):
                selected += gitmod.get_staged_files(cwd)
            if get(args, "unstaged", False):
                selected += gitmod.get_unstaged_files(cwd)
        except gitmod.GitError as exc:
            print(f"secretsieve: error: {exc}", file=sys.stderr)
            return 2
        selected = [p for p in dict.fromkeys(selected) if (cwd / p).exists()]
        if not selected:
            git_warnings.append("git file list is empty; nothing to scan")
        scan_targets = selected or []
        if not scan_targets:
            # Still emit a valid (empty) report for CI stability.
            return _emit_empty(args, cfg, cfg_warnings + git_warnings)

    try:
        outcome = run_scan(scan_targets or ["."], cfg)
    except FileNotFoundError as exc:
        print(f"secretsieve: error: {exc}", file=sys.stderr)
        return 2

    warnings = cfg_warnings + git_warnings + outcome.warnings

    gate = [f for f in outcome.findings if scoring.meets_fail_on(f.severity, cfg.fail_on)]
    if gate:
        exit_code = 1
    elif outcome.stats.files_errored > 0:
        exit_code = 2
    else:
        exit_code = 0

    if cfg.as_json:
        return _emit_json(args, cfg, outcome, warnings, exit_code)

    display = [
        f for f in outcome.findings
        if scoring.meets_floor(f.severity, cfg.severity_floor) and f.confidence >= cfg.min_confidence
    ]
    text = outmod.render_human(
        findings=display,
        stats=outcome.stats,
        version=__version__,
        targets=scan_targets or ["."],
        duration_ms=outcome.duration_ms,
        exit_code=exit_code,
        use_color=outmod.should_use_color(cfg.no_color, False),
        quiet=cfg.quiet,
        verbose=cfg.verbose,
        warnings=warnings,
        file_errors=list(outcome.stats.errors),
        timing=dict(outcome.timing),
    )
    _write_stdout(text)
    for w in warnings:
        if not cfg.verbose:
            print(f"secretsieve: warning: {w}", file=sys.stderr)
    for e in outcome.stats.errors:
        print(f"secretsieve: warning: {e}", file=sys.stderr)
    return exit_code


def _emit_json(args: object, cfg: object, outcome: object, warnings: list[str], exit_code: int) -> int:
    from secretsieve.reporting.json_report import build_report

    get = getattr
    report = build_report(
        version=__version__,
        scan_root=str(get(outcome, "scan_root", ".")),
        duration_ms=int(get(outcome, "duration_ms", 0)),
        stats=get(outcome, "stats"),
        findings=list(get(outcome, "findings", [])),
        config_snapshot=get(cfg, "snapshot")(),
        exit_code=exit_code,
        warnings=warnings,
    )
    payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=False)
    out_path = get(cfg, "output_path", None)
    if out_path:
        try:
            Path(out_path).write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"secretsieve: error: cannot write --output file: {exc}", file=sys.stderr)
            return 2
    else:
        _write_stdout(payload + "\n")
    for w in warnings:
        print(f"secretsieve: warning: {w}", file=sys.stderr)
    for e in get(get(outcome, "stats"), "errors", []):
        print(f"secretsieve: warning: {e}", file=sys.stderr)
    return exit_code


def _emit_empty(args: object, cfg: object, warnings: list[str]) -> int:
    """Emit a valid empty report (used when git file lists are empty)."""
    from secretsieve.models.stats import ScanStats
    from types import SimpleNamespace

    outcome = SimpleNamespace(findings=[], stats=ScanStats(), warnings=[], scan_root=Path.cwd(), duration_ms=0, timing={})
    if bool(getattr(cfg, "as_json", False)):
        return _emit_json(args, cfg, outcome, warnings, 0)
    text = outmod.render_human(
        findings=[], stats=outcome.stats, version=__version__, targets=["(git file list: empty)"],
        duration_ms=0, exit_code=0, use_color=False, quiet=bool(getattr(cfg, "quiet", False)),
        verbose=bool(getattr(cfg, "verbose", False)), warnings=warnings, file_errors=[],
    )
    _write_stdout(text)
    return 0


def _write_stdout(text: str) -> None:
    try:
        sys.stdout.write(text)
    except BrokenPipeError:
        pass


# -------------------------------------------------------------- subcommands

def _run_subcommand(argv: list[str]) -> int:
    name = argv[0]
    if name == "scan":
        parser = build_scan_parser()
        args = parser.parse_args(argv[1:])
        if getattr(args, "version", False):
            _print_version()
            return 0
        return _execute_scan(args, targets=args.paths or ["."])
    parser = build_explicit_parser()
    args = parser.parse_args(argv)
    cmd = getattr(args, "command", None)
    if cmd == "rules":
        return _cmd_rules(args)
    if cmd == "explain":
        return _cmd_explain(str(getattr(args, "rule_id", "")))
    if cmd == "config":
        return _cmd_config(args)
    parser.print_help()
    return 2


def _cmd_rules(args: object) -> int:
    from secretsieve.rules import RULE_REGISTRY, RULES_BY_ID
    from secretsieve.utils.sanitize import sanitize_for_terminal

    if getattr(args, "list", False):
        for rule in sorted(RULE_REGISTRY, key=lambda r: r.id):
            print(f"{rule.id:<22} {rule.severity:<8} {sanitize_for_terminal(rule.name)}")
        print(f"\n{len(RULE_REGISTRY)} rules - https://3rabdev.online")
        return 0
    show = getattr(args, "show", None)
    if show:
        return _cmd_explain(str(show))
    return 2


def _cmd_explain(rule_id: str) -> int:
    from secretsieve.rules import RULES_BY_ID
    from secretsieve.utils.sanitize import sanitize_for_terminal

    rid = rule_id.strip().upper()
    # Accept the documented alias.
    if rid == "SS-GENERIC-JWT-001":
        rid = "SS-JWT-001"
    rule = RULES_BY_ID.get(rid)
    if rule is None:
        print(f"secretsieve: error: unknown rule '{rule_id.strip()}' (try: secretsieve rules --list)", file=sys.stderr)
        return 2
    print(f"{sanitize_for_terminal(rule.id)} - {sanitize_for_terminal(rule.name)}")
    print(f"Provider:   {sanitize_for_terminal(rule.provider)}")
    print(f"Category:   {sanitize_for_terminal(rule.category)}")
    print(f"Severity:   {rule.severity}")
    print(f"Confidence: base {rule.base_confidence} (adjusted by context, entropy, structure)")
    print(f"Needs context: {'yes' if rule.context_required else 'no (standalone signature)'}")
    print(f"Keywords:   {sanitize_for_terminal(', '.join(rule.keywords) or '-')}")
    print(f"About:      {sanitize_for_terminal(rule.description)}")
    print(f"Fix:        {sanitize_for_terminal(rule.remediation)}")
    print(f"FP notes:   {sanitize_for_terminal(rule.fp_notes)}")
    return 0


def _cmd_config(args: object) -> int:
    if getattr(args, "init", False):
        _write_stdout(TEMPLATE)
        return 0
    # --validate
    try:
        cfg, warnings = config_loader.discover_config(
            getattr(args, "config", None), bool(getattr(args, "no_config", False)), Path.cwd()
        )
    except config_loader.ConfigError as exc:
        print(f"secretsieve: error: {exc}", file=sys.stderr)
        return 2
    unknown = config_loader.validate_rule_ids(list(cfg.disabled_rules))
    if unknown:
        print(f"secretsieve: error: unknown rule ID(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    where = cfg.config_path or "(defaults; no config file found)"
    print(f"config OK - {where}")
    for w in warnings:
        print(f"warning: {w}")
    return 0


def _print_version() -> None:
    print(f"secretsieve {__version__}")
    print("Copyright (c) 3rabDev - https://3rabdev.online")
