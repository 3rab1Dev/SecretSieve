"""Argument parsing (PLAN Sec. 24).

Dispatch model: ``scan`` (explicit or implicit), ``rules``, ``explain``,
``config``. The implicit form (``secretsieve [PATH] [options]``) is parsed
with the same scan options as ``secretsieve scan ...``.
"""

from __future__ import annotations

import argparse

SEVERITY_CHOICES = ("info", "low", "medium", "high", "critical")
FAIL_CHOICES = ("low", "medium", "high", "critical")

_EPILOG = (
    "Privacy: SecretSieve is local-first - scanning performs no network I/O, "
    "uploads nothing, and verifies nothing against third-party services. "
    "Output is redacted by default. See https://3rabdev.online"
)


def add_scan_options(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("paths", nargs="*", default=[], help="files or directories to scan (default: .)")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON report on stdout")
    parser.add_argument("-q", "--quiet", action="store_true", help="findings only (one line per finding)")
    parser.add_argument("-v", "--verbose", action="store_true", help="detail without secrets: stats, suppress counts, skips")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    parser.add_argument("--severity", choices=SEVERITY_CHOICES, default=None,
                        help="minimum DISPLAY severity (default: low; info shows INFO)")
    parser.add_argument("--fail-on", choices=FAIL_CHOICES, default=None,
                        help="minimum severity that fails CI (default: low; INFO never fails)")
    parser.add_argument("--min-confidence", type=int, default=None, help="hide findings below N (0-99)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="extra exclude glob (repeatable)")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB",
                        help="restrict to matching paths (repeatable)")
    parser.add_argument("--no-default-excludes", action="store_true", help="drop default directory exclusions")
    parser.add_argument("--follow-symlinks", action="store_true", help="follow directory symlinks during descent")
    parser.add_argument("--staged", action="store_true", help="scan files staged in the git index")
    parser.add_argument("--unstaged", action="store_true", help="scan tracked-modified + untracked files")
    parser.add_argument("--config", default=None, metavar="PATH", help="config file path")
    parser.add_argument("--no-config", action="store_true", help="ignore config files (hermetic CI)")
    parser.add_argument("--disable-rule", action="append", default=[], metavar="ID",
                        help="rule kill-switch, e.g. SS-DISCORD-001 (repeatable)")
    parser.add_argument("--max-file-bytes", type=int, default=None, metavar="N", help="override size gate")
    parser.add_argument("--output", default=None, metavar="PATH", help="write JSON report to file (with --json)")
    return parser


def build_scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretsieve", description="SecretSieve - sieve the secrets out of your source.", epilog=_EPILOG)
    parser.add_argument("--version", action="store_true", help="print version and exit")
    return add_scan_options(parser)


def build_explicit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretsieve", description="SecretSieve - sieve the secrets out of your source.", epilog=_EPILOG)
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="scan files or directories (explicit form)")
    add_scan_options(scan_p)

    rules_p = sub.add_parser("rules", help="list / show detection rules")
    group = rules_p.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list all rules")
    group.add_argument("--show", metavar="ID", help="show one rule card")

    explain_p = sub.add_parser("explain", help="explain a rule ID")
    explain_p.add_argument("rule_id", help="e.g. SS-GITHUB-001")

    config_p = sub.add_parser("config", help="config helpers")
    cgroup = config_p.add_mutually_exclusive_group(required=True)
    cgroup.add_argument("--init", action="store_true", help="print a starter secretsieve.toml")
    cgroup.add_argument("--validate", action="store_true", help="validate the resolved config file")
    config_p.add_argument("--config", default=None, metavar="PATH", help="config file path")
    config_p.add_argument("--no-config", action="store_true", help="ignore config files")
    return parser


def parse_scan_args(argv: list[str]) -> argparse.Namespace:
    """Parse implicit-scan argv (testable without I/O)."""
    return build_scan_parser().parse_args(argv)
