# CLI Reference

Copyright (c) 3rabDev - https://3rabdev.online

## Scan

```bash
secretsieve [PATH ...] [options]       # implicit scan (default PATH = .)
secretsieve scan [PATH ...] [options]  # explicit scan (same behavior, CI clarity)
```

## Helpers

```bash
secretsieve rules --list               # list all 24 rules (ID, severity, name)
secretsieve rules --show SS-AWS-001    # rule card
secretsieve explain SS-GITHUB-001      # same as rules --show
secretsieve config --init              # print starter secretsieve.toml
secretsieve config --validate          # validate resolved config (exit 2 on error)
secretsieve --version                  # version + copyright
python -m secretsieve ...              # identical to the console script
```

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--json` | off | JSON schema-v1 report on stdout |
| `-q, --quiet` | off | one line per finding (`SEVERITY path:line rule conf%`) |
| `-v, --verbose` | off | suppress/skip accounting, file errors, detail (never secrets) |
| `--no-color` | auto | disable ANSI (also honors `NO_COLOR`, `TERM=dumb`, non-TTY) |
| `--severity LEVEL` | `low` | display floor: `info\|low\|medium\|high\|critical` (display only) |
| `--fail-on LEVEL` | `low` | CI gate: `low\|medium\|high\|critical` (INFO never fails) |
| `--min-confidence N` | `0` | hide findings below N (display only) |
| `--exclude GLOB` | - | extra exclude (repeatable, appends to defaults) |
| `--include GLOB` | - | allowlist: only matching paths (repeatable) |
| `--no-default-excludes` | off | drop default dir exclusions |
| `--follow-symlinks` | off | follow directory symlinks |
| `--staged` | off | scan staged index blob contents (never working-tree bytes) |
| `--unstaged` | off | scan tracked-modified + untracked files |
| `--config PATH` | auto | explicit config file |
| `--no-config` | off | ignore config files (hermetic CI) |
| `--disable-rule ID` | - | rule kill-switch (repeatable) |
| `--max-file-bytes N` | 5242880 | override size gate |
| `--output PATH` | stdout | write JSON report to file (use with `--json`) |

Important: `--severity` and `--min-confidence` are **display-only**.
Findings hidden by them still count toward `--fail-on` (prevents hiding
failures with display filters). `--disable-rule` and allowlists remove
findings entirely (auditable in `--verbose` suppress counts).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | no findings at/above `--fail-on`, no fatal errors |
| `1` | findings at/above `--fail-on` (even with non-fatal file errors) |
| `2` | bad path/config/flag, unreadable config, or file errors with no gating findings |

Generic CI example (any system that runs shell):

```bash
secretsieve scan . --json --fail-on high > report.json
```
