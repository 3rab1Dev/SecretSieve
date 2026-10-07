"""Strict TOML configuration loading (PLAN Sec. 28).

- Source precedence: ``--config PATH`` > ``./secretsieve.toml`` >
  ``./pyproject.toml [tool.secretsieve]`` > defaults.
- Unknown keys are hard errors (exit 2) to catch typos.
- The file is size-capped at 1 MiB; parsed with stdlib ``tomllib``
  (``tomli`` backport on 3.10). No code execution from config.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 backport
    import tomli as tomllib  # type: ignore[no-redef]

from secretsieve.models.config import Config

MAX_CONFIG_BYTES = 1024 * 1024
SEVERITIES = ("info", "low", "medium", "high", "critical")
FAIL_LEVELS = ("low", "medium", "high", "critical")

# Top-level sections and their known keys (strict validation).
_KNOWN_SCHEMA: dict[str, set[str]] = {
    "scan": {"exclude", "include", "follow_symlinks", "max_file_bytes", "max_line_len", "respect_gitignore"},
    "output": {"format", "severity_floor", "fail_on", "min_confidence", "no_color"},
    "entropy": {"base64_threshold", "hex_threshold", "mixed_threshold", "min_length"},
    "rules": {"disabled"},
    "allow": {"placeholder_values", "fingerprint", "path_rule"},
    "advanced": {"max_candidates_per_file", "max_findings_per_file", "max_findings_total"},
}


class ConfigError(Exception):
    """Fatal configuration problem (maps to exit code 2)."""


def _read_toml_file(path: Path) -> dict:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigError(f"cannot read config '{path}': {exc.strerror or exc}") from exc
    if size > MAX_CONFIG_BYTES:
        raise ConfigError(f"config '{path}' exceeds 1 MiB size cap")
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception as exc:
        raise ConfigError(f"invalid TOML in '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"invalid TOML in '{path}': top level must be a table")
    return data


def _check_unknown(section: str, table: dict, source: str) -> None:
    known = _KNOWN_SCHEMA[section]
    for key in table:
        if key not in known:
            raise ConfigError(
                f"unknown config key '{section}.{key}' in {source} "
                f"(known keys: {sorted(known)})"
            )


def _as_str_list(value: object, dotted: str, source: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"config '{dotted}' in {source} must be a list of strings")
    return list(value)


def build_config(data: dict, source: str) -> tuple[Config, list[str]]:
    """Validate a parsed TOML table into a :class:`Config` (+ warnings)."""
    warnings: list[str] = []
    cfg = Config()
    cfg.config_path = source if source != "<defaults>" else None

    top_known = set(_KNOWN_SCHEMA) | {"custom_rule"}
    for key in data:
        if key not in top_known:
            raise ConfigError(f"unknown config section '[{key}]' in {source}")
    if "custom_rule" in data:
        raise ConfigError(
            f"custom rules are not supported in this version (see {source}); "
            "remove [[custom_rule]] (planned post-v1.0)"
        )

    scan = data.get("scan", {}) or {}
    if not isinstance(scan, dict):
        raise ConfigError(f"[scan] in {source} must be a table")
    _check_unknown("scan", scan, source)
    cfg.exclude = _as_str_list(scan.get("exclude"), "scan.exclude", source)
    cfg.include = _as_str_list(scan.get("include"), "scan.include", source)
    cfg.follow_symlinks = bool(scan.get("follow_symlinks", False))
    cfg.max_file_bytes = int(scan.get("max_file_bytes", cfg.max_file_bytes))
    cfg.max_line_len = int(scan.get("max_line_len", cfg.max_line_len))
    if cfg.max_file_bytes <= 0 or cfg.max_line_len <= 0:
        raise ConfigError(f"[scan] size limits in {source} must be positive integers")
    if scan.get("respect_gitignore", False):
        warnings.append(
            "config 'scan.respect_gitignore = true' is reserved for a future version "
            "and is ignored (SecretSieve never honors .gitignore in v0.1)."
        )

    output = data.get("output", {}) or {}
    if not isinstance(output, dict):
        raise ConfigError(f"[output] in {source} must be a table")
    _check_unknown("output", output, source)
    fmt = str(output.get("format", "human")).lower()
    if fmt not in ("human", "json"):
        raise ConfigError(f"config 'output.format' in {source} must be 'human' or 'json'")
    cfg.as_json = fmt == "json"
    sev = str(output.get("severity_floor", "low")).lower()
    if sev not in SEVERITIES:
        raise ConfigError(f"config 'output.severity_floor' in {source} must be one of {SEVERITIES}")
    cfg.severity_floor = sev
    fail = str(output.get("fail_on", "low")).lower()
    if fail not in FAIL_LEVELS:
        raise ConfigError(f"config 'output.fail_on' in {source} must be one of {FAIL_LEVELS}")
    cfg.fail_on = fail
    cfg.min_confidence = int(output.get("min_confidence", 0))
    if not 0 <= cfg.min_confidence <= 99:
        raise ConfigError(f"config 'output.min_confidence' in {source} must be 0-99")
    cfg.no_color = bool(output.get("no_color", False))

    entropy = data.get("entropy", {}) or {}
    if not isinstance(entropy, dict):
        raise ConfigError(f"[entropy] in {source} must be a table")
    _check_unknown("entropy", entropy, source)
    cfg.base64_threshold = float(entropy.get("base64_threshold", cfg.base64_threshold))
    cfg.hex_threshold = float(entropy.get("hex_threshold", cfg.hex_threshold))
    cfg.mixed_threshold = float(entropy.get("mixed_threshold", cfg.mixed_threshold))
    cfg.entropy_min_length = int(entropy.get("min_length", cfg.entropy_min_length))
    for name in ("base64_threshold", "hex_threshold", "mixed_threshold"):
        if not 0.0 < getattr(cfg, name) < 8.0:
            raise ConfigError(f"config 'entropy.{name}' in {source} must be within (0, 8)")

    rules = data.get("rules", {}) or {}
    if not isinstance(rules, dict):
        raise ConfigError(f"[rules] in {source} must be a table")
    _check_unknown("rules", rules, source)
    cfg.disabled_rules = _as_str_list(rules.get("disabled"), "rules.disabled", source)

    allow = data.get("allow", {}) or {}
    if not isinstance(allow, dict):
        raise ConfigError(f"[allow] in {source} must be a table")
    _check_unknown("allow", allow, source)
    cfg.placeholder_values = _as_str_list(allow.get("placeholder_values"), "allow.placeholder_values", source)
    fps = allow.get("fingerprint", []) or []
    if isinstance(fps, dict):
        fps = [fps]
    if not isinstance(fps, list):
        raise ConfigError(f"config 'allow.fingerprint' in {source} must be a list of tables")
    for entry in fps:
        if not isinstance(entry, dict) or "value" not in entry:
            raise ConfigError(f"config '[[allow.fingerprint]]' entries in {source} need a 'value' key")
        cfg.allow_fingerprints.append(str(entry["value"]))
    prs = allow.get("path_rule", []) or []
    if isinstance(prs, dict):
        prs = [prs]
    if not isinstance(prs, list):
        raise ConfigError(f"config 'allow.path_rule' in {source} must be a list of tables")
    for entry in prs:
        if not isinstance(entry, dict) or "rule" not in entry or "path" not in entry:
            raise ConfigError(f"config '[[allow.path_rule]]' entries in {source} need 'rule' and 'path' keys")
        cfg.allow_path_rules.append({"rule": str(entry["rule"]), "path": str(entry["path"])})

    advanced = data.get("advanced", {}) or {}
    if not isinstance(advanced, dict):
        raise ConfigError(f"[advanced] in {source} must be a table")
    _check_unknown("advanced", advanced, source)
    cfg.max_candidates_per_file = int(advanced.get("max_candidates_per_file", cfg.max_candidates_per_file))
    cfg.max_findings_per_file = int(advanced.get("max_findings_per_file", cfg.max_findings_per_file))
    cfg.max_findings_total = int(advanced.get("max_findings_total", cfg.max_findings_total))

    return cfg, warnings


def _load_pyproject_tool_table(path: Path) -> dict | None:
    try:
        data = _read_toml_file(path)
    except ConfigError:
        return None
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("secretsieve"), dict):
        return tool["secretsieve"]
    return None


def discover_config(explicit: str | None, no_config: bool, cwd: str | Path) -> tuple[Config, list[str]]:
    """Resolve configuration from explicit path / auto-discovery / defaults."""
    warnings: list[str] = []
    if no_config:
        return Config(), warnings
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise ConfigError(f"config file not found: '{explicit}'")
        cfg, warnings = build_config(_read_toml_file(p), str(p))
        cfg.config_path = str(p)
        return cfg, warnings
    cwd_p = Path(cwd)
    local = cwd_p / "secretsieve.toml"
    if local.is_file():
        cfg, warnings = build_config(_read_toml_file(local), str(local))
        cfg.config_path = str(local)
        return cfg, warnings
    pyproject = cwd_p / "pyproject.toml"
    if pyproject.is_file():
        table = _load_pyproject_tool_table(pyproject)
        if table is not None:
            cfg, warnings = build_config(table, f"{pyproject} [tool.secretsieve]")
            cfg.config_path = str(pyproject)
            return cfg, warnings
    return Config(), warnings


def validate_rule_ids(ids: list[str]) -> list[str]:
    """Return the subset of rule IDs unknown to the registry (lazy import)."""
    from secretsieve.rules import RULES_BY_ID

    return [i for i in ids if i not in RULES_BY_ID]


_RULE_ID_RE = re.compile(r"^SS-[A-Z0-9-]+-[0-9]{3}$")


def check_rule_id_format(rule_id: str) -> bool:
    return bool(_RULE_ID_RE.match(rule_id))


def apply_cli(cfg: Config, args: object) -> Config:
    """Merge CLI flags over file config (CLI wins). ``args`` is argparse Namespace."""
    get = getattr
    if get(args, "exclude", None):
        cfg.exclude = list(cfg.exclude) + list(get(args, "exclude"))
    if get(args, "include", None):
        cfg.include = list(cfg.include) + list(get(args, "include"))
    if get(args, "no_default_excludes", False):
        cfg.no_default_excludes = True
    if get(args, "follow_symlinks", False):
        cfg.follow_symlinks = True
    if get(args, "max_file_bytes", None) is not None:
        if get(args, "max_file_bytes") <= 0:
            raise ConfigError("--max-file-bytes must be a positive integer")
        cfg.max_file_bytes = int(get(args, "max_file_bytes"))
    if get(args, "severity", None):
        cfg.severity_floor = str(get(args, "severity")).lower()
    if get(args, "fail_on", None):
        cfg.fail_on = str(get(args, "fail_on")).lower()
    if get(args, "min_confidence", None) is not None:
        cfg.min_confidence = int(get(args, "min_confidence"))
    if get(args, "no_color", False):
        cfg.no_color = True
    if get(args, "json", False):
        cfg.as_json = True
    if get(args, "quiet", False):
        cfg.quiet = True
    if get(args, "verbose", False):
        cfg.verbose = True
    if get(args, "disable_rule", None):
        cfg.disabled_rules = list(cfg.disabled_rules) + list(get(args, "disable_rule"))
    if get(args, "output", None):
        cfg.output_path = str(get(args, "output"))
    for rid in cfg.disabled_rules:
        if not check_rule_id_format(rid):
            raise ConfigError(f"bad rule ID '{rid}' (expected SS-<FAMILY>-<NNN>)")
    unknown = validate_rule_ids(cfg.disabled_rules)
    if unknown:
        raise ConfigError(f"unknown rule ID(s) in disabled list: {', '.join(unknown)}")
    if cfg.severity_floor not in SEVERITIES:
        raise ConfigError(f"--severity must be one of {SEVERITIES}")
    if cfg.fail_on not in FAIL_LEVELS:
        raise ConfigError(f"--fail-on must be one of {FAIL_LEVELS}")
    if not 0 <= cfg.min_confidence <= 99:
        raise ConfigError("--min-confidence must be 0-99")
    # Honor NO_COLOR env per spec (CLI flag already handled above).
    if os.environ.get("NO_COLOR"):
        cfg.no_color = True
    return cfg
