"""Unit: configuration loading, validation, precedence."""

import pytest

from secretsieve.config import loader as L
from secretsieve.config.template import TEMPLATE


def test_template_parses_and_validates(tmp_path):
    p = tmp_path / "secretsieve.toml"
    p.write_text(TEMPLATE, encoding="utf-8")
    cfg, warnings = L.build_config(L._read_toml_file(p), str(p))
    assert cfg.fail_on == "low" and cfg.severity_floor == "low"
    assert cfg.max_file_bytes == 5242880


def test_unknown_section_rejected():
    with pytest.raises(L.ConfigError):
        L.build_config({"nope": {}}, "<t>")


def test_unknown_key_rejected():
    with pytest.raises(L.ConfigError):
        L.build_config({"scan": {"bogus_key": 1}}, "<t>")


def test_bad_severity_and_confidence_rejected():
    with pytest.raises(L.ConfigError):
        L.build_config({"output": {"severity_floor": "extreme"}}, "<t>")
    with pytest.raises(L.ConfigError):
        L.build_config({"output": {"min_confidence": 101}}, "<t>")


def test_custom_rule_section_rejected_with_guidance():
    with pytest.raises(L.ConfigError, match="not supported"):
        L.build_config({"custom_rule": []}, "<t>")


def test_discover_prefers_local_toml(tmp_path, monkeypatch):
    (tmp_path / "secretsieve.toml").write_text('[output]\nfail_on = "high"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cfg, _ = L.discover_config(None, False, tmp_path)
    assert cfg.fail_on == "high"


def test_discover_reads_pyproject_tool_table(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[tool.secretsieve.output]\nfail_on = "critical"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cfg, _ = L.discover_config(None, False, tmp_path)
    assert cfg.fail_on == "critical"


def test_no_config_ignores_files(tmp_path, monkeypatch):
    (tmp_path / "secretsieve.toml").write_text('[output]\nfail_on = "high"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cfg, _ = L.discover_config(None, True, tmp_path)
    assert cfg.fail_on == "low"


def test_missing_explicit_config_errors(tmp_path):
    with pytest.raises(L.ConfigError):
        L.discover_config(str(tmp_path / "nope.toml"), False, tmp_path)


def test_allowlist_shapes(tmp_path):
    data = {"allow": {"placeholder_values": ["acme-test"], "fingerprint": [{"value": "sha256:abc"}],
                      "path_rule": [{"rule": "SS-GENERIC-002", "path": "tests/**"}]}}
    cfg, _ = L.build_config(data, "<t>")
    assert cfg.placeholder_values == ["acme-test"]
    assert cfg.allow_fingerprints == ["sha256:abc"]
    assert cfg.allow_path_rules == [{"rule": "SS-GENERIC-002", "path": "tests/**"}]


def test_rule_id_format_and_existence():
    assert L.check_rule_id_format("SS-GITHUB-001")
    assert not L.check_rule_id_format("GITHUB-1")
    assert L.validate_rule_ids(["SS-GITHUB-001"]) == []
    assert L.validate_rule_ids(["SS-NOPE-001"]) == ["SS-NOPE-001"]


def test_respect_gitignore_warns():
    _cfg, warnings = L.build_config({"scan": {"respect_gitignore": True}}, "<t>")
    assert warnings and "reserved" in warnings[0]
