"""Unit: JSON schema-v1 file conformance (offline, stdlib only)."""

import json
import pathlib
import re

from secretsieve.reporting.json_report import FINDING_KEYS, TOP_LEVEL_KEYS

SCHEMA_PATH = pathlib.Path("schemas/report-v1.json")


def _load_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_file_exists_and_declares_v1():
    schema = _load_schema()
    assert schema["title"].startswith("SecretSieve")
    assert schema["properties"]["schema_version"] == {"const": 1}


def test_code_and_schema_agree_on_fields():
    schema = _load_schema()
    assert set(schema["required"]) == set(TOP_LEVEL_KEYS)
    required_top = set(schema["required"])
    assert {"tool", "version", "schema_version", "findings", "exit_code"} <= required_top
    finding_required = set(schema["properties"]["findings"]["items"]["required"])
    assert finding_required <= FINDING_KEYS
    assert {"rule_id", "severity", "confidence", "redacted", "value_hash", "fingerprint"} <= finding_required


def test_report_validates_against_schema_shapes(tmp_path, monkeypatch):
    from secretsieve.cli import app as appmod
    from tests.conftest import FAKE_GITHUB_TOKEN

    (tmp_path / "a.py").write_text("t = '%s'\n" % FAKE_GITHUB_TOKEN, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert appmod.main([".", "--json", "--no-config"]) == 1


def test_fingerprint_and_rule_id_shapes():
    assert re.match(r"^sha256:[0-9a-f]{32}$", "sha256:" + "ab12" * 8)
    assert re.match(r"^SS-[A-Z0-9-]+-[0-9]{3}$", "SS-PRIVATE-KEY-001")
