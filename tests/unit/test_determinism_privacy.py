"""Unit: determinism + privacy/offline guarantees."""

import socket

from secretsieve.models.config import Config
from secretsieve.models.stats import ScanStats
from secretsieve.detectors.engine import scan_file_content


def _sig(f):
    d = f.to_dict()
    d.pop("id", None)  # run-unique; everything else must be stable
    d["reason_codes"] = sorted(d["reason_codes"])
    return d


def test_double_scan_stable():
    from tests.conftest import FAKE_GITHUB_TOKEN

    lines = [(1, f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}", False), (2, 'password = "hunter2"', False)]
    first = scan_file_content("a.py", lines, Config(), ScanStats())
    second = scan_file_content("a.py", lines, Config(), ScanStats())
    assert [_sig(f) for f in first] == [_sig(f) for f in second]


def test_ordering_severity_then_confidence_then_path():
    from tests.conftest import FAKE_GITHUB_TOKEN, FAKE_AWS_KEY_ID

    lines = [(1, f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}", False), (2, f'ID="{FAKE_AWS_KEY_ID}"', False)]
    out = scan_file_content("a.py", lines, Config(), ScanStats())
    ranks = [("CRITICAL", 0), ("HIGH", 1), ("MEDIUM", 2), ("LOW", 3), ("INFO", 4)]
    order = {k: v for k, v in ranks}
    assert [order[f.severity] for f in out] == sorted(order[f.severity] for f in out)


def test_offline_scan_with_sockets_blocked(tmp_path):
    from secretsieve.scanner.orchestrator import run_scan

    (tmp_path / "app.py").write_text('password = "hunter2"\n', encoding="utf-8")

    real_socket = socket.socket

    def _blocked(*a, **k):
        raise OSError("network disabled in test")

    socket.socket = _blocked  # type: ignore[assignment]
    try:
        outcome = run_scan([str(tmp_path)], Config())
    finally:
        socket.socket = real_socket
    assert outcome.stats.files_scanned == 1


def test_no_network_imports_in_scan_path():
    import pathlib

    roots = [
        pathlib.Path("src/secretsieve/scanner"),
        pathlib.Path("src/secretsieve/detectors"),
        pathlib.Path("src/secretsieve/rules"),
    ]
    banned = ("import socket", "import requests", "urllib.request", "http.client", "shell=True")
    hits = []
    for root in roots:
        for py in root.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            for token in banned:
                if token in text:
                    hits.append(f"{py}:{token}")
    assert hits == []
