"""End-to-end test: real MCP and A2A servers, real sessions, captures read back.

The real run happens once (about 30 s) and is shared by the tests below.
Skipped when capture tools are missing or the testbed ports are already taken.
"""

import shutil

import pytest

import capture
import e2e_check as e
import manifest
import runner
import testbed


def _available():
    try:
        capture.find_dumpcap()
        capture.loopback_interface()
        e.find_tshark()
    except capture.CaptureError:
        return False
    return not (testbed.port_in_use(testbed.MCP_SERVER.port) or testbed.port_in_use(testbed.A2A_SERVER.port))


pytestmark = pytest.mark.skipif(not _available(), reason="capture tools missing or testbed ports in use")


@pytest.fixture(scope="module")
def e2e(tmp_path_factory):
    out = tmp_path_factory.mktemp("e2e") / "out"
    return e.run_e2e(out, sessions=1)


def _reverify(out_dir, results):
    report = e.E2EReport(out_dir, list(results))
    run = runner.SessionRunner(manifest_path=out_dir / "manifest.csv", log_path=out_dir / "capture_log.csv",
                               capture_dir=out_dir / "pcaps", run_id="REVERIFY")
    e.verify(report, run)
    return report


def test_end_to_end(e2e):
    assert e2e.ok, e2e.problems
    assert [r.session_id for r in e2e.results] == ["MCP-S-B0001", "A2A-S-B0001"]
    assert e2e.observed["MCP-S-B0001"] == e.MCP_EXPECTED_METHODS
    assert e2e.observed["A2A-S-B0001"].count("SendMessage") == 10
    rows, mreport = manifest.load(e2e.out_dir / "manifest.csv")
    assert mreport.ok and len(rows) == 2
    logs = sorted(p.name for p in (e2e.out_dir / "logs").iterdir())
    assert len(logs) == 2 and all(p.endswith(("_mcp-server.log", "_a2a-server.log")) for p in logs)
    assert not testbed.port_in_use(testbed.MCP_SERVER.port), "servers must be stopped afterwards"
    assert not capture._running


def test_reverify_of_untouched_output_passes(e2e):
    assert _reverify(e2e.out_dir, e2e.results).problems == []


def test_verify_detects_unexpected_mcp_methods(e2e, monkeypatch):
    monkeypatch.setattr(e, "MCP_EXPECTED_METHODS", ["server/discover", "tools/list"])
    problems = _reverify(e2e.out_dir, e2e.results).problems
    assert any("MCP-S-B0001" in p and "JSON-RPC methods" in p for p in problems), problems


def test_verify_detects_unexpected_a2a_methods(e2e, monkeypatch):
    monkeypatch.setattr(e, "A2A_EXPECTED_METHODS", {"SendMessage": 9})
    problems = _reverify(e2e.out_dir, e2e.results).problems
    assert any("A2A-S-B0001" in p and "JSON-RPC methods" in p for p in problems), problems


def test_verify_detects_tampering(e2e, tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(e2e.out_dir, copy)
    pcap = copy / "pcaps" / e2e.results[0].capture_file
    pcap.chmod(0o666)
    with open(pcap, "ab") as f:
        f.write(b"\x00")
    problems = _reverify(copy, e2e.results).problems
    assert any("SHA-256" in p for p in problems), problems


def test_verify_reports_missing_capture(e2e, tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(e2e.out_dir, copy)
    pcap = copy / "pcaps" / e2e.results[1].capture_file
    pcap.chmod(0o666)
    pcap.unlink()
    problems = _reverify(copy, e2e.results).problems
    assert any("missing" in p for p in problems), problems


def test_refuses_non_empty_output(tmp_path):
    (tmp_path / "something.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="not empty"):
        e.run_e2e(tmp_path, sessions=1)
