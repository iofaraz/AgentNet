"""End-to-end test: real MCP and A2A servers, real sessions, captures read back.

The real run happens once (about 1 minute; the A2A Lab Assistant uses the
local model) and is shared by the tests below. Skipped when capture tools or
the Ollama model are missing, or the testbed ports are already taken.
"""

import asyncio
import shutil
import sys

import pytest

import capture
import e2e_check as e
import manifest
import runner
import testbed

sys.path.insert(0, str(testbed.TESTBED / "llm"))
sys.path.insert(0, str(testbed.TESTBED / "mcp"))
import agent  # noqa: E402
import audit  # noqa: E402


def _available():
    try:
        capture.find_dumpcap()
        capture.loopback_interface()
        e.find_tshark()
        asyncio.run(agent.model_digest(agent.DEFAULT_MODEL))
    except Exception:
        return False
    return not (testbed.port_in_use(testbed.MCP_SERVER.port) or testbed.port_in_use(testbed.A2A_SERVER.port))


pytestmark = pytest.mark.skipif(not _available(),
                                reason="capture tools or Ollama model missing, or testbed ports in use")


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
    a2a_seen = e2e.observed["A2A-S-B0001"]
    assert a2a_seen.count("SendMessage") == len(e.A2A_REQUESTS)
    assert a2a_seen.count("MCP server/discover") == len(e.A2A_REQUESTS), "one MCP connection per request"
    assert "MCP tools/call" in a2a_seen, "the A2A capture includes the assistant's MCP leg"
    rows, mreport = manifest.load(e2e.out_dir / "manifest.csv")
    assert mreport.ok and len(rows) == 2
    logs = sorted(p.name for p in (e2e.out_dir / "logs").iterdir())
    assert len(logs) == 4, logs
    for suffix in ("_mcp-server.log", "_a2a-server.log", "_mcp-server_audit.jsonl", "_a2a-server_audit.jsonl"):
        assert sum(p.endswith(suffix) for p in logs) == 1, suffix


def test_a2a_session_audits_link_requester_to_mcp_calls(e2e):
    # A2A audit: who asked. MCP audit: what the assistant then did, as ops-agent.
    from datetime import datetime
    rows = {r["session_id"]: r for r in manifest.load(e2e.out_dir / "manifest.csv")[0]}
    a2a = rows["A2A-S-B0001"]
    start, end = datetime.fromisoformat(a2a["start_time"]), datetime.fromisoformat(a2a["end_time"])
    logs = e2e.out_dir / "logs"
    tasks = audit.between(audit.read(next(logs.glob("*_a2a-server_audit.jsonl"))), start, end)
    assert [(t["tool"], t["principal"], t["decision"]) for t in tasks] == \
        [("a2a_task", "alice", "allowed")] * len(e.A2A_REQUESTS)
    mcp_calls = audit.between(audit.read(next(logs.glob("*_mcp-server_audit.jsonl"))), start, end)
    assert mcp_calls and {c["principal"] for c in mcp_calls} == {"ops-agent"}


def test_audit_entries_match_the_session_window(e2e):
    # Attack scenarios will decide success from the audit log, selecting a
    # session's entries by its manifest time window (no IDs on the wire).
    import sys
    from datetime import datetime
    sys.path.insert(0, str(testbed.TESTBED / "mcp"))
    import audit
    rows = {r["session_id"]: r for r in manifest.load(e2e.out_dir / "manifest.csv")[0]}
    mcp = rows["MCP-S-B0001"]
    log = next((e2e.out_dir / "logs").glob("*_mcp-server_audit.jsonl"))
    entries = audit.read(log)
    window = audit.between(entries, datetime.fromisoformat(mcp["start_time"]), datetime.fromisoformat(mcp["end_time"]))
    assert [e["tool"] for e in window] == ["calculate", "get_weather", "list_files", "read_file", "read_sensor"]
    assert {(e["principal"], e["role"], e["decision"]) for e in window} == {("alice", "viewer", "allowed")}
    outside = [x for x in entries if x not in window]
    assert {x["principal"] for x in outside} == {"ops-agent"}, \
        "every other MCP call belongs to the A2A session's assistant"
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
