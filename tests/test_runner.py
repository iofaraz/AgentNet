"""Tests for scripts/runner.py: one labelled, captured session per run.

Sessions talk to a throw-away local HTTP server and are really captured on
the loopback interface.
"""

import asyncio
import csv
import http.server
import threading
import urllib.request

import pytest

import capture
import manifest
import runner as r

def _loopback_available():
    try:
        capture.find_dumpcap()
        capture.loopback_interface()
        return True
    except capture.CaptureError:
        return False


pytestmark = pytest.mark.skipif(not _loopback_available(), reason="dumpcap/loopback not available")


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def http_port():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def runner(tmp_path):
    return r.SessionRunner(
        manifest_path=tmp_path / "manifest.csv",
        log_path=tmp_path / "capture_log.csv",
        capture_dir=tmp_path / "pcaps",
        run_id="TEST-RUN",
    )


def _get(port):
    urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read()


def scenario(port, *, attack_id="AT-00", protocol="MCP", variant=None, result=None, notes="", **kw):
    async def run():
        await asyncio.to_thread(_get, port)
        return r.Outcome(success=result, notes=notes)

    if variant is None:
        variant = "N/A" if attack_id == "AT-00" else "V1"
    return r.Scenario(name="test-scenario", protocol=protocol, attack_id=attack_id,
                      bpf=f"tcp port {port}", run=run, variant=variant, **{"timeout": 30, **kw})


def log_rows(runner):
    with open(runner.log_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ---- valid sessions -------------------------------------------------------

def test_benign_session_is_recorded(runner, http_port):
    res = runner.run(scenario(http_port, source_device="client@127.0.0.1",
                              destination_device=f"server@127.0.0.1:{http_port}"))
    assert res.valid, res.reason
    assert res.session_id == "MCP-S-B0001"
    assert res.capture_file == "mcp_benign_software_0001.pcapng"

    rows, report = manifest.load(runner.manifest_path)
    assert report.ok, report.errors
    row = rows[0]
    assert (row["label"], row["attack_id"], row["outcome"]) == ("Benign", "AT-00", "N/A")
    assert row["run_id"] == "TEST-RUN"
    assert row["notes"] == "scenario=test-scenario"
    assert row["source_device"] == "client@127.0.0.1"

    log = log_rows(runner)[0]
    assert log["status"] == "valid" and log["reason"] == ""
    assert log["sha256"] == capture.sha256_of(runner.capture_dir / res.capture_file)
    assert int(log["packets_captured"]) > 0 and log["packets_dropped"] == "0"
    assert "mcp=" in log["software_versions"] and "dumpcap=" in log["software_versions"]


def test_session_times_lie_inside_the_capture(runner, http_port):
    res = runner.run(scenario(http_port))
    row = res.manifest_row
    assert res.capture.started_at <= row["start_time"] <= row["end_time"] <= res.capture.stopped_at


def test_numbering_is_per_protocol_environment_and_attack(runner, http_port):
    ids = [runner.run(scenario(http_port)).session_id,
           runner.run(scenario(http_port)).session_id,
           runner.run(scenario(http_port, attack_id="AT-01", result=True)).session_id,
           runner.run(scenario(http_port, protocol="A2A")).session_id]
    assert ids == ["MCP-S-B0001", "MCP-S-B0002", "MCP-S-AT01-0001", "A2A-S-B0001"]
    assert manifest.load(runner.manifest_path)[1].ok


@pytest.mark.parametrize("success, expected", [(True, "Success"), (False, "Failed")])
def test_attack_outcome_comes_from_the_scenario(runner, http_port, success, expected):
    res = runner.run(scenario(http_port, attack_id="AT-01", result=success, variant="V2"))
    assert res.valid, res.reason
    assert res.manifest_row["outcome"] == expected
    assert res.manifest_row["label"] == "Attack"
    assert res.manifest_row["attack_variant"] == "V2"


def test_hardware_environment(tmp_path, http_port):
    hw = r.SessionRunner(manifest_path=tmp_path / "m.csv", log_path=tmp_path / "l.csv",
                         capture_dir=tmp_path / "p", environment="Hardware", run_id="HW")
    res = hw.run(scenario(http_port))
    assert res.valid and res.session_id == "MCP-H-B0001"
    assert res.capture_file == "mcp_benign_hardware_0001.pcapng"


# ---- excluded sessions: kept and explained, never in the manifest -----------

def _assert_excluded(runner, res, fragment):
    assert not res.valid
    assert fragment in res.reason, res.reason
    assert res.manifest_row is None
    rows, _ = manifest.load(runner.manifest_path) if runner.manifest_path.exists() else ([], None)
    assert res.session_id not in [x["session_id"] for x in rows]
    log = [x for x in log_rows(runner) if x["session_id"] == res.session_id]
    assert len(log) == 1 and log[0]["status"] == "excluded" and fragment in log[0]["reason"]
    assert (runner.capture_dir / res.capture_file).is_file(), "excluded captures are kept"


def test_undetermined_attack_outcome_is_excluded(runner, http_port):
    res = runner.run(scenario(http_port, attack_id="AT-01", result=None))
    _assert_excluded(runner, res, "not determined")


def test_benign_reporting_success_is_excluded(runner, http_port):
    res = runner.run(scenario(http_port, result=True))
    _assert_excluded(runner, res, "benign scenario reported")


def test_scenario_error_is_excluded_and_capture_stopped(runner, http_port):
    async def boom():
        await asyncio.to_thread(_get, http_port)
        raise ConnectionError("server went away")
    res = runner.run(r.Scenario(name="boom", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=boom))
    _assert_excluded(runner, res, "ConnectionError: server went away")
    assert not capture._running


def test_runner_timeout_is_excluded(runner, http_port):
    async def hang():
        await asyncio.to_thread(_get, http_port)
        await asyncio.sleep(60)
    res = runner.run(r.Scenario(name="hang", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=hang, timeout=1))
    _assert_excluded(runner, res, "timed out after 1s")


def test_scenario_own_timeout_is_not_called_a_runner_timeout(runner, http_port):
    async def own_timeout():
        await asyncio.to_thread(_get, http_port)
        raise TimeoutError("read timed out")
    res = runner.run(r.Scenario(name="t", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=own_timeout, timeout=30))
    _assert_excluded(runner, res, "scenario error: TimeoutError: read timed out")


def test_empty_capture_is_excluded(runner, http_port):
    async def nothing():
        return r.Outcome()
    res = runner.run(r.Scenario(name="idle", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=nothing))
    _assert_excluded(runner, res, "capture is empty")


def test_long_error_text_is_capped_in_log(runner, http_port):
    async def noisy():
        await asyncio.to_thread(_get, http_port)
        raise RuntimeError("x" * 5000)
    res = runner.run(r.Scenario(name="noisy", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=noisy))
    assert not res.valid
    assert len(log_rows(runner)[0]["reason"]) == r.MAX_REASON


def test_wrong_return_type_is_excluded(runner, http_port):
    async def bad():
        await asyncio.to_thread(_get, http_port)
        return "done"
    res = runner.run(r.Scenario(name="bad", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=bad))
    _assert_excluded(runner, res, "expected Outcome")


def test_interrupt_is_recorded_then_propagates(runner, http_port):
    async def interrupted():
        await asyncio.to_thread(_get, http_port)
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        runner.run(r.Scenario(name="ctrl-c", protocol="MCP", attack_id="AT-00",
                              bpf=f"tcp port {http_port}", run=interrupted))
    log = log_rows(runner)
    assert log[0]["status"] == "excluded" and "interrupted" in log[0]["reason"]
    assert not capture._running


def test_excluded_ids_are_never_reused(runner, http_port):
    first = runner.run(scenario(http_port, attack_id="AT-01", result=None))   # excluded
    second = runner.run(scenario(http_port, attack_id="AT-01", result=True))  # valid
    assert first.session_id == "MCP-S-AT01-0001"
    assert second.session_id == "MCP-S-AT01-0002"


def test_ids_not_reused_after_captures_move_to_backup(runner, http_port):
    # Once captures are moved off this machine (backup), the manifest and the
    # capture log alone must still prevent reuse — for excluded sessions too.
    valid = runner.run(scenario(http_port, attack_id="AT-01", result=True))      # AT01-0001
    excluded = runner.run(scenario(http_port, attack_id="AT-01", result=None))   # AT01-0002, newest
    for res in (valid, excluded):
        p = runner.capture_dir / res.capture_file
        p.chmod(0o666)
        p.unlink()
    # The excluded session is the newest and appears only in the capture log.
    assert runner.run(scenario(http_port, attack_id="AT-01", result=True)).session_id == "MCP-S-AT01-0003"


def test_orphan_capture_file_number_is_skipped(runner, http_port):
    runner.capture_dir.mkdir(parents=True)
    (runner.capture_dir / "mcp_benign_software_0005.pcapng").write_bytes(b"left over")
    assert runner.run(scenario(http_port)).session_id == "MCP-S-B0006"


def test_free_text_is_neutralised(runner, http_port):
    # Manifest notes always begin with "scenario=", so a formula can never lead the cell.
    res = runner.run(scenario(http_port, notes="=cmd|' /C calc'!A0"))
    assert res.valid
    assert res.manifest_row["notes"].startswith("scenario=test-scenario; =cmd")

    async def boom():
        await asyncio.to_thread(_get, http_port)
        raise ValueError("=HYPERLINK(\"http://x\")")
    bad = runner.run(r.Scenario(name="b", protocol="MCP", attack_id="AT-00",
                                bpf=f"tcp port {http_port}", run=boom))
    assert not bad.reason.startswith("=")
    assert not log_rows(runner)[-1]["reason"].startswith("=")


# ---- refused before anything is recorded --------------------------------------

@pytest.mark.parametrize("kw, fragment", [
    (dict(attack_id="AT-06"), "AT-06 is not defined for MCP"),
    (dict(attack_id="AT-09"), "attack_id must be one of"),
    (dict(protocol="HTTP"), "protocol must be one of"),
    (dict(transport="TLS"), "transport must be one of"),
    (dict(variant="V1"), "benign scenarios have variant N/A"),
    (dict(attack_id="AT-01", variant="N/A"), "need a variant"),
    (dict(timeout=0), "timeout must be positive"),
])
def test_invalid_scenarios_rejected_before_capture(runner, http_port, kw, fragment):
    with pytest.raises(ValueError, match=fragment):
        runner.run(scenario(http_port, **kw))
    assert not runner.manifest_path.exists() and not runner.log_path.exists()
    assert not (runner.capture_dir.exists() and any(runner.capture_dir.glob("*.pcapng")))


def test_sync_function_rejected(runner, http_port):
    def not_async():
        return r.Outcome()
    with pytest.raises(ValueError, match="async"):
        runner.run(r.Scenario(name="s", protocol="MCP", attack_id="AT-00",
                              bpf=f"tcp port {http_port}", run=not_async))


def test_bad_capture_filter_raises_and_records_nothing(runner):
    async def run():
        return r.Outcome()
    with pytest.raises(r.RunnerError, match="could not start capture"):
        runner.run(r.Scenario(name="s", protocol="MCP", attack_id="AT-00", bpf="tcp prt 1", run=run))
    assert not runner.manifest_path.exists() and not runner.log_path.exists()


@pytest.mark.parametrize("kw", [dict(environment="Cloud"), dict(run_id="bad id; rm -rf")])
def test_invalid_runner_settings(tmp_path, kw):
    with pytest.raises(ValueError):
        r.SessionRunner(manifest_path=tmp_path / "m.csv", log_path=tmp_path / "l.csv",
                        capture_dir=tmp_path / "p", **kw)


def test_only_one_runner_at_a_time(runner, http_port):
    with r._RunnerLock(runner.capture_dir / ".runner.lock"):
        with pytest.raises(r.RunnerError, match="already active"):
            runner.run(scenario(http_port))
    assert runner.run(scenario(http_port)).valid  # lock released afterwards


def test_damaged_log_stops_before_recording(runner, http_port):
    runner.log_path.write_text("something,else\n", encoding="utf-8")
    with pytest.raises(r.RunnerError, match="unexpected header"):
        runner.run(scenario(http_port))
    assert not runner.manifest_path.exists(), "nothing may be written to the manifest"
    assert not (runner.capture_dir.exists() and any(runner.capture_dir.glob("*.pcapng")))


def test_damaged_manifest_stops_before_recording(runner, http_port):
    runner.manifest_path.write_text("not,a,manifest\n", encoding="utf-8")
    with pytest.raises(r.RunnerError, match="is invalid"):
        runner.run(scenario(http_port))
    assert not runner.log_path.exists()
    assert not (runner.capture_dir.exists() and any(runner.capture_dir.glob("*.pcapng")))
