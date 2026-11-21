"""Tests for scripts/testbed.py (starting and stopping testbed servers).

Uses small throw-away server scripts so the real testbed ports are untouched.
"""

import socket
import time

import pytest

import testbed as t


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spec_for(tmp_path, body, port=None, ready_url=None, name="fake"):
    port = port or free_port()
    (tmp_path / "srv.py").write_text(body.format(port=port), encoding="utf-8")
    return t.ServerSpec(name, tmp_path, "srv.py", port, ready_url)


HTTP_SERVER = (
    "import http.server\n"
    "print('starting', flush=True)\n"
    "http.server.ThreadingHTTPServer(('127.0.0.1', {port}), http.server.SimpleHTTPRequestHandler).serve_forever()\n"
)


def test_specs_match_the_server_scripts():
    for spec in (t.MCP_SERVER, t.A2A_SERVER):
        source = (spec.directory / spec.script).read_text(encoding="utf-8")
        assert f"port={spec.port}" in source, f"{spec.name}: port differs from {spec.script}"
        assert 'host="127.0.0.1"' in source, f"{spec.name} must bind to 127.0.0.1 only"
    assert t.MCP_SERVER.bpf == "tcp port 8000" and t.A2A_SERVER.bpf == "tcp port 9999"


def test_start_ready_stop(tmp_path):
    spec = spec_for(tmp_path, HTTP_SERVER, ready_url=None)
    server = t.Server(spec, tmp_path / "logs" / "fake.log")
    server.start()
    try:
        assert server.running and t.port_in_use(spec.port)
    finally:
        server.stop()
    assert not server.running
    deadline = time.monotonic() + 5
    while t.port_in_use(spec.port) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not t.port_in_use(spec.port), "port must be released after stop"
    assert "starting" in (tmp_path / "logs" / "fake.log").read_text(encoding="utf-8")


def test_waits_for_ready_url(tmp_path):
    port = free_port()
    spec = spec_for(tmp_path, HTTP_SERVER, port=port, ready_url=f"http://127.0.0.1:{port}/")
    with t.running(spec, log_dir=tmp_path / "logs", run_id="R") as servers:
        assert servers[0].running


def test_refuses_port_already_in_use(tmp_path):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        spec = spec_for(tmp_path, HTTP_SERVER, port=busy.getsockname()[1])
        with pytest.raises(t.TestbedError, match="already in use"):
            t.Server(spec, tmp_path / "x.log").start()
    assert not (tmp_path / "x.log").exists(), "nothing is started or written"


def test_crash_during_startup_is_reported(tmp_path):
    spec = spec_for(tmp_path, "import sys\nprint('boom', flush=True)\nsys.exit(3)\n")
    with pytest.raises(t.TestbedError, match="exited during start-up"):
        t.Server(spec, tmp_path / "crash.log").start()
    assert "boom" in (tmp_path / "crash.log").read_text(encoding="utf-8")


def test_not_ready_in_time_is_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(t, "START_TIMEOUT", 1.0)
    spec = spec_for(tmp_path, "import time\ntime.sleep(60)\n")
    server = t.Server(spec, tmp_path / "slow.log")
    with pytest.raises(t.TestbedError, match="not ready"):
        server.start()
    assert not server.running, "a server that never became ready must be stopped"


def test_logs_are_never_overwritten(tmp_path):
    (tmp_path / "taken.log").write_text("earlier run", encoding="utf-8")
    spec = spec_for(tmp_path, HTTP_SERVER)
    with pytest.raises(t.TestbedError, match="never overwritten"):
        t.Server(spec, tmp_path / "taken.log").start()
    assert (tmp_path / "taken.log").read_text(encoding="utf-8") == "earlier run"
    assert not t.port_in_use(spec.port)


def test_running_stops_servers_even_on_error(tmp_path):
    spec = spec_for(tmp_path, HTTP_SERVER)
    with pytest.raises(RuntimeError, match="session failed"):
        with t.running(spec, log_dir=tmp_path, run_id="R") as servers:
            server = servers[0]
            raise RuntimeError("session failed")
    assert not server.running


def test_running_stops_earlier_servers_if_a_later_one_fails(tmp_path):
    good_dir, bad_dir = tmp_path / "good", tmp_path / "bad"
    good_dir.mkdir()
    bad_dir.mkdir()
    good = spec_for(good_dir, HTTP_SERVER, name="good")
    bad = spec_for(bad_dir, "import sys\nsys.exit(1)\n", name="bad")
    with pytest.raises(t.TestbedError):
        with t.running(good, bad, log_dir=tmp_path / "logs", run_id="R"):
            pass
    deadline = time.monotonic() + 5
    while t.port_in_use(good.port) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not t.port_in_use(good.port), "the first server must be stopped"
