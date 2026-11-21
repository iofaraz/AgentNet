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
    return t.ServerSpec(name, tmp_path, "srv.py", port, ready_url, host="127.0.0.1")


HTTP_SERVER = (
    "import http.server\n"
    "print('starting', flush=True)\n"
    "http.server.ThreadingHTTPServer(('127.0.0.1', {port}), http.server.SimpleHTTPRequestHandler).serve_forever()\n"
)


def test_specs_match_the_address_plan_and_server_scripts():
    import re
    A = t.addresses
    expected = {"mcp-server": ("MCP_HOST", "MCP_PORT"), "a2a-server": ("A2A_HOST", "A2A_PORT")}
    for spec in (t.MCP_SERVER, t.A2A_SERVER):
        host_name, port_name = expected[spec.name]
        assert (spec.host, spec.port) == (getattr(A, host_name), getattr(A, port_name))
        source = (spec.directory / spec.script).read_text(encoding="utf-8")
        # The server binds exactly the planned address, taken from addresses.py.
        assert f"HOST = addresses.{host_name}" in source and f"PORT = addresses.{port_name}" in source
        assert re.search(r"host=HOST\b", source) and re.search(r"port=PORT\b", source)
        literals = re.findall(r"\b127\.\d+\.\d+\.\d+\b", source)
        assert not literals, f"{spec.script} hard-codes addresses {literals}; use addresses.py"
    assert t.MCP_SERVER.bpf == t.A2A_SERVER.bpf == t.A2A_SESSION_BPF == "net 127.77.0.0/16"
    assert t.MCP_SERVER.audit and t.A2A_SERVER.audit
    assert t.A2A_SERVER.ready_url == "http://127.77.2.10:9999/.well-known/agent-card.json"


def test_start_ready_stop(tmp_path):
    spec = spec_for(tmp_path, HTTP_SERVER, ready_url=None)
    server = t.Server(spec, tmp_path / "logs" / "fake.log")
    server.start()
    try:
        assert server.running and spec.in_use()
    finally:
        server.stop()
    assert not server.running
    deadline = time.monotonic() + 5
    while spec.in_use() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not spec.in_use(), "port must be released after stop"
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
    assert not spec.in_use()


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
    while good.in_use() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not good.in_use(), "the first server must be stopped"
