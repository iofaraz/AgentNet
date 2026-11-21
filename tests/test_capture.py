"""Tests for scripts/capture.py.

The integration tests make real captures on the loopback interface, using a
throw-away local HTTP server, and are skipped where dumpcap or a loopback
interface is not available.
"""

import http.server
import os
import stat
import threading
import time
import urllib.request

import pytest

import capture as c

NAME = "mcp_benign_software_001.pcapng"


# ---- argument and path checks (no capture needed) --------------------------

@pytest.mark.parametrize("name", [
    "capture.pcapng",
    "mcp_benign_software_001.pcap",
    "MCP_benign_software_001.pcapng",
])
def test_rejects_non_contract_names(name, tmp_path):
    with pytest.raises(c.CaptureError, match="contract name"):
        c.Capture(name, bpf="tcp port 1", capture_dir=tmp_path)


@pytest.mark.parametrize("name", [
    "../mcp_benign_software_001.pcapng",
    "sub/mcp_benign_software_001.pcapng",
    r"C:\temp\mcp_benign_software_001.pcapng",
])
def test_rejects_paths(name, tmp_path):
    with pytest.raises(c.CaptureError, match="bare file name"):
        c.Capture(name, bpf="tcp port 1", capture_dir=tmp_path)


@pytest.mark.parametrize("bpf", ["", "   "])
def test_requires_capture_filter(bpf, tmp_path):
    with pytest.raises(c.CaptureError, match="filter"):
        c.Capture(NAME, bpf=bpf, capture_dir=tmp_path)


def test_rejects_negative_grace(tmp_path):
    with pytest.raises(c.CaptureError, match="grace"):
        c.Capture(NAME, bpf="tcp port 1", capture_dir=tmp_path, grace=-1)


def test_never_overwrites(tmp_path):
    (tmp_path / NAME).write_bytes(b"existing")
    cap = c.Capture(NAME, bpf="tcp port 1", capture_dir=tmp_path)
    with pytest.raises(c.CaptureError, match="never overwritten"):
        cap.start()
    assert (tmp_path / NAME).read_bytes() == b"existing"


def test_stop_before_start_is_an_error(tmp_path):
    with pytest.raises(c.CaptureError, match="never started"):
        c.Capture(NAME, bpf="tcp port 1", capture_dir=tmp_path).stop()


def test_ok_property():
    base = dict(path=None, started_at="", stopped_at="", sha256="")
    assert c.CaptureResult(packets_captured=10, packets_dropped=0, **base).ok
    assert not c.CaptureResult(packets_captured=0, packets_dropped=0, **base).ok
    assert not c.CaptureResult(packets_captured=10, packets_dropped=1, **base).ok


# ---- real captures ------------------------------------------------------------

def _loopback_available():
    try:
        c.find_dumpcap()
        c.loopback_interface()
        return True
    except c.CaptureError:
        return False


needs_capture = pytest.mark.skipif(not _loopback_available(), reason="dumpcap/loopback not available")


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


def _requests(port, n):
    for _ in range(n):
        urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read()


def _tcp_flags(path):
    from scapy.all import TCP, rdpcap
    return [str(p[TCP].flags) for p in rdpcap(str(path)) if TCP in p]


@needs_capture
def test_records_complete_connections(tmp_path, http_port):
    with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path) as cap:
        _requests(http_port, 3)
    r = cap.result
    assert r.ok, r
    flags = _tcp_flags(r.path)
    assert flags[0] == "S", "first packet must be the opening SYN (nothing lost at start)"
    assert sum(1 for f in flags if f == "S") == 3, "one SYN per connection"
    assert sum(1 for f in flags if "F" in f) == 6, "both FINs of every connection (grace period works)"
    assert r.packets_captured == len(flags)


@needs_capture
def test_result_metadata(tmp_path, http_port):
    with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path) as cap:
        _requests(http_port, 1)
    r = cap.result
    assert r.sha256 == c.sha256_of(r.path)
    assert not os.stat(r.path).st_mode & stat.S_IWRITE, "capture must be read-only"
    assert r.started_at < r.stopped_at
    assert not c.manifest.check_record({
        **{k: "" for k in c.manifest.COLUMNS},
        "session_id": "MCP-S-B0001", "label": "Benign", "attack_id": "AT-00",
        "protocol": "MCP", "transport": "HTTP", "environment": "Software",
        "capture_file": r.path.name, "outcome": "N/A",
        "start_time": r.started_at, "end_time": r.stopped_at,
    }).errors, "capture timestamps and file name must be valid in the manifest"


@needs_capture
def test_filter_excludes_other_traffic(tmp_path, http_port):
    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    threading.Thread(target=other.serve_forever, daemon=True).start()
    try:
        with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path) as cap:
            _requests(other.server_address[1], 2)   # must NOT be recorded
            _requests(http_port, 1)                 # must be recorded
    finally:
        other.shutdown()
        other.server_close()
    from scapy.all import TCP, rdpcap
    ports = {p[TCP].sport for p in rdpcap(str(cap.result.path)) if TCP in p} | \
            {p[TCP].dport for p in rdpcap(str(cap.result.path)) if TCP in p}
    assert http_port in ports
    assert other.server_address[1] not in ports


@needs_capture
def test_empty_capture_is_not_ok(tmp_path, http_port):
    with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path, grace=0) as cap:
        pass
    assert cap.result.packets_captured == 0
    assert not cap.result.ok


@needs_capture
def test_session_error_still_stops_and_keeps_capture(tmp_path, http_port):
    cap = c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path)
    with pytest.raises(ZeroDivisionError):
        with cap:
            _requests(http_port, 1)
            1 / 0
    assert cap._proc.poll() is not None, "dumpcap must not be left running"
    assert cap.result is not None and cap.result.packets_captured > 0
    assert cap not in c._running


@needs_capture
def test_stop_failure_is_reported(tmp_path, http_port, monkeypatch):
    # A capture that cannot be verified must never pass silently.
    monkeypatch.setattr(c, "_CAPTURED_RE", c.re.compile(r"(?!x)x"))  # never matches
    with pytest.raises(c.CaptureError, match="packet/drop counts"):
        with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path, grace=0):
            _requests(http_port, 1)
    assert not any(cap.path.parent == tmp_path for cap in c._running)


@needs_capture
def test_session_error_wins_over_stop_failure(tmp_path, http_port, monkeypatch):
    # When the session itself failed, its error is the one worth seeing.
    monkeypatch.setattr(c, "_CAPTURED_RE", c.re.compile(r"(?!x)x"))
    with pytest.raises(ZeroDivisionError):
        with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path, grace=0):
            1 / 0


@needs_capture
@pytest.mark.parametrize("bpf", ["tcp port notaport", "tcp prt 80", "tcp port 99999"])
def test_invalid_filter_fails_fast(tmp_path, bpf):
    # dumpcap prints "Capturing on" before rejecting the filter; start() must
    # not mistake that for a running capture.
    cap = c.Capture(NAME, bpf=bpf, capture_dir=tmp_path)
    t = time.monotonic()
    with pytest.raises(c.CaptureError, match="Invalid capture filter"):
        cap.start()
    assert time.monotonic() - t < 10
    assert cap not in c._running


@needs_capture
def test_cannot_start_twice(tmp_path, http_port):
    with c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path, grace=0) as cap:
        with pytest.raises(c.CaptureError, match="already started"):
            cap.start()


@needs_capture
def test_stop_is_idempotent(tmp_path, http_port):
    cap = c.Capture(NAME, bpf=f"tcp port {http_port}", capture_dir=tmp_path, grace=0)
    cap.start()
    first = cap.stop()
    assert cap.stop() is first


@needs_capture
def test_cli_interfaces_marks_loopback(capsys):
    assert c.main(["interfaces"]) == 0
    assert "<- loopback" in capsys.readouterr().out


@needs_capture
def test_cli_record(tmp_path, http_port, capsys):
    t = threading.Timer(0.8, _requests, args=(http_port, 1))
    t.start()
    rc = c.main(["record", NAME, "--filter", f"tcp port {http_port}", "--seconds", "2", "--dir", str(tmp_path)])
    t.join()
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "dropped: 0" in out and (tmp_path / NAME).is_file()


@needs_capture
def test_cli_record_empty_capture_fails(tmp_path, http_port, capsys):
    rc = c.main(["record", NAME, "--filter", f"tcp port {http_port}", "--seconds", "0", "--dir", str(tmp_path)])
    assert rc == 1
    assert "empty" in capsys.readouterr().err


def test_cli_rejects_negative_seconds(tmp_path):
    with pytest.raises(SystemExit):
        c.main(["record", NAME, "--filter", "tcp port 1", "--seconds", "-1", "--dir", str(tmp_path)])


def test_cli_rejects_bad_name(tmp_path, capsys):
    assert c.main(["record", "x.pcapng", "--filter", "tcp port 1", "--seconds", "0", "--dir", str(tmp_path)]) == 1
    assert "contract name" in capsys.readouterr().err
