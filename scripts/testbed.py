"""Start and stop the software testbed servers.

    from testbed import MCP_SERVER, A2A_SERVER, running
    with running(MCP_SERVER, A2A_SERVER, log_dir=...):
        ...run sessions...

Servers are started once per collection run, outside any captured session,
so their start-up traffic never appears in a session's capture.

Safety:
* refuses to start if the port is already in use, so a session can never be
  recorded against some other program listening on the same port;
* binds to loopback addresses only, each server on its own address in the
  testbed network defined in software_testbed/addresses.py;
* each server's output goes to a log file, kept as raw experiment data (the
  taxonomy validates attack outcomes against application logs);
* servers are always stopped, even if the run fails.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTBED = REPO_ROOT / "software_testbed"
if str(TESTBED) not in sys.path:
    sys.path.append(str(TESTBED))
import addresses  # noqa: E402

# One capture filter for every session: all traffic between testbed hosts
# (any port, including attacker services) and nothing from the address where
# Ollama, editors and Docker run.
TESTBED_BPF = addresses.CAPTURE_FILTER

START_TIMEOUT = 60.0
STOP_TIMEOUT = 15.0


class TestbedError(RuntimeError):
    """A testbed server could not be started or stopped."""


@dataclass(frozen=True)
class ServerSpec:
    name: str              # e.g. "mcp-server"
    directory: Path        # working directory (server scripts import siblings)
    script: str            # file to run with the project's Python
    port: int
    ready_url: str | None  # HTTP URL that must answer 200 before the server counts as ready
    host: str              # address the server binds (from addresses.py)
    audit: bool = False    # server writes an audit log (path passed in AGENTNET_AUDIT_LOG)

    @property
    def bpf(self) -> str:
        """Capture filter for sessions with this server (all testbed traffic)."""
        return TESTBED_BPF

    def in_use(self) -> bool:
        """True if something already listens on this server's address and port."""
        return port_in_use(self.port, self.host)


MCP_SERVER = ServerSpec("mcp-server", TESTBED / "mcp", "server.py", addresses.MCP_PORT, None,
                        audit=True, host=addresses.MCP_HOST)
A2A_SERVER = ServerSpec(
    "a2a-server", TESTBED / "a2a", "server.py", addresses.A2A_PORT,
    f"{addresses.A2A_URL}/.well-known/agent-card.json", audit=True, host=addresses.A2A_HOST,
)

# An A2A session also carries the MCP traffic the assistant generates on the
# requester's behalf: both legs are visible on the network, and attacks such
# as confused deputy or exfiltration are only recognisable across them.
A2A_SESSION_BPF = TESTBED_BPF


def port_in_use(port: int, host: str) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


class Server:
    """One running testbed server process."""

    def __init__(self, spec: ServerSpec, log_path: Path) -> None:
        self.spec = spec
        self.log_path = Path(log_path)
        # <run>_<server>.log -> <run>_<server>_audit.jsonl, next to the server log
        self.audit_path = self.log_path.with_name(self.log_path.stem + "_audit.jsonl") if spec.audit else None
        self._proc: subprocess.Popen | None = None
        self._log = None

    def start(self) -> None:
        spec = self.spec
        if self._proc is not None:
            raise TestbedError(f"{spec.name} already started")
        if spec.in_use():
            raise TestbedError(
                f"port {spec.port} is already in use; stop whatever is listening there "
                f"before starting {spec.name}"
            )
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.audit_path and self.audit_path.exists():
            raise TestbedError(f"{self.audit_path} already exists; logs are never overwritten")
        try:
            self._log = open(self.log_path, "x", encoding="utf-8")  # never overwrite a log
        except FileExistsError:
            raise TestbedError(f"{self.log_path} already exists; logs are never overwritten") from None
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
        env.pop("AGENTNET_AUDIT_LOG", None)
        if self.audit_path:
            env["AGENTNET_AUDIT_LOG"] = str(self.audit_path)
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self._proc = subprocess.Popen(
            [sys.executable, spec.script],
            cwd=spec.directory,
            stdin=subprocess.DEVNULL,
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
            creationflags=flags,
        )
        try:
            self._wait_ready()
        except BaseException:
            self.stop()
            raise

    def _wait_ready(self) -> None:
        spec = self.spec
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise TestbedError(f"{spec.name} exited during start-up; see {self.log_path}")
            if spec.in_use():
                if spec.ready_url is None:
                    return
                try:
                    with urllib.request.urlopen(spec.ready_url, timeout=2) as resp:
                        if resp.status == 200:
                            return
                except (urllib.error.URLError, OSError):
                    pass
            time.sleep(0.2)
        raise TestbedError(f"{spec.name} not ready within {START_TIMEOUT:g}s; see {self.log_path}")

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        try:
            if proc and proc.poll() is None:
                proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
                try:
                    proc.wait(timeout=STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        finally:
            if self._log:
                self._log.close()
                self._log = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None


@contextlib.contextmanager
def running(*specs: ServerSpec, log_dir: Path, run_id: str):
    """Start the given servers, yield them, and always stop them afterwards.

    Logs are written to <log_dir>/<run_id>_<server name>.log.
    """
    servers: list[Server] = []
    try:
        for spec in specs:
            server = Server(spec, Path(log_dir) / f"{run_id}_{spec.name}.log")
            server.start()
            servers.append(server)
        yield servers
    finally:
        for server in reversed(servers):
            server.stop()
