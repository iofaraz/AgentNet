"""Automated packet capture for AgentNet sessions.

Wraps Wireshark's ``dumpcap`` so a session can be recorded from code:

    from capture import Capture
    with Capture("mcp_benign_software_001.pcapng", bpf="tcp port 8000") as cap:
        run_the_session()
    print(cap.result)

Guarantees, so thousands of captures can be trusted without checking each
one by hand:

* recording has really started before the session runs (waits until dumpcap
  has accepted the filter and opened the file), so the first packets are not
  lost and a bad filter can never produce a session with no recording;
* a short grace period before stopping catches connection teardown packets;
* dumpcap is stopped gracefully, so the file is complete, and it is always
  stopped, even if the session raises an error;
* the packet and drop counts reported by dumpcap are returned, so a capture
  that missed packets is detected;
* file names follow the contract (section 5), files are never overwritten,
  and finished captures are made read-only with a SHA-256 hash recorded
  (contract section 5: keep original PCAP files unchanged).

Command line:
    python scripts/capture.py interfaces
    python scripts/capture.py record <file.pcapng> --filter "tcp port 8000" --seconds 10
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = REPO_ROOT / "traffic" / "pcaps"

DEFAULT_READY_TIMEOUT = 15.0  # seconds to wait for dumpcap to start capturing
DEFAULT_GRACE = 1.0           # seconds to keep recording after the session ends
STOP_TIMEOUT = 15.0           # seconds to wait for dumpcap to exit after the stop signal

_WINDOWS_DUMPCAP = Path(r"C:\Program Files\Wireshark\dumpcap.exe")
# dumpcap prints "Capturing on ..." BEFORE it checks the capture filter, so that
# line does not prove recording has started (with a bad filter it is followed
# by an error and exit). "File: ..." is printed only after the filter has been
# accepted and the output file is open.
_READY_LINE = "File: "
_CAPTURED_RE = re.compile(r"Packets captured:\s*(\d+)")
_RECEIVED_DROPPED_RE = re.compile(r"Packets received/dropped on interface .*?:\s*(\d+)/(\d+)")


class CaptureError(RuntimeError):
    """The capture could not be started, stopped or verified."""


@dataclass(frozen=True)
class CaptureResult:
    """What a finished capture produced."""

    path: Path
    started_at: str        # manifest timestamp when recording was confirmed running
    stopped_at: str        # manifest timestamp when dumpcap finished
    packets_captured: int
    packets_dropped: int
    sha256: str

    @property
    def ok(self) -> bool:
        """True when the capture holds packets and none were dropped."""
        return self.packets_captured > 0 and self.packets_dropped == 0


# --------------------------------------------------------------------------
# Finding dumpcap and interfaces
# --------------------------------------------------------------------------

def find_dumpcap() -> Path:
    """Locate dumpcap on PATH or in Wireshark's default Windows folder."""
    found = shutil.which("dumpcap")
    if found:
        return Path(found)
    if _WINDOWS_DUMPCAP.is_file():
        return _WINDOWS_DUMPCAP
    raise CaptureError("dumpcap not found; install Wireshark and add it to PATH")


def list_interfaces() -> list[tuple[str, str]]:
    """Return (interface name, description) pairs that dumpcap can capture on."""
    proc = subprocess.run(
        [str(find_dumpcap()), "-D"], capture_output=True, text=True, timeout=30
    )
    if proc.returncode != 0:
        raise CaptureError(f"dumpcap -D failed: {proc.stderr.strip()}")
    interfaces = []
    for line in proc.stdout.splitlines():
        m = re.match(r"^\d+\.\s+(\S+)(?:\s+\((.*)\))?\s*$", line.strip())
        if m:
            interfaces.append((m[1], m[2] or ""))
    return interfaces


def loopback_interface() -> str:
    """Name of the loopback interface (where the software testbed talks)."""
    for name, description in list_interfaces():
        if name == "lo" or "loopback" in name.lower() or "loopback" in description.lower():
            return name
    raise CaptureError(
        "no loopback interface found; on Windows install Npcap with "
        "'Support loopback traffic' enabled"
    )


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------

_running: set["Capture"] = set()


@atexit.register
def _stop_orphans() -> None:
    """Never leave dumpcap running if the program exits unexpectedly."""
    for cap in list(_running):
        if cap._proc and cap._proc.poll() is None:
            cap._proc.kill()


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class Capture:
    """Record packets matching ``bpf`` on ``interface`` into one pcapng file.

    Args:
        filename: contract file name, e.g. ``mcp_benign_software_001.pcapng``.
        bpf: capture filter (required), e.g. ``"tcp port 8000 or tcp port 9999"``.
            Required so unrelated traffic on the same interface (Ollama,
            editors, Docker) never ends up in the dataset.
        interface: dumpcap interface name; defaults to the loopback interface.
        capture_dir: folder for captures; defaults to ``traffic/pcaps``.
        grace: seconds to keep recording after the session ends.
    """

    def __init__(
        self,
        filename: str,
        *,
        bpf: str,
        interface: str | None = None,
        capture_dir: str | Path = CAPTURE_DIR,
        grace: float = DEFAULT_GRACE,
        ready_timeout: float = DEFAULT_READY_TIMEOUT,
    ) -> None:
        if Path(filename).name != filename:
            raise CaptureError(f"give a bare file name, not a path: {filename!r}")
        if not manifest.CAPTURE_FILE_PATTERN.match(filename):
            raise CaptureError(
                f"{filename!r} does not follow the contract name "
                "<protocol>_<attack-id>_<environment>_<run>.pcapng"
            )
        if not bpf or not bpf.strip():
            raise CaptureError("a capture filter (bpf) is required")
        if grace < 0:
            raise CaptureError("grace must not be negative")

        self.path = Path(capture_dir) / filename
        self.bpf = bpf.strip()
        self.interface = interface
        self.grace = grace
        self.ready_timeout = ready_timeout
        self.result: CaptureResult | None = None

        self._proc: subprocess.Popen[str] | None = None
        self._stderr: list[str] = []
        self._ready = threading.Event()
        self._reader: threading.Thread | None = None
        self._started_at = ""

    # ---- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Start dumpcap and block until it is really capturing."""
        if self._proc is not None:
            raise CaptureError("capture already started")
        if self.path.exists():
            raise CaptureError(f"{self.path} already exists; captures are never overwritten")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        interface = self.interface or loopback_interface()

        cmd = [str(find_dumpcap()), "-i", interface, "-f", self.bpf, "-w", str(self.path)]
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        # Arguments are passed as a list, never through a shell, so a filter or
        # interface string cannot inject commands.
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
        )
        _running.add(self)
        # dumpcap keeps writing progress to stderr; read it continuously so the
        # pipe never fills up and blocks the capture.
        self._reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()

        deadline = time.monotonic() + self.ready_timeout
        while not self._ready.wait(0.02):
            if self._proc.poll() is not None:
                self._reader.join(timeout=2)
                _running.discard(self)
                raise CaptureError(f"dumpcap exited before capturing: {self._stderr_text()}")
            if time.monotonic() > deadline:
                self._kill()
                raise CaptureError(f"dumpcap did not start within {self.ready_timeout}s: {self._stderr_text()}")
        self._started_at = manifest.now()

    def stop(self) -> CaptureResult:
        """Stop gracefully, verify the file, make it read-only, and return the result."""
        if self._proc is None:
            raise CaptureError("capture was never started")
        if self.result is not None:
            return self.result

        time.sleep(self.grace)
        if self._proc.poll() is None:
            if os.name == "nt":
                self._proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._kill()
                raise CaptureError(
                    f"dumpcap did not stop within {STOP_TIMEOUT}s and was killed; "
                    f"{self.path.name} may be incomplete"
                ) from None
        if self._reader:
            self._reader.join(timeout=5)
        _running.discard(self)
        stopped_at = manifest.now()

        text = self._stderr_text()
        if self._proc.returncode != 0:
            raise CaptureError(f"dumpcap exited with code {self._proc.returncode}: {text}")
        if not self.path.is_file():
            raise CaptureError(f"dumpcap reported success but {self.path} is missing")
        captured = _CAPTURED_RE.search(text)
        received = _RECEIVED_DROPPED_RE.search(text)
        if not captured or not received:
            raise CaptureError(f"could not read packet/drop counts from dumpcap: {text}")

        os.chmod(self.path, stat.S_IREAD)  # originals must stay unchanged
        self.result = CaptureResult(
            path=self.path,
            started_at=self._started_at,
            stopped_at=stopped_at,
            packets_captured=int(captured[1]),
            packets_dropped=int(received[2]),
            sha256=sha256_of(self.path),
        )
        return self.result

    def __enter__(self) -> "Capture":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Always stop dumpcap. If the session itself failed, keep the capture
        # (failed experiments are recorded, never silently dropped) and let the
        # session's error propagate rather than a secondary capture error.
        try:
            self.stop()
        except CaptureError:
            if exc_type is None:
                raise

    # ---- internals -----------------------------------------------------------

    def _read_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for line in self._proc.stderr:
            line = line.rstrip()
            self._stderr.append(line)
            if line.startswith(_READY_LINE):
                self._ready.set()

    def _stderr_text(self) -> str:
        return " | ".join(l for l in self._stderr if l and not l.startswith("Packets: "))

    def _kill(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.kill()
            self._proc.wait(timeout=5)
        _running.discard(self)


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _non_negative(text: str) -> float:
    value = float(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return value


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AgentNet packet capture")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("interfaces", help="list capture interfaces")
    rec = sub.add_parser("record", help="record for a fixed time (manual testing)")
    rec.add_argument("filename", help="contract name, e.g. mcp_benign_software_001.pcapng")
    rec.add_argument("--filter", required=True, help='capture filter, e.g. "tcp port 8000"')
    rec.add_argument("--seconds", type=_non_negative, required=True)
    rec.add_argument("--interface", help="defaults to the loopback interface")
    rec.add_argument("--dir", type=Path, default=CAPTURE_DIR, help="output folder (default: traffic/pcaps)")
    args = parser.parse_args(argv)

    try:
        if args.command == "interfaces":
            loop = loopback_interface()
            for name, desc in list_interfaces():
                mark = "  <- loopback (software testbed)" if name == loop else ""
                print(f"{name}  ({desc}){mark}")
            return 0

        with Capture(args.filename, bpf=args.filter, interface=args.interface, capture_dir=args.dir) as cap:
            print(f"recording {cap.path} for {args.seconds}s ...")
            time.sleep(args.seconds)
        r = cap.result
        print(f"packets: {r.packets_captured}, dropped: {r.packets_dropped}, sha256: {r.sha256}")
        if not r.ok:
            print("WARNING: capture is empty or dropped packets", file=sys.stderr)
            return 1
        return 0
    except CaptureError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
