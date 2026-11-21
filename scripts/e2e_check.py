"""End-to-end check of the software pipeline (contract section 13).

Starts the real MCP and A2A servers, runs real benign sessions through the
session runner, then reads every capture back and verifies it:

* the manifest validates and every valid session has a capture log row;
* each capture's SHA-256 still matches the capture log;
* tshark's packet count equals the count dumpcap reported;
* the capture holds exactly the protocol messages the scenario sent.

Output goes to its own folder (not the dataset): these sessions use the
Phase 2-3 demonstration agents, which Part 2 replaces.

    python scripts/e2e_check.py --sessions 2
    python scripts/e2e_check.py --sessions 2 --out C:\\path\\to\\folder
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import capture
import manifest
import runner
import testbed

MCP_EXPECTED_TOOLS = ["calculate_sum", "get_system_info", "get_weather"]
MCP_EXPECTED_METHODS = ["server/discover", "tools/list", "tools/call", "tools/call", "tools/call"]
A2A_AGENT_CARD_PATH = "/.well-known/agent-card.json"
A2A_EXPECTED_METHODS = {"SendMessage": 10}


class ScenarioCheckError(RuntimeError):
    """The server answered, but not with what a normal session expects."""


# --------------------------------------------------------------------------
# Scenarios built on the existing clients
# --------------------------------------------------------------------------

def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mcp_basic_tools() -> runner.Scenario:
    client = _load(testbed.TESTBED / "mcp" / "client.py", "agentnet_mcp_client")

    async def run() -> runner.Outcome:
        r = await client.exercise_tools()
        tools = sorted(name for name, _ in r["tools"])
        if tools != MCP_EXPECTED_TOOLS:
            raise ScenarioCheckError(f"unexpected tool list {tools}")
        if r["calculate_sum"] != {"result": 30.0}:
            raise ScenarioCheckError(f"calculate_sum(10, 20) returned {r['calculate_sum']}")
        if "Islamabad" not in r["get_weather"]:
            raise ScenarioCheckError("get_weather answer does not mention the requested city")
        if "Operating System:" not in r["get_system_info"]:
            raise ScenarioCheckError("get_system_info answer is malformed")
        return runner.Outcome(notes="3 tools listed; 3 tool calls answered correctly")

    spec = testbed.MCP_SERVER
    return runner.Scenario(
        name="mcp-basic-tools", protocol="MCP", attack_id=manifest.BENIGN_ID,
        bpf=spec.bpf, run=run, timeout=60,
        source_device="mcp-client@127.0.0.1",
        destination_device=f"{spec.name}@127.0.0.1:{spec.port}",
    )


def a2a_echo() -> runner.Scenario:
    client = _load(testbed.TESTBED / "a2a" / "client.py", "agentnet_a2a_client")

    async def run() -> runner.Outcome:
        replies = await client.send_messages()
        expected = [f"Echo Agent received: {m}" for m in client.MESSAGES]
        if replies != expected:
            bad = sum(a != b for a, b in zip(replies, expected)) + abs(len(replies) - len(expected))
            raise ScenarioCheckError(f"{bad} of {len(expected)} replies missing or wrong")
        return runner.Outcome(notes=f"{len(expected)} messages echoed correctly")

    spec = testbed.A2A_SERVER
    return runner.Scenario(
        name="a2a-echo-10", protocol="A2A", attack_id=manifest.BENIGN_ID,
        bpf=spec.bpf, run=run, timeout=60,
        source_device="a2a-client@127.0.0.1",
        destination_device=f"{spec.name}@127.0.0.1:{spec.port}",
    )


# --------------------------------------------------------------------------
# Reading captures back
# --------------------------------------------------------------------------

def find_tshark() -> Path:
    found = shutil.which("tshark")
    if found:
        return Path(found)
    candidate = capture.find_dumpcap().with_name("tshark.exe" if sys.platform == "win32" else "tshark")
    if candidate.is_file():
        return candidate
    raise capture.CaptureError("tshark not found")


def http_requests(pcap: Path, port: int) -> list[tuple[str, str, dict | None]]:
    """(HTTP method, URI, JSON body or None) for every HTTP request in a capture.

    tshark returns HTTP bodies (http.file_data) as hex, so they are decoded here.
    """
    out = subprocess.run(
        [str(find_tshark()), "-r", str(pcap), "-d", f"tcp.port=={port},http", "-Y", "http.request",
         "-T", "fields", "-E", "separator=\t",
         "-e", "http.request.method", "-e", "http.request.uri", "-e", "http.file_data"],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        raise capture.CaptureError(f"tshark failed on {pcap.name}: {out.stderr.strip()}")
    requests = []
    for line in out.stdout.splitlines():
        method, uri, data = (line.split("\t") + ["", "", ""])[:3]
        body = None
        if data:
            try:
                body = json.loads(bytes.fromhex(data.replace(":", "")).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                body = None
        requests.append((method, uri, body))
    return requests


def frame_count(pcap: Path) -> int:
    out = subprocess.run([str(find_tshark()), "-r", str(pcap), "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise capture.CaptureError(f"tshark failed on {pcap.name}: {out.stderr.strip()}")
    return len(out.stdout.split())


def jsonrpc_methods(requests) -> list[str]:
    return [body["method"] for _, _, body in requests if isinstance(body, dict) and "method" in body]


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------

@dataclass
class E2EReport:
    out_dir: Path
    results: list[runner.SessionResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    observed: dict[str, list[str]] = field(default_factory=dict)  # session_id -> methods seen

    @property
    def ok(self) -> bool:
        return not self.problems and bool(self.results) and all(r.valid for r in self.results)


def verify(report: E2EReport, run: runner.SessionRunner) -> None:
    """Read every capture back and compare it with the records."""
    problem = report.problems.append
    rows, mreport = manifest.load(run.manifest_path)
    problem_list = [f"manifest: {e}" for e in mreport.errors]
    report.problems.extend(problem_list)
    with open(run.log_path, newline="", encoding="utf-8") as f:
        log = {row["session_id"]: row for row in csv.DictReader(f)}

    by_id = {row["session_id"]: row for row in rows}
    for res in report.results:
        sid = res.session_id
        if not res.valid:
            problem(f"{sid}: excluded ({res.reason})")
            continue
        if sid not in by_id:
            problem(f"{sid}: valid but missing from the manifest")
        entry = log.get(sid)
        if entry is None:
            problem(f"{sid}: missing from the capture log")
            continue
        pcap = run.capture_dir / res.capture_file
        if not pcap.is_file():
            problem(f"{sid}: capture file {pcap.name} is missing")
            continue
        if capture.sha256_of(pcap) != entry["sha256"]:
            problem(f"{sid}: SHA-256 of {pcap.name} does not match the capture log")
        try:
            _check_contents(report, sid, pcap, entry, by_id.get(sid, {}).get("protocol", ""))
        except capture.CaptureError as err:  # unreadable capture: report it, keep checking others
            problem(f"{sid}: {err}")


def _check_contents(report: E2EReport, sid: str, pcap: Path, entry: dict, protocol: str) -> None:
    problem = report.problems.append
    frames = frame_count(pcap)
    if str(frames) != entry["packets_captured"]:
        problem(f"{sid}: tshark sees {frames} packets, capture log says {entry['packets_captured']}")

    if protocol == "MCP":
        requests = http_requests(pcap, testbed.MCP_SERVER.port)
        methods = jsonrpc_methods(requests)
        report.observed[sid] = methods
        if methods != MCP_EXPECTED_METHODS:
            problem(f"{sid}: JSON-RPC methods {methods}, expected {MCP_EXPECTED_METHODS}")
    elif protocol == "A2A":
        requests = http_requests(pcap, testbed.A2A_SERVER.port)
        methods = jsonrpc_methods(requests)
        card = [uri for m, uri, _ in requests if m == "GET" and uri == A2A_AGENT_CARD_PATH]
        report.observed[sid] = ([f"GET {A2A_AGENT_CARD_PATH}"] * len(card)) + methods
        if len(card) != 1:
            problem(f"{sid}: expected 1 Agent Card request, saw {len(card)}")
        counts = Counter(methods)
        if counts != Counter(A2A_EXPECTED_METHODS):
            problem(f"{sid}: JSON-RPC methods {dict(counts)}, expected {A2A_EXPECTED_METHODS}")
    else:
        problem(f"{sid}: unknown protocol {protocol!r}")


def run_e2e(out_dir: Path, sessions: int = 2) -> E2EReport:
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"{out_dir} is not empty; give an empty or new folder")
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = "E2E-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    run = runner.SessionRunner(
        manifest_path=out_dir / "manifest.csv",
        log_path=out_dir / "capture_log.csv",
        capture_dir=out_dir / "pcaps",
        run_id=run_id,
    )
    report = E2EReport(out_dir)
    scenarios = [mcp_basic_tools(), a2a_echo()]
    with testbed.running(testbed.MCP_SERVER, testbed.A2A_SERVER, log_dir=out_dir / "logs", run_id=run_id):
        for _ in range(sessions):
            for scenario in scenarios:
                report.results.append(run.run(scenario))
    verify(report, run)
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AgentNet end-to-end check")
    parser.add_argument("--sessions", type=int, default=2, help="sessions per scenario (default 2)")
    parser.add_argument("--out", type=Path, help="empty output folder (default: a new temporary folder)")
    args = parser.parse_args(argv)
    if args.sessions < 1:
        parser.error("--sessions must be at least 1")
    out = args.out or Path(tempfile.mkdtemp(prefix="agentnet-e2e-"))

    try:
        report = run_e2e(out, args.sessions)
    except (ValueError, testbed.TestbedError, runner.RunnerError, capture.CaptureError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for res in report.results:
        packets = res.capture.packets_captured if res.capture else "-"
        print(f"{res.session_id:16} {res.status:8} {packets!s:>4} packets  {res.capture_file}")
        if res.session_id in report.observed:
            print(f"{'':16} seen: {', '.join(report.observed[res.session_id])}")
    print(f"\noutput: {report.out_dir}")
    if report.ok:
        print("END-TO-END CHECK PASSED")
        return 0
    for p in report.problems:
        print(f"PROBLEM: {p}")
    print("END-TO-END CHECK FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
