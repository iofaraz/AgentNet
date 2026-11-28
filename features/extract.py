"""Session features from the captures (first version, for the Milestone 2 baseline).

One row per valid session in the manifest, with two feature groups:

* network features - only what is visible even if the traffic were encrypted:
  packet counts and sizes, byte volumes per direction, timing, connections.
  These are what the baseline IDS uses.
* protocol features - read from the plaintext MCP / A2A messages: method
  counts, distinct tools, errors, actuation calls, secret-folder access,
  tool-description lengths. These preview the proposed protocol-aware IDS.

Never used as features (contract §11b.4, D15): IP addresses, ports, tokens,
user names, session IDs, outcome, environment.

    python features/extract.py            # writes dataset/processed/session_features.csv
"""

from __future__ import annotations

import csv
import re
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import capture  # noqa: E402
import runner  # noqa: E402

OUT = REPO / "dataset" / "processed" / "session_features.csv"
SERVER_PORTS = {8000, 9999}          # MCP server, A2A Lab Assistant (requests go *to* these)

NETWORK = ["packets", "bytes_total", "duration_s", "pkt_size_mean", "pkt_size_std", "pkt_size_max",
           "bytes_up", "bytes_down", "down_up_ratio", "pkts_up", "pkts_down", "connections",
           "iat_mean", "iat_std", "iat_max", "payload_pkts"]
PROTOCOL = ["n_requests", "n_tools_list", "n_tools_call", "n_handshake", "n_distinct_tools",
            "n_tool_errors", "n_actuation_calls", "n_secret_refs", "n_read_file",
            "desc_len_max", "desc_len_mean", "n_a2a_messages"]
META = ["session_id", "run_id", "label", "attack_id", "attack_variant", "outcome", "protocol", "kind"]

_METHOD = re.compile(rb'"method":"([^"]+)"')
_NAME = re.compile(rb'"name":"([a-z_]+)"')
_DESC = re.compile(rb'"description":"((?:[^"\\]|\\.)*)"')
_POST = re.compile(rb"POST /")


def _tool_calls(up: bytes) -> list[str]:
    """Names of the tools called (the 'name' that follows each tools/call)."""
    out = []
    for m in re.finditer(rb'"method":"tools/call"', up):
        n = _NAME.search(up, m.end(), m.end() + 400)
        if n:
            out.append(n.group(1).decode())
    return out


def _std(xs):
    return statistics.pstdev(xs) if len(xs) > 1 else 0.0


def session_features(pcap: Path) -> dict:
    from scapy.all import IP, TCP, Raw, PcapNgReader
    times, sizes, up, down = [], [], b"", b""
    bytes_up = bytes_down = pkts_up = pkts_down = syns = payload_pkts = 0
    with PcapNgReader(str(pcap)) as reader:
        for p in reader:
            if IP not in p or TCP not in p:
                continue
            n = len(p)
            times.append(float(p.time))
            sizes.append(n)
            t = p[TCP]
            is_up = t.dport in SERVER_PORTS
            if is_up:
                bytes_up += n
                pkts_up += 1
            else:
                bytes_down += n
                pkts_down += 1
            if t.flags & 0x02 and not t.flags & 0x10:      # SYN without ACK = new connection
                syns += 1
            if Raw in p:
                payload_pkts += 1
                if is_up:
                    up += bytes(p[Raw].load)
                else:
                    down += bytes(p[Raw].load)
    iats = [b - a for a, b in zip(times, times[1:])]
    f = {
        "packets": len(sizes), "bytes_total": sum(sizes),
        "duration_s": (times[-1] - times[0]) if times else 0.0,
        "pkt_size_mean": statistics.fmean(sizes) if sizes else 0.0, "pkt_size_std": _std(sizes),
        "pkt_size_max": max(sizes, default=0), "bytes_up": bytes_up, "bytes_down": bytes_down,
        "down_up_ratio": bytes_down / bytes_up if bytes_up else 0.0, "pkts_up": pkts_up, "pkts_down": pkts_down,
        "connections": syns, "iat_mean": statistics.fmean(iats) if iats else 0.0, "iat_std": _std(iats),
        "iat_max": max(iats, default=0.0), "payload_pkts": payload_pkts,
    }
    methods = [m.decode(errors="replace") for m in _METHOD.findall(up)]
    calls = _tool_calls(up)
    descs = [len(d) for d in _DESC.findall(down)]
    f.update({
        "n_requests": len(_POST.findall(up)),
        "n_tools_list": methods.count("tools/list"),
        "n_tools_call": methods.count("tools/call"),
        "n_handshake": sum(m in ("initialize", "server/discover", "notifications/initialized") for m in methods),
        "n_distinct_tools": len(set(calls)),
        "n_tool_errors": down.count(b'"isError":true'),
        "n_actuation_calls": sum(c in ("set_led", "sound_buzzer") for c in calls),
        "n_secret_refs": up.count(b"secrets/"),
        "n_read_file": calls.count("read_file"),
        "desc_len_max": max(descs, default=0),
        "desc_len_mean": statistics.fmean(descs) if descs else 0.0,
        "n_a2a_messages": up.count(b'"method":"message/send"') + up.count(b'"method":"SendMessage"'),
    })
    return f


def _kind(notes: str) -> str:
    m = re.search(r"kind=([\w-]+)", notes) or re.search(r"scenario=benign-([\w-]+)", notes)
    return m.group(1) if m else ""


def rows(run_prefixes=("S-BENIGN3-", "S-PILOT-ATK-")):
    with open(runner.DEFAULT_MANIFEST, newline="", encoding="utf-8-sig") as f:
        manifest = [r for r in csv.DictReader(f) if r["run_id"].startswith(run_prefixes)]
    for r in manifest:
        meta = {k: r.get(k, "") for k in META if k != "kind"}
        meta["kind"] = _kind(r["notes"])
        yield {**meta, **session_features(capture.CAPTURE_DIR / r["capture_file"])}


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=META + NETWORK + PROTOCOL)
        w.writeheader()
        for row in rows():
            w.writerow(row)
            n += 1
            if n % 250 == 0:
                print(f"{n} sessions...", flush=True)
    print(f"wrote {n} sessions to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
