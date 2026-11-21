"""Append-only audit log of every MCP tool call.

One JSON object per line: when, who (principal and role), which tool, the
arguments, and whether the call was allowed, denied or failed.

Attack scenarios use this log as ground truth for their success conditions
(attack-taxonomy.md §5: outcomes are validated against application logs, not
assumed). Entries are matched to sessions by time — sessions never overlap —
so nothing that identifies a session or its label is ever sent over the
network.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path

MAX_ARG_TEXT = 200   # characters of each string argument kept in the log

ALLOWED, DENIED, INVALID, ERROR = "allowed", "denied", "invalid", "error"


def _short(value):
    if isinstance(value, str) and len(value) > MAX_ARG_TEXT:
        return value[:MAX_ARG_TEXT] + f"...(+{len(value) - MAX_ARG_TEXT} chars)"
    return value


class AuditLog:
    """Writes audit entries to a JSON-lines file, or nowhere if path is None."""

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._file = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, "a", encoding="utf-8", buffering=1)

    def record(self, *, tool: str, principal: str, role: str, args: dict,
               decision: str, detail: str = "", request_id=None) -> dict:
        now = time.time()
        entry = {
            "ts": round(now, 6),
            "time": datetime.fromtimestamp(now).astimezone().isoformat(timespec="milliseconds"),
            "tool": tool,
            "principal": principal,
            "role": role,
            "args": {k: _short(v) for k, v in args.items()},
            "decision": decision,
            "detail": _short(detail),
            "request_id": request_id,
        }
        if self._file:
            line = json.dumps(entry, ensure_ascii=False, default=str)
            with self._lock:
                self._file.write(line + "\n")
        return entry

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None


def read(path: str | Path) -> list[dict]:
    """All entries of an audit log file."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def between(entries: list[dict], start: datetime, end: datetime) -> list[dict]:
    """Entries whose timestamp lies within [start, end] (a session's window)."""
    lo, hi = start.timestamp(), end.timestamp()
    return [e for e in entries if lo <= e["ts"] <= hi]
