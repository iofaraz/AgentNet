"""Run one labelled, captured session.

A session is one benign or attack scenario. The runner does everything around
it, in this order:

    1. allocate the next session ID and capture file name
    2. start the capture and wait until it is really recording
    3. run the scenario (with a time limit)
    4. stop the capture and verify it
    5. decide whether the session is valid
    6. valid    -> add a row to the manifest (dataset/labels/manifest.csv)
       excluded -> keep the capture, record why (contract section 9)
    7. always add a row to the capture log (dataset/labels/capture_log.csv)

The capture log holds what the manifest has no columns for: each capture's
SHA-256 hash, packet and drop counts, the scenario name and software versions
(contract section 11), and the status of excluded sessions.

Example:

    async def basic_tools() -> Outcome:
        ...talk to the MCP server...
        return Outcome()                     # benign: no success value

    runner = SessionRunner()
    result = runner.run(Scenario(
        name="mcp-basic-tools", protocol="MCP", attack_id="AT-00",
        bpf="tcp port 8000", run=basic_tools,
    ))
"""

from __future__ import annotations

import asyncio
import csv
import functools
import importlib.metadata
import inspect
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Awaitable, Callable

import capture
import manifest

DEFAULT_MANIFEST = capture.REPO_ROOT / "dataset" / "labels" / "manifest.csv"
DEFAULT_LOG = capture.REPO_ROOT / "dataset" / "labels" / "capture_log.csv"
DEFAULT_TIMEOUT = 120.0

LOG_COLUMNS = (
    "session_id",
    "run_id",
    "scenario",
    "status",             # valid | excluded
    "reason",             # why a session was excluded (empty when valid)
    "capture_file",
    "sha256",
    "packets_captured",
    "packets_dropped",
    "capture_start",
    "capture_stop",
    "software_versions",
)
VALID, EXCLUDED = "valid", "excluded"
MAX_REASON = 500  # characters of an exclusion reason kept in the capture log


class RunnerError(RuntimeError):
    """The runner could not run a session at all (nothing was recorded)."""


@dataclass(frozen=True)
class Outcome:
    """What a scenario reports when it finishes.

    success: for attacks, whether the scenario's predefined success condition
        was met (checked by the scenario, e.g. from server logs or device
        state) — never assumed. Must be None for benign scenarios.
    notes: short observations recorded in the manifest.
    """

    success: bool | None = None
    notes: str = ""


@dataclass(frozen=True)
class Scenario:
    """One benign or attack scenario."""

    name: str
    protocol: str                              # MCP | A2A
    attack_id: str                             # AT-00 (benign) .. AT-07
    bpf: str                                   # capture filter for this scenario's traffic
    run: Callable[[], Awaitable[Outcome]]      # async function that performs the session
    transport: str = "HTTP"
    variant: str = manifest.NOT_APPLICABLE     # attack variant; N/A for benign
    source_device: str = ""
    destination_device: str = ""
    timeout: float = DEFAULT_TIMEOUT

    @property
    def is_benign(self) -> bool:
        return self.attack_id == manifest.BENIGN_ID


@dataclass(frozen=True)
class SessionResult:
    session_id: str
    capture_file: str
    status: str                                # valid | excluded
    reason: str
    manifest_row: dict[str, str] | None        # the row written, None if excluded
    capture: capture.CaptureResult | None

    @property
    def valid(self) -> bool:
        return self.status == VALID


# --------------------------------------------------------------------------
# Scenario checks
# --------------------------------------------------------------------------

def check_scenario(s: Scenario) -> None:
    """Reject a scenario that could only ever produce invalid records."""
    problems = []
    if not s.name or s.name != s.name.strip():
        problems.append("name must be non-empty without surrounding spaces")
    if s.protocol not in manifest.PROTOCOLS:
        problems.append(f"protocol must be one of {sorted(manifest.PROTOCOLS)}")
    if s.transport not in manifest.TRANSPORTS:
        problems.append(f"transport must be one of {sorted(manifest.TRANSPORTS)}")
    if s.attack_id not in manifest.ATTACKS:
        problems.append(f"attack_id must be one of {sorted(manifest.ATTACKS)}")
    elif s.protocol in manifest.PROTOCOLS and s.protocol not in manifest.ATTACKS[s.attack_id][1]:
        problems.append(f"{s.attack_id} is not defined for {s.protocol}")
    if s.attack_id == manifest.BENIGN_ID and s.variant != manifest.NOT_APPLICABLE:
        problems.append("benign scenarios have variant N/A")
    if s.attack_id != manifest.BENIGN_ID and (not s.variant.strip() or s.variant == manifest.NOT_APPLICABLE):
        problems.append("attack scenarios need a variant identifier, e.g. 'V1'")
    if not s.bpf.strip():
        problems.append("a capture filter (bpf) is required")
    if not inspect.iscoroutinefunction(s.run):
        problems.append("run must be an async function (async def)")
    if not s.timeout > 0:
        problems.append("timeout must be positive")
    if problems:
        raise ValueError(f"invalid scenario {s.name!r}: " + "; ".join(problems))


# --------------------------------------------------------------------------
# IDs, versions, lock
# --------------------------------------------------------------------------

def _id_prefix(protocol: str, environment: str, attack_id: str) -> str:
    env = "S" if environment == "Software" else "H"
    kind = "B" if attack_id == manifest.BENIGN_ID else f"AT{attack_id[3:]}-"
    return f"{protocol}-{env}-{kind}"


def _file_prefix(protocol: str, environment: str, attack_id: str) -> str:
    kind = "benign" if attack_id == manifest.BENIGN_ID else f"at{attack_id[3:]}"
    return f"{protocol.lower()}_{kind}_{environment.lower()}_"


def _read_ids(path: Path, column: str) -> list[str]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return [row.get(column, "") for row in csv.DictReader(f)]


@functools.lru_cache(maxsize=1)
def software_versions() -> str:
    """Versions that affect the generated traffic (contract section 11)."""
    parts = [f"python={platform.python_version()}"]
    for dist in ("mcp", "a2a-sdk"):
        try:
            parts.append(f"{dist}={importlib.metadata.version(dist)}")
        except importlib.metadata.PackageNotFoundError:
            pass
    try:
        out = subprocess.run([str(capture.find_dumpcap()), "-v"], capture_output=True, text=True, timeout=30).stdout
        m = re.search(r"(\d+\.\d+\.\d+)", out)
        if m:
            parts.append(f"dumpcap={m[1]}")
    except (capture.CaptureError, OSError, subprocess.SubprocessError):
        pass
    return ";".join(parts)


class _RunnerLock:
    """Only one runner at a time may allocate IDs and capture.

    Uses an operating-system file lock, which is released automatically if
    the process dies, so a crash can never leave a stale lock behind.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._file = None

    def __enter__(self) -> "_RunnerLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = open(self.path, "a+")
        try:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            raise RunnerError("another session runner is already active") from None
        self._file = f
        return self

    def __exit__(self, *exc) -> None:
        f, self._file = self._file, None
        if f is None:
            return
        try:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_UN)
        finally:
            f.close()


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

class _ScenarioTimeout(Exception):
    """The runner's own time limit expired (not a timeout inside the scenario)."""


async def _run_bounded(s: Scenario) -> Outcome:
    limit = asyncio.timeout(s.timeout)
    try:
        async with limit:
            return await s.run()
    except TimeoutError:
        # A scenario's own network timeout is also a TimeoutError; only call it
        # a runner timeout when our deadline is what expired.
        if limit.expired():
            raise _ScenarioTimeout() from None
        raise

@dataclass
class SessionRunner:
    """Runs scenarios one at a time and records every session.

    run_id groups the sessions of one collection run (contract section 10:
    splits are made by run, so related sessions stay together).
    """

    manifest_path: Path = DEFAULT_MANIFEST
    log_path: Path = DEFAULT_LOG
    capture_dir: Path = capture.CAPTURE_DIR
    environment: str = "Software"
    run_id: str = field(default_factory=lambda: "S-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    interface: str | None = None
    grace: float = capture.DEFAULT_GRACE

    def __post_init__(self) -> None:
        self.manifest_path = Path(self.manifest_path)
        self.log_path = Path(self.log_path)
        self.capture_dir = Path(self.capture_dir)
        if self.environment not in manifest.ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(manifest.ENVIRONMENTS)}")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.run_id):
            raise ValueError("run_id may contain only letters, digits, '.', '_' and '-'")

    # ---- public ------------------------------------------------------------

    def run(self, scenario: Scenario) -> SessionResult:
        """Run one scenario as one captured, labelled session."""
        check_scenario(scenario)
        with _RunnerLock(self.capture_dir / ".runner.lock"):
            self._preflight()
            number = self._next_number(scenario)
            session_id = f"{_id_prefix(scenario.protocol, self.environment, scenario.attack_id)}{number:04d}"
            capture_file = f"{_file_prefix(scenario.protocol, self.environment, scenario.attack_id)}{number:04d}.pcapng"
            return self._run_locked(scenario, session_id, capture_file)

    # ---- internals -----------------------------------------------------------

    def _preflight(self) -> None:
        """Refuse to record if either output file is damaged.

        Checked before capturing so a session can never end up written to one
        file but not the other.
        """
        if self.manifest_path.exists():
            _, report = manifest.load(self.manifest_path)
            if report.errors:
                raise RunnerError(f"{self.manifest_path} is invalid: " + "; ".join(report.errors[:3]))
        if self.log_path.exists():
            with open(self.log_path, newline="", encoding="utf-8-sig") as f:
                header = next(csv.reader(f), None)
            if tuple(header or ()) != LOG_COLUMNS:
                raise RunnerError(f"{self.log_path} has an unexpected header; not appending")

    def _next_number(self, s: Scenario) -> int:
        """Highest number used so far for this protocol/environment/attack, plus one.

        Looks at the manifest, the capture log (excluded sessions also use up
        their ID) and existing capture files (e.g. from an interrupted run),
        so a number is never handed out twice.
        """
        id_prefix = _id_prefix(s.protocol, self.environment, s.attack_id)
        file_prefix = _file_prefix(s.protocol, self.environment, s.attack_id)
        used = [0]
        for sid in _read_ids(self.manifest_path, "session_id") + _read_ids(self.log_path, "session_id"):
            if sid.startswith(id_prefix) and sid[len(id_prefix):].isdigit():
                used.append(int(sid[len(id_prefix):]))
        if self.capture_dir.is_dir():
            for p in self.capture_dir.glob(f"{file_prefix}*.pcapng"):
                digits = p.name[len(file_prefix):-len(".pcapng")]
                if digits.isdigit():
                    used.append(int(digits))
        return max(used) + 1

    def _run_locked(self, s: Scenario, session_id: str, capture_file: str) -> SessionResult:
        cap = capture.Capture(
            capture_file, bpf=s.bpf, interface=self.interface,
            capture_dir=self.capture_dir, grace=self.grace,
        )
        try:
            cap.start()
        except capture.CaptureError as e:
            raise RunnerError(f"could not start capture for {session_id}: {e}") from e

        start_time = manifest.now()
        outcome: Outcome | None = None
        reason = ""
        try:
            try:
                outcome = asyncio.run(_run_bounded(s))
            except _ScenarioTimeout:
                reason = f"scenario timed out after {s.timeout:g}s"
            except Exception as e:  # the session failed; record it, don't crash the run
                reason = f"scenario error: {type(e).__name__}: {e}"
        except BaseException:
            # Interrupted (e.g. Ctrl+C): stop recording, record the session as
            # excluded, then let the interruption continue.
            self._finish(cap, s, session_id, capture_file, start_time, manifest.now(),
                         None, "interrupted before the scenario finished")
            raise
        end_time = manifest.now()

        if not reason:
            reason = self._outcome_problem(s, outcome)
        return self._finish(cap, s, session_id, capture_file, start_time, end_time, outcome, reason)

    @staticmethod
    def _outcome_problem(s: Scenario, outcome: Outcome | None) -> str:
        if not isinstance(outcome, Outcome):
            return f"scenario returned {type(outcome).__name__}, expected Outcome"
        if s.is_benign and outcome.success is not None:
            return "benign scenario reported an attack success value"
        if not s.is_benign and not isinstance(outcome.success, bool):
            return "attack outcome was not determined (success must be True or False)"
        return ""

    def _finish(self, cap: capture.Capture, s: Scenario, session_id: str, capture_file: str,
                start_time: str, end_time: str, outcome: Outcome | None, reason: str) -> SessionResult:
        cap_result: capture.CaptureResult | None = None
        try:
            cap_result = cap.stop()
        except capture.CaptureError as e:
            reason = reason or f"capture error: {e}"
        if cap_result and not reason:
            if cap_result.packets_captured == 0:
                reason = "capture is empty (no packets matched the filter)"
            elif cap_result.packets_dropped:
                reason = f"capture dropped {cap_result.packets_dropped} packet(s)"

        row = None
        if not reason:
            row = self._manifest_row(s, session_id, capture_file, start_time, end_time, outcome)
            try:
                row = manifest.append(self.manifest_path, row)
            except manifest.ManifestError as e:
                row, reason = None, f"manifest rejected the record: {e}"

        status = EXCLUDED if reason else VALID
        self._log(s, session_id, capture_file, status, reason, cap_result)
        return SessionResult(session_id, capture_file, status, reason, row, cap_result)

    def _manifest_row(self, s: Scenario, session_id: str, capture_file: str,
                      start_time: str, end_time: str, outcome: Outcome) -> dict[str, str]:
        if s.is_benign:
            label, result = "Benign", manifest.NOT_APPLICABLE
        else:
            label, result = "Attack", ("Success" if outcome.success else "Failed")
        notes = f"scenario={s.name}" + (f"; {outcome.notes}" if outcome.notes else "")
        return {
            "session_id": session_id,
            "label": label,
            "attack_id": s.attack_id,
            "protocol": s.protocol,
            "transport": s.transport,
            "environment": self.environment,
            "capture_file": capture_file,
            "outcome": result,
            "start_time": start_time,
            "end_time": end_time,
            "run_id": self.run_id,
            "attack_variant": s.variant,
            "source_device": s.source_device,
            "destination_device": s.destination_device,
            "notes": notes,
        }

    def _log(self, s: Scenario, session_id: str, capture_file: str, status: str,
             reason: str, r: capture.CaptureResult | None) -> None:
        row = {
            "session_id": session_id,
            "run_id": self.run_id,
            "scenario": s.name,
            "status": status,
            # The log is version-controlled; cap long error text.
            "reason": manifest.sanitize_free_text(reason)[:MAX_REASON],
            "capture_file": capture_file,
            "sha256": r.sha256 if r else "",
            "packets_captured": str(r.packets_captured) if r else "",
            "packets_dropped": str(r.packets_dropped) if r else "",
            "capture_start": r.started_at if r else "",
            "capture_stop": r.stopped_at if r else "",
            "software_versions": software_versions(),
        }
        new = not self.log_path.exists()  # header already verified by _preflight
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=LOG_COLUMNS)
            if new:
                w.writeheader()
            w.writerow(row)
