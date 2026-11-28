"""Benign collection run: thousands of captured sessions in reproducible,
resumable batches, then validation and backup.

The whole collection is fixed in advance by a schedule (2,500 sessions,
10 batches of 250). Every batch holds exactly the agreed mix of session
kinds (40% scripted MCP, 30% LLM over MCP, 30% A2A), and every session has a
fixed (kind, seed), so the collection can be repeated and audited.

Each batch is one run (run_id S-BENIGN3-01 .. S-BENIGN3-10). Contract section
10 splits datasets by run, so the batches double as the units for
train/validation/test splits.

Every attempt is recorded in dataset/labels/benign_schedule.csv (schedule
slot -> session ID -> valid/excluded). That makes a batch resumable: running
it again skips finished slots and retries excluded ones (at most
MAX_ATTEMPTS times). Excluded sessions stay in the capture log with their
reason (contract section 9) - nothing is deleted.

Pilot: the first batch (run S-BENIGN-01, catalogue without multi-step tasks,
llama3.2:3b) showed that the agent almost never chained tool calls. It is kept
and documented but left out of the final dataset (dataset/labels/
excluded_runs.csv, decision D16); its progress is in benign_schedule_pilot.csv.
The collection restarted with run IDs S-BENIGN2-xx and seeds from 1001.

GPU: S-BENIGN2-01 ran the model on the laptop CPU. The model then moved to
a lab RTX 3090 (AGENTNET_OLLAMA_URL), so S-BENIGN2-01 is excluded as well
(timing differs, decision D17; progress in benign_schedule_cpu.csv) and the
collection restarted as S-BENIGN3-xx with seeds from 2001.

Command line:
    python scripts/collect.py plan                  # show the schedule (no network)
    python scripts/collect.py run --batch 1         # run (or resume) one batch
    python scripts/collect.py run --next            # run the first unfinished batch
    python scripts/collect.py status                # progress per batch
    python scripts/collect.py verify                # full check incl. capture hashes
    python scripts/collect.py backup                # to DEFAULT_BACKUP_DIR (or --to <folder>)

After a batch, `run` backs up to DEFAULT_BACKUP_DIR automatically if that
folder exists.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import os
import random
import shutil
import stat
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import benign_scenarios as B
import capture
import manifest
import runner
import testbed

LABELS_DIR = capture.REPO_ROOT / "dataset" / "labels"
PROGRESS_PATH = LABELS_DIR / "benign_schedule.csv"
PILOT_PROGRESS_PATH = LABELS_DIR / "benign_schedule_pilot.csv"
CPU_PROGRESS_PATH = LABELS_DIR / "benign_schedule_cpu.csv"   # S-BENIGN2-01, excluded (D17)
EXCLUDED_RUNS_PATH = LABELS_DIR / "excluded_runs.csv"
EXCLUDED_RUNS_COLUMNS = ("run_id", "environment", "reason", "decided_on")
SERVER_LOG_DIR = capture.CAPTURE_DIR / "logs"
# Shared Google Drive folder (decision D7). Override with AGENTNET_BACKUP_DIR.
DEFAULT_BACKUP_DIR = Path(os.environ.get("AGENTNET_BACKUP_DIR", r"H:\My Drive\AgentNet"))

# The agreed collection (decided 2026-11-23). Changing any of these changes
# the schedule; verify() refuses progress recorded under a different one.
BENIGN_TOTAL = 2500
BATCH_SIZE = 250
BENIGN_MIX = {"mcp-scripted": 0.40, "mcp-llm": 0.30, "a2a": 0.30}
RUN_PREFIX = "S-BENIGN3-"     # S-BENIGN-01 = pilot, S-BENIGN2-01 = CPU model; both excluded
SEED_START = 2001             # above every seed used by the excluded runs

MAX_ATTEMPTS = 3              # tries per schedule slot before giving up on it
MAX_CONSECUTIVE_EXCLUDED = 5  # stop the batch: something systematic is wrong
TYPICAL_SECONDS = {"mcp-scripted": 7, "mcp-llm": 35, "a2a": 90}  # per session, incl. capture overhead

PROGRESS_COLUMNS = ("index", "batch", "run_id", "kind", "seed", "attempt", "session_id", "status", "reason")
INTERRUPTED = "interrupted"
# An attempt that failed while the LLM backend (Ollama, possibly through a
# tunnel) was unreachable. Like INTERRUPTED it does not use up the slot's
# tries: the session itself was never given a fair chance. The capture log
# still keeps the excluded session with its original reason.
BACKEND_DOWN = "llm backend unreachable"
NOT_COUNTED = (INTERRUPTED, BACKEND_DOWN)
BACKEND_WAIT_SECONDS = 2 * 3600   # how long to wait for the backend to come back
BACKEND_POLL_SECONDS = 30
LLM_KINDS = ("mcp-llm", "a2a")


class CollectionError(RuntimeError):
    """The collection cannot continue (bad progress file, systematic failures)."""


# ==========================================================================
# Schedule
# ==========================================================================

@dataclass(frozen=True)
class Slot:
    index: int    # position in the whole collection, from 0
    batch: int    # from 1
    kind: str
    seed: int

    @property
    def run_id(self) -> str:
        return run_id_for(self.batch)


def run_id_for(batch: int) -> str:
    return f"{RUN_PREFIX}{batch:02d}"


def kinds_per_batch(size: int, mix: dict[str, float]) -> dict[str, int]:
    """Exact number of sessions of each kind in one batch (largest remainder)."""
    if not mix or any(v < 0 for v in mix.values()) or abs(sum(mix.values()) - 1) > 1e-9:
        raise ValueError("mix shares must be non-negative and sum to 1")
    exact = {k: size * share for k, share in mix.items()}
    counts = {k: int(v) for k, v in exact.items()}
    for k in sorted(exact, key=lambda k: exact[k] - counts[k], reverse=True)[: size - sum(counts.values())]:
        counts[k] += 1
    return counts


def schedule(total: int = BENIGN_TOTAL, size: int = BATCH_SIZE, mix: dict[str, float] = BENIGN_MIX,
             seed_start: int = SEED_START) -> list[Slot]:
    """The whole collection, slot by slot.

    Each batch has exactly the mix; the order of kinds inside a batch is
    shuffled (so the testbed never runs long blocks of one kind); seeds count
    up per kind across the whole collection, so no (kind, seed) repeats.
    """
    unknown = set(mix) - set(B.KINDS)
    if unknown:
        raise ValueError(f"unknown kinds: {sorted(unknown)}")
    if size < 1 or total < size or total % size:
        raise ValueError("total must be a positive multiple of the batch size")
    counts = kinds_per_batch(size, mix)
    next_seed = {k: seed_start for k in mix}
    slots: list[Slot] = []
    for batch in range(1, total // size + 1):
        kinds = [k for k in mix for _ in range(counts[k])]
        random.Random(f"benign-schedule:{batch}").shuffle(kinds)
        for kind in kinds:
            slots.append(Slot(len(slots), batch, kind, next_seed[kind]))
            next_seed[kind] += 1
    return slots


# ==========================================================================
# Progress file (one row per attempt)
# ==========================================================================

def read_progress(path: Path = PROGRESS_PATH) -> list[dict[str, str]]:
    path = Path(path)
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != PROGRESS_COLUMNS:
            raise CollectionError(f"{path} has an unexpected header")
        return list(reader)


def _append_progress(path: Path, row: dict) -> None:
    path = Path(path)
    new = not path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=PROGRESS_COLUMNS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in PROGRESS_COLUMNS})


def history(rows: list[dict[str, str]], slots: list[Slot]) -> dict[int, list[dict[str, str]]]:
    """Attempts per slot index, after checking they belong to this schedule."""
    by_index: dict[int, list[dict[str, str]]] = defaultdict(list)
    for n, row in enumerate(rows, start=2):
        try:
            i = int(row["index"])
            slot = slots[i]
        except (ValueError, IndexError):
            raise CollectionError(f"progress line {n}: index {row['index']!r} is not in the schedule") from None
        if (row["kind"], row["seed"], row["batch"]) != (slot.kind, str(slot.seed), str(slot.batch)):
            raise CollectionError(
                f"progress line {n}: slot {i} was recorded as {row['kind']}/seed {row['seed']}/batch "
                f"{row['batch']}, but the schedule says {slot.kind}/seed {slot.seed}/batch {slot.batch}. "
                "The schedule settings were changed after collection started.")
        by_index[i].append(row)
    return by_index


def slot_state(attempts: list[dict[str, str]], max_attempts: int = MAX_ATTEMPTS) -> str:
    """valid | gave_up | pending.  Interrupted attempts (Ctrl+C) do not count."""
    if any(a["status"] == runner.VALID for a in attempts):
        return "valid"
    tries = sum(not a["reason"].startswith(NOT_COUNTED) for a in attempts)
    return "gave_up" if tries >= max_attempts else "pending"


# ==========================================================================
# Running a batch
# ==========================================================================

def check_ollama() -> None:
    """LLM-driven kinds need the local model; fail before capturing anything."""
    import agent  # on sys.path via benign_scenarios (software_testbed/llm)
    try:
        asyncio.run(agent.model_digest(agent.DEFAULT_MODEL))
    except Exception as e:
        raise CollectionError(f"Ollama is not ready ({type(e).__name__}: {e}). Start Ollama and "
                              f"make sure '{agent.DEFAULT_MODEL}' is installed.") from None


def ollama_reachable() -> bool:
    import agent
    try:
        asyncio.run(agent.model_digest(agent.DEFAULT_MODEL))
        return True
    except Exception:
        return False


def ollama_backend_check(echo: Callable[[str], None] = print, *, reachable: Callable[[], bool] = ollama_reachable,
                         wait_s: float = BACKEND_WAIT_SECONDS, poll_s: float = BACKEND_POLL_SECONDS,
                         sleep: Callable[[float], None] = time.sleep) -> str:
    """'up' if the model answers now; otherwise wait for it: 'recovered' or 'down'."""
    if reachable():
        return "up"
    echo(f"LLM backend unreachable - waiting up to {wait_s / 60:.0f} min for it to come back "
         f"(reopen the SSH tunnel / start Ollama)")
    waited = 0.0
    while waited < wait_s:
        sleep(poll_s)
        waited += poll_s
        if reachable():
            echo(f"LLM backend is back after {waited / 60:.1f} min; continuing")
            return "recovered"
    return "down"


def run_batch(
    batch: int,
    *,
    slots: list[Slot] | None = None,
    session_runner: runner.SessionRunner | None = None,
    build: Callable[[str, int], runner.Scenario] = B.build,
    progress_path: Path = PROGRESS_PATH,
    servers=None,
    preflight: Callable[[], None] | None = check_ollama,
    max_attempts: int = MAX_ATTEMPTS,
    max_consecutive: int = MAX_CONSECUTIVE_EXCLUDED,
    echo: Callable[[str], None] = print,
    backend_check: Callable[[Callable[[str], None]], str] | None = ollama_backend_check,
) -> Counter:
    """Run (or resume) one batch. Returns counts of valid / excluded / gave_up / skipped."""
    slots = schedule() if slots is None else slots
    mine = [s for s in slots if s.batch == batch]
    if not mine:
        raise ValueError(f"batch {batch} is not in the schedule")
    run_id = run_id_for(batch)
    run = session_runner or runner.SessionRunner(run_id=run_id)
    if run.run_id != run_id:
        raise ValueError(f"session runner has run_id {run.run_id!r}, batch {batch} needs {run_id!r}")
    past = history(read_progress(progress_path), slots)
    todo = [s for s in mine if slot_state(past.get(s.index, []), max_attempts) == "pending"]
    counts = Counter(skipped=len(mine) - len(todo))
    if not todo:
        echo(f"batch {batch}: nothing to do")
        return counts
    if preflight and any(s.kind != "mcp-scripted" for s in todo):
        preflight()

    ctx = servers if servers is not None else testbed.running(
        testbed.MCP_SERVER, testbed.A2A_SERVER, log_dir=SERVER_LOG_DIR,
        run_id=server_log_label(run_id, SERVER_LOG_DIR))
    consecutive, last_reason = 0, ""
    with ctx:
        for n, slot in enumerate(todo, start=1):
            while slot_state(past.get(slot.index, []), max_attempts) == "pending":
                attempt = len(past.get(slot.index, [])) + 1
                base = {"index": slot.index, "batch": slot.batch, "run_id": run_id,
                        "kind": slot.kind, "seed": slot.seed, "attempt": attempt}
                try:
                    res = run.run(build(slot.kind, slot.seed))
                except KeyboardInterrupt:
                    # The runner has already logged the session as excluded.
                    _append_progress(progress_path, {**base, "status": runner.EXCLUDED, "reason": INTERRUPTED})
                    raise
                reason = manifest.sanitize_free_text(res.reason)[: runner.MAX_REASON]
                backend = "up"
                if not res.valid and backend_check and slot.kind in LLM_KINDS:
                    backend = backend_check(echo)
                    if backend != "up":
                        reason = f"{BACKEND_DOWN}; {reason}"[: runner.MAX_REASON]
                row = {**base, "session_id": res.session_id, "status": res.status, "reason": reason}
                _append_progress(progress_path, row)
                past.setdefault(slot.index, []).append({k: str(v) for k, v in row.items()})
                counts[res.status] += 1
                echo(f"[{run_id} {n}/{len(todo)}] {res.session_id:14} {slot.kind:13} seed={slot.seed:<5} "
                     f"{res.status}{(': ' + res.reason) if res.reason else ''}")
                if backend == "down":
                    raise CollectionError(
                        f"the LLM backend did not come back within {BACKEND_WAIT_SECONDS / 60:.0f} min; "
                        f"stopping the batch. Reopen the tunnel / start Ollama, then run the batch again to resume.")
                if res.valid or backend == "recovered":
                    consecutive = 0
                else:
                    consecutive, last_reason = consecutive + 1, res.reason
                    if consecutive >= max_consecutive:
                        raise CollectionError(
                            f"{consecutive} sessions in a row were excluded; stopping the batch. "
                            f"Last reason: {last_reason}. Fix the cause, then run the batch again to resume.")
            if slot_state(past[slot.index], max_attempts) == "gave_up":
                counts["gave_up"] += 1
    return counts


def server_log_label(run_id: str, log_dir: Path) -> str:
    """Name for this run's server logs: run_id, or run_id_partN when a paused
    batch is resumed (logs are never overwritten, so each part gets its own)."""
    log_dir = Path(log_dir)
    if not any(log_dir.glob(f"{run_id}_*")):
        return run_id
    part = 2
    while any(log_dir.glob(f"{run_id}_part{part}_*")):
        part += 1
    return f"{run_id}_part{part}"


def next_batch(slots: list[Slot] | None = None, progress_path: Path = PROGRESS_PATH) -> int | None:
    slots = schedule() if slots is None else slots
    past = history(read_progress(progress_path), slots)
    for s in slots:
        if slot_state(past.get(s.index, [])) == "pending":
            return s.batch
    return None


def excluded_runs(path: Path = EXCLUDED_RUNS_PATH) -> dict[str, dict[str, str]]:
    """Runs kept on record but left out of the final dataset (run_id -> row).

    The dataset pipeline (Part 6) must drop every manifest row whose run_id
    is listed here.
    """
    path = Path(path)
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != EXCLUDED_RUNS_COLUMNS:
            raise CollectionError(f"{path} has an unexpected header")
        return {r["run_id"]: r for r in reader}


# ==========================================================================
# Status and verification
# ==========================================================================

@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _read_log(path: Path) -> list[dict[str, str]]:
    if not Path(path).exists():
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def status_lines(slots: list[Slot], past: dict[int, list[dict[str, str]]]) -> list[str]:
    lines = [f"{'batch':6} {'run_id':12} {'valid':>6} {'gave up':>8} {'pending':>8} {'attempts':>9}"]
    totals = Counter()
    for batch in sorted({s.batch for s in slots}):
        c = Counter(slot_state(past.get(s.index, [])) for s in slots if s.batch == batch)
        attempts = sum(len(past.get(s.index, [])) for s in slots if s.batch == batch)
        totals.update(c)
        totals["attempts"] += attempts
        lines.append(f"{batch:<6} {run_id_for(batch):12} {c['valid']:>6} {c['gave_up']:>8} {c['pending']:>8} {attempts:>9}")
    lines.append(f"{'total':6} {'':12} {totals['valid']:>6} {totals['gave_up']:>8} {totals['pending']:>8} {totals['attempts']:>9}")
    return lines


def verify(
    *,
    slots: list[Slot] | None = None,
    manifest_path: Path = runner.DEFAULT_MANIFEST,
    log_path: Path = runner.DEFAULT_LOG,
    capture_dir: Path = capture.CAPTURE_DIR,
    progress_path: Path = PROGRESS_PATH,
    excluded_runs_path: Path = EXCLUDED_RUNS_PATH,
    check_hashes: bool = True,
) -> Report:
    """Check the collected data end to end and summarise it."""
    slots = schedule() if slots is None else slots
    rep = Report()

    rows, mreport = manifest.load(manifest_path) if Path(manifest_path).exists() else ([], None)
    if mreport:
        rep.errors += [f"manifest: {e}" for e in mreport.errors]
        rep.warnings += [f"manifest: {w}" for w in mreport.warnings]
    by_sid = {r["session_id"]: r for r in rows}
    log = _read_log(log_path)
    log_by_sid = {r["session_id"]: r for r in log}

    try:
        past = history(read_progress(progress_path), slots)
    except CollectionError as e:
        rep.errors.append(str(e))
        return rep

    # Every capture: present and unchanged (hash recorded when it was made).
    for r in log:
        path = Path(capture_dir) / r["capture_file"]
        if not path.exists():
            (rep.errors if r["status"] == runner.VALID else rep.warnings).append(
                f"{r['session_id']}: capture {r['capture_file']} is missing")
            continue
        if check_hashes and r["sha256"] and capture.sha256_of(path) != r["sha256"]:
            rep.errors.append(f"{r['session_id']}: {r['capture_file']} does not match its recorded SHA-256")

    # The manifest holds exactly the valid sessions of the capture log.
    valid_log = {sid for sid, r in log_by_sid.items() if r["status"] == runner.VALID}
    for sid in sorted(set(by_sid) - valid_log):
        rep.errors.append(f"{sid}: in the manifest but not logged as a valid capture")
    for sid in sorted(valid_log - set(by_sid)):
        rep.errors.append(f"{sid}: logged as valid but missing from the manifest")

    # Every recorded attempt points at a real session with the right label.
    for i, attempts in past.items():
        slot = slots[i]
        for a in attempts:
            sid = a["session_id"]
            if a["status"] == runner.VALID:
                row = by_sid.get(sid)
                if row is None:
                    rep.errors.append(f"slot {i}: valid session {sid} is not in the manifest")
                    continue
                if row["attack_id"] != manifest.BENIGN_ID or row["run_id"] != slot.run_id:
                    rep.errors.append(f"slot {i}: {sid} is not a benign session of run {slot.run_id}")
                if f"scenario=benign-{slot.kind}" not in row["notes"] or f"seed={slot.seed};" not in row["notes"]:
                    rep.errors.append(f"slot {i}: {sid} does not record kind {slot.kind} / seed {slot.seed}")
            elif sid and sid not in log_by_sid:
                rep.errors.append(f"slot {i}: excluded session {sid} is not in the capture log")

    # Summary.
    rep.lines += status_lines(slots, past)
    valid_slots = [s for s in slots if slot_state(past.get(s.index, [])) == "valid"]
    if valid_slots:
        rep.lines.append("")
        rep.lines.append(f"{'kind':13} {'sessions':>8} {'share':>6} {'median pkts':>11} {'median s':>9}")
        sid_of = {s.index: next(a["session_id"] for a in past[s.index] if a["status"] == runner.VALID)
                  for s in valid_slots}
        for kind in sorted({s.kind for s in slots}):
            sids = [sid_of[s.index] for s in valid_slots if s.kind == kind]
            pkts = [int(log_by_sid[x]["packets_captured"]) for x in sids
                    if x in log_by_sid and log_by_sid[x]["packets_captured"].isdigit()]
            durs = [(datetime.fromisoformat(by_sid[x]["end_time"]) - datetime.fromisoformat(by_sid[x]["start_time"]))
                    .total_seconds() for x in sids if x in by_sid]
            rep.lines.append(f"{kind:13} {len(sids):>8} {len(sids) / len(valid_slots):>6.1%} "
                             f"{statistics.median(pkts) if pkts else '-':>11} "
                             f"{round(statistics.median(durs), 2) if durs else '-':>9}")
        llm_rows = [by_sid[sid_of[s.index]] for s in valid_slots if s.kind == "mcp-llm" and sid_of[s.index] in by_sid]
        if llm_rows:
            calls = [_tool_calls(r["notes"]) for r in llm_rows]
            chained = sum(c >= 2 for c in calls)
            rep.lines.append(f"mcp-llm sessions with 2+ tool calls: {chained}/{len(calls)} ({chained / len(calls):.0%})")
    try:
        excl = excluded_runs(excluded_runs_path)
    except CollectionError as e:
        rep.errors.append(str(e))
        excl = {}
    for run_id, r in excl.items():
        n = sum(row["run_id"] == run_id for row in rows)
        rep.lines.append(f"excluded from the final dataset: run {run_id} ({n} manifest rows) - {r['reason']}")
    reasons = Counter(a["reason"].split(":")[0] for att in past.values() for a in att if a["status"] != runner.VALID)
    if reasons:
        rep.lines.append("")
        rep.lines.append("exclusion reasons: " + "; ".join(f"{r} x{n}" for r, n in reasons.most_common(5)))
    return rep


def _tool_calls(notes: str) -> int:
    """Number of tools an LLM session called, from its manifest notes ('tools=a,b')."""
    for part in notes.split(";"):
        key, _, value = part.strip().partition("=")
        if key == "tools":
            return 0 if value in ("", "-") else len(value.split(","))
    return 0


# ==========================================================================
# Backup
# ==========================================================================

@dataclass
class BackupReport:
    copied: int = 0
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)


def _replace(src: Path, dst: Path) -> None:
    if dst.exists():
        os.chmod(dst, stat.S_IWRITE)   # captures are read-only
        dst.unlink()
    shutil.copy2(src, dst)


def backup(
    dest: Path,
    *,
    manifest_path: Path = runner.DEFAULT_MANIFEST,
    log_path: Path = runner.DEFAULT_LOG,
    capture_dir: Path = capture.CAPTURE_DIR,
    progress_path: Path = PROGRESS_PATH,
    server_log_dir: Path = SERVER_LOG_DIR,
    extra_labels: tuple[Path, ...] = (PILOT_PROGRESS_PATH, CPU_PROGRESS_PATH, EXCLUDED_RUNS_PATH),
) -> BackupReport:
    """Copy captures and label files to dest/AgentNet-software, verifying every copy.

    Captures already backed up with the right hash are skipped, so the
    command can be run after every batch.
    """
    dest = Path(dest)
    if not dest.is_dir():
        raise CollectionError(f"backup folder {dest} does not exist")
    root = dest / "AgentNet-software"
    (root / "pcaps").mkdir(parents=True, exist_ok=True)
    (root / "labels").mkdir(parents=True, exist_ok=True)
    rep = BackupReport()
    sums = []

    for r in _read_log(log_path):
        if not r["sha256"]:
            continue
        src, dst = Path(capture_dir) / r["capture_file"], root / "pcaps" / r["capture_file"]
        if not src.exists():
            rep.errors.append(f"{r['capture_file']}: missing locally, not backed up")
            continue
        sums.append(f"{r['sha256']}  pcaps/{r['capture_file']}")
        if dst.exists() and capture.sha256_of(dst) == r["sha256"]:
            rep.unchanged += 1
            continue
        if capture.sha256_of(src) != r["sha256"]:
            rep.errors.append(f"{r['capture_file']}: local file does not match its recorded hash; not copied")
            continue
        _replace(src, dst)
        if capture.sha256_of(dst) != r["sha256"]:
            rep.errors.append(f"{r['capture_file']}: backup copy is corrupt")
            continue
        rep.copied += 1

    for src in (manifest_path, log_path, progress_path, *extra_labels):
        src = Path(src)
        if src.exists():
            dst = root / "labels" / src.name
            _replace(src, dst)
            digest = capture.sha256_of(dst)
            if digest != capture.sha256_of(src):
                rep.errors.append(f"{src.name}: backup copy is corrupt")
            sums.append(f"{digest}  labels/{src.name}")

    if Path(server_log_dir).is_dir():
        (root / "server-logs").mkdir(exist_ok=True)
        # *.log: server output; *_audit.jsonl: every tool call (ground truth for attack outcomes)
        for src in sorted(p for p in Path(server_log_dir).iterdir() if p.suffix in (".log", ".jsonl")):
            _replace(src, root / "server-logs" / src.name)

    (root / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return rep


# ==========================================================================
# Command line
# ==========================================================================

def _print_plan(slots: list[Slot]) -> None:
    per_batch = kinds_per_batch(BATCH_SIZE, BENIGN_MIX)
    batches = len({s.batch for s in slots})
    print(f"{len(slots)} sessions in {batches} batches of {BATCH_SIZE}")
    print("each batch: " + ", ".join(f"{k} {n}" for k, n in per_batch.items()))
    secs = sum(TYPICAL_SECONDS[k] * n for k, n in per_batch.items())
    print(f"estimated time: ~{secs / 60:.0f} min per batch, ~{secs * batches / 3600:.1f} h in total")
    for batch in range(1, batches + 1):
        mine = [s for s in slots if s.batch == batch]
        seeds = {k: [s.seed for s in mine if s.kind == k] for k in BENIGN_MIX}
        print(f"  {run_id_for(batch)}: " + ", ".join(f"{k} seeds {min(v)}-{max(v)}" for k, v in seeds.items() if v)
              + f"; first: {', '.join(s.kind for s in mine[:3])} ...")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AgentNet benign collection run")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="show the schedule (no network)")
    r = sub.add_parser("run", help="run or resume one batch")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--batch", type=int)
    g.add_argument("--next", action="store_true", help="the first batch with unfinished sessions")
    sub.add_parser("status", help="progress per batch")
    v = sub.add_parser("verify", help="check manifest, capture log, hashes and schedule")
    v.add_argument("--no-hashes", action="store_true", help="skip recomputing capture hashes")
    b = sub.add_parser("backup", help="copy captures and labels to a folder, verifying every copy")
    b.add_argument("--to", type=Path, default=DEFAULT_BACKUP_DIR,
                   help=f"backup folder (default: {DEFAULT_BACKUP_DIR})")
    args = parser.parse_args(argv)
    slots = schedule()

    try:
        if args.command == "plan":
            _print_plan(slots)
            return 0
        if args.command == "status":
            print("\n".join(status_lines(slots, history(read_progress(), slots))))
            return 0
        if args.command == "run":
            batch = next_batch(slots) if args.next else args.batch
            if batch is None:
                print("all batches are finished")
                return 0
            started = datetime.now()
            counts = run_batch(batch, slots=slots)
            print(f"batch {batch} done in {datetime.now() - started}: valid {counts['valid']}, "
                  f"excluded attempts {counts['excluded']}, gave up {counts['gave_up']}, "
                  f"already done {counts['skipped']}")
            if DEFAULT_BACKUP_DIR.is_dir():
                rep = backup(DEFAULT_BACKUP_DIR)
                print(f"backup to {DEFAULT_BACKUP_DIR}: copied {rep.copied}, already backed up {rep.unchanged}")
                for e in rep.errors:
                    print(f"ERROR {e}")
                return 0 if not rep.errors else 1
            print(f"WARNING backup folder {DEFAULT_BACKUP_DIR} not found; run 'collect.py backup --to <folder>'")
            return 0
        if args.command == "verify":
            rep = verify(slots=slots, check_hashes=not args.no_hashes)
            print("\n".join(rep.lines))
            for w in rep.warnings[:20]:
                print(f"WARNING {w}")
            for e in rep.errors[:50]:
                print(f"ERROR {e}")
            print("verification passed" if rep.ok else f"verification FAILED ({len(rep.errors)} errors)")
            return 0 if rep.ok else 1
        rep = backup(args.to)
        print(f"backup to {args.to}: copied {rep.copied}, already backed up {rep.unchanged}")
        for e in rep.errors:
            print(f"ERROR {e}")
        return 0 if not rep.errors else 1
    except (CollectionError, runner.RunnerError) as e:
        print(f"ERROR {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
