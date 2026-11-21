"""AgentNet session manifest.

The manifest is the shared record of every captured session, defined in
docs/attack-dataset-contract.md (v1.1). This module is the single place that
knows that schema, so the capture tools, the dataset pipeline and the
hardware team's records are all checked by the same rules.

Command line:
    python scripts/manifest.py init dataset/labels/manifest.csv
    python scripts/manifest.py validate dataset/labels/manifest.csv
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Schema (contract sections 2-5)
# --------------------------------------------------------------------------

REQUIRED_COLUMNS = (
    "session_id",
    "label",
    "attack_id",
    "protocol",
    "transport",
    "environment",
    "capture_file",
    "outcome",
    "start_time",
    "end_time",
)
RECOMMENDED_COLUMNS = (
    "run_id",
    "attack_variant",
    "source_device",
    "destination_device",
    "notes",
)
COLUMNS = REQUIRED_COLUMNS + RECOMMENDED_COLUMNS

# Attack ID -> (official name, protocols the attack may appear on).
ATTACKS: dict[str, tuple[str, frozenset[str]]] = {
    "AT-00": ("Benign Traffic", frozenset({"MCP", "A2A"})),
    "AT-01": ("Tool Poisoning", frozenset({"MCP"})),
    "AT-02": ("Rug Pull", frozenset({"MCP"})),
    "AT-03": ("Prompt Injection via Tool Output", frozenset({"MCP"})),
    "AT-04": ("Confused Deputy", frozenset({"MCP"})),
    "AT-05": ("Data Exfiltration", frozenset({"MCP", "A2A"})),
    "AT-06": ("Agent Card Spoofing", frozenset({"A2A"})),
    "AT-07": ("Unauthorized Physical Actuation", frozenset({"MCP", "A2A"})),
}
BENIGN_ID = "AT-00"
NOT_APPLICABLE = "N/A"

LABELS = frozenset({"Benign", "Attack"})
PROTOCOLS = frozenset({"MCP", "A2A"})
TRANSPORTS = frozenset({"HTTP", "HTTPS"})
ENVIRONMENTS = frozenset({"Software", "Hardware"})
ATTACK_OUTCOMES = frozenset({"Success", "Failed"})

# Spellings found elsewhere in the project docs. Accepted when reading (with a
# warning) so the hardware team's rows are not rejected outright, but never
# written by this module.
LEGACY_BENIGN_ATTACK_ID = NOT_APPLICABLE  # contract column table says "N/A"
LEGACY_FAILED = "Failure"                 # attack-taxonomy.md says "Failure"

# Contract section 4: <PROTOCOL>-<ENV>-B<number> or <PROTOCOL>-<ENV>-AT<nn>-<number>
# ENV is S (Software) or H (Hardware) so the two datasets can be merged without
# ID clashes. Numbers have at least 4 digits (~2,500 benign sessions planned).
SESSION_ID_PATTERN = re.compile(
    r"^(?P<proto>MCP|A2A)-(?P<env>[SH])-(?:B\d{4,}|AT(?P<at>0[1-7])-\d{4,})$"
)
ENV_LETTERS = {"S": "Software", "H": "Hardware"}

# Contract section 5: <protocol>_<attack-id>_<environment>_<run-number>.pcapng
CAPTURE_FILE_PATTERN = re.compile(
    r"^(?P<proto>mcp|a2a)_(?P<kind>benign|at0[1-7])_"
    r"(?P<env>software|hardware)_\d{3,}\.pcapng$"
)

# Cells starting with these are run as formulas by Excel/LibreOffice
# ("CSV injection"). Only free-text columns can contain them.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
FREE_TEXT_COLUMNS = RECOMMENDED_COLUMNS


class ManifestError(ValueError):
    """Raised when a record or manifest file breaks the contract."""


@dataclass
class Report:
    """Result of checking a manifest: errors break the contract, warnings
    are allowed but should be reviewed."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def timestamp(dt: datetime) -> str:
    """Format a time the way the manifest stores it: ISO 8601, local time
    with its UTC offset, millisecond precision.

    The offset makes every timestamp unambiguous, and milliseconds keep short
    sessions (under a second) distinguishable when several share one capture.
    """
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ManifestError("timestamps must be timezone-aware (include a UTC offset)")
    return dt.isoformat(timespec="milliseconds")


def now() -> str:
    """Current local time in manifest format."""
    return timestamp(datetime.now().astimezone())


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _is_aware(dt: datetime) -> bool:
    return dt.tzinfo is not None and dt.utcoffset() is not None


def sanitize_free_text(value: str) -> str:
    """Make a free-text cell safe to open in a spreadsheet.

    Newlines become spaces (multi-line cells break simple CSV readers) and a
    leading formula character is neutralised with an apostrophe.
    """
    value = " ".join(value.splitlines()).strip()
    if value.startswith(FORMULA_PREFIXES):
        value = "'" + value
    return value


# --------------------------------------------------------------------------
# Checking
# --------------------------------------------------------------------------

def check_record(rec: dict[str, str]) -> Report:
    """Check one row on its own (cross-row rules are in check_records)."""
    report = Report()
    err, warn = report.errors.append, report.warnings.append

    for col, value in rec.items():
        if value != value.strip():
            err(f"{col}: leading or trailing spaces in {value!r}")

    missing = [c for c in REQUIRED_COLUMNS if not rec.get(c, "").strip()]
    if missing:
        err(f"missing required value(s): {', '.join(missing)}")
        return report

    sid = rec["session_id"]
    label = rec["label"]
    attack_id = rec["attack_id"]
    proto = rec["protocol"]
    outcome = rec["outcome"]

    if label not in LABELS:
        err(f"label must be one of {sorted(LABELS)}, got {label!r}")
    if proto not in PROTOCOLS:
        err(f"protocol must be one of {sorted(PROTOCOLS)}, got {proto!r}")
    if rec["transport"] not in TRANSPORTS:
        err(f"transport must be one of {sorted(TRANSPORTS)}, got {rec['transport']!r}")
    if rec["environment"] not in ENVIRONMENTS:
        err(f"environment must be one of {sorted(ENVIRONMENTS)}, got {rec['environment']!r}")

    # Attack ID, label, outcome and protocol must agree with each other.
    if attack_id == LEGACY_BENIGN_ATTACK_ID and label == "Benign":
        warn(f"attack_id {attack_id!r} for benign traffic; the contract's ID table uses {BENIGN_ID!r}")
        attack_id = BENIGN_ID
    if attack_id not in ATTACKS:
        err(f"attack_id must be one of {sorted(ATTACKS)}, got {attack_id!r}")
    else:
        allowed_protocols = ATTACKS[attack_id][1]
        if proto in PROTOCOLS and proto not in allowed_protocols:
            err(f"{attack_id} is not defined for {proto} (allowed: {sorted(allowed_protocols)})")

        if attack_id == BENIGN_ID:
            if label != "Benign":
                err(f"{BENIGN_ID} is benign traffic but label is {label!r}")
            if outcome != NOT_APPLICABLE:
                err(f"benign sessions have outcome {NOT_APPLICABLE!r}, got {outcome!r}")
            variant = rec.get("attack_variant", "")
            if variant not in ("", NOT_APPLICABLE):
                err(f"benign sessions have attack_variant {NOT_APPLICABLE!r}, got {variant!r}")
        else:
            if label != "Attack":
                err(f"{attack_id} is an attack but label is {label!r}")
            if outcome == LEGACY_FAILED:
                warn(f"outcome {outcome!r}; the contract spells it 'Failed'")
            elif outcome not in ATTACK_OUTCOMES:
                err(f"attack outcome must be one of {sorted(ATTACK_OUTCOMES)}, got {outcome!r}")

    # Session ID format, and agreement with protocol and attack.
    m = SESSION_ID_PATTERN.match(sid)
    if not m:
        err(f"session_id {sid!r} does not match the contract format (e.g. MCP-S-B0001, MCP-S-AT01-0001)")
    else:
        if m["proto"] != proto:
            err(f"session_id {sid!r} says {m['proto']} but protocol is {proto!r}")
        id_env = ENV_LETTERS[m["env"]]
        if rec["environment"] in ENVIRONMENTS and id_env != rec["environment"]:
            err(f"session_id {sid!r} says {id_env} but environment is {rec['environment']!r}")
        id_attack = f"AT-{m['at']}" if m["at"] else BENIGN_ID
        if attack_id in ATTACKS and id_attack != attack_id:
            err(f"session_id {sid!r} implies {id_attack} but attack_id is {attack_id!r}")

    # Capture file name, and agreement with protocol, attack and environment.
    cap = rec["capture_file"]
    if Path(cap).name != cap:
        err(f"capture_file must be a bare file name, not a path: {cap!r}")
    else:
        m = CAPTURE_FILE_PATTERN.match(cap)
        if not m:
            err(f"capture_file {cap!r} does not match <protocol>_<attack-id>_<environment>_<run>.pcapng")
        else:
            if m["proto"] != proto.lower():
                err(f"capture_file {cap!r} says {m['proto']} but protocol is {proto!r}")
            file_attack = BENIGN_ID if m["kind"] == "benign" else f"AT-{m['kind'][2:]}"
            if attack_id in ATTACKS and file_attack != attack_id:
                err(f"capture_file {cap!r} implies {file_attack} but attack_id is {attack_id!r}")
            if m["env"] != rec["environment"].lower():
                err(f"capture_file {cap!r} says {m['env']} but environment is {rec['environment']!r}")

    # Timestamps.
    start, end = _parse_time(rec["start_time"]), _parse_time(rec["end_time"])
    if start is None:
        err(f"start_time is not ISO 8601: {rec['start_time']!r}")
    if end is None:
        err(f"end_time is not ISO 8601: {rec['end_time']!r}")
    if start and end:
        if _is_aware(start) != _is_aware(end):
            err("start_time and end_time mix timestamps with and without a UTC offset")
        elif end < start:
            err(f"end_time {rec['end_time']} is before start_time {rec['start_time']}")

    for col in FREE_TEXT_COLUMNS:
        if rec.get(col, "").startswith(FORMULA_PREFIXES):
            warn(f"{col} starts with a spreadsheet formula character: {rec[col]!r}")

    return report


def check_records(records: list[dict[str, str]]) -> Report:
    """Check every row, then the rules that span rows."""
    report = Report()

    for line, rec in enumerate(records, start=2):  # line 1 is the header
        r = check_record(rec)
        sid = rec.get("session_id") or f"line {line}"
        report.errors += [f"line {line} ({sid}): {e}" for e in r.errors]
        report.warnings += [f"line {line} ({sid}): {w}" for w in r.warnings]

    # Session IDs must never be reused.
    seen: dict[str, int] = {}
    for line, rec in enumerate(records, start=2):
        sid = rec.get("session_id", "")
        if sid in seen:
            report.errors.append(f"line {line}: session_id {sid!r} already used on line {seen[sid]}")
        elif sid:
            seen[sid] = line

    # One timezone convention throughout.
    kinds = set()
    for rec in records:
        for col in ("start_time", "end_time"):
            t = _parse_time(rec.get(col, ""))
            if t:
                kinds.add(_is_aware(t))
    if len(kinds) > 1:
        report.errors.append("timestamps mix values with and without a UTC offset; use one convention")

    # Sessions sharing a capture file must not overlap in time, otherwise
    # their packets cannot be told apart.
    by_file: dict[str, list[tuple[datetime, datetime, str]]] = {}
    for rec in records:
        s, e = _parse_time(rec.get("start_time", "")), _parse_time(rec.get("end_time", ""))
        if s and e and _is_aware(s) == _is_aware(e) and e >= s:
            by_file.setdefault(rec.get("capture_file", ""), []).append((s, e, rec.get("session_id", "")))
    for cap, spans in by_file.items():
        if len(spans) < 2 or len(kinds) > 1:
            continue
        spans.sort()
        for (s1, e1, id1), (s2, _e2, id2) in zip(spans, spans[1:]):
            if s2 < e1:
                report.errors.append(f"{id1} and {id2} overlap in time inside the same capture file {cap!r}")

    return report


# --------------------------------------------------------------------------
# Reading and writing
# --------------------------------------------------------------------------

def _check_header(header: list[str] | None) -> list[str]:
    if not header:
        return ["file is empty or has no header row"]
    errors = []
    dupes = sorted({c for c in header if header.count(c) > 1})
    if dupes:
        errors.append(f"duplicate column(s): {', '.join(dupes)}")
    missing = [c for c in REQUIRED_COLUMNS if c not in header]
    if missing:
        errors.append(f"missing required column(s): {', '.join(missing)}")
    unknown = [c for c in header if c not in COLUMNS]
    if unknown:
        errors.append(
            f"unknown column(s): {', '.join(unknown)} "
            "(schema changes must be agreed by both team members first)"
        )
    return errors


def load(path: str | Path) -> tuple[list[dict[str, str]], Report]:
    """Read a manifest and check it. Returns the rows and a report."""
    report = Report()
    # utf-8-sig also accepts the byte-order mark Excel adds when saving.
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        report.errors += _check_header(reader.fieldnames)
        if report.errors:
            return [], report
        records = []
        for line, row in enumerate(reader, start=2):
            if None in row:
                report.errors.append(f"line {line}: more values than columns")
                continue
            if any(v is None for v in row.values()):
                report.errors.append(f"line {line}: fewer values than columns")
                continue
            records.append({c: row.get(c, "") for c in COLUMNS})
    checked = check_records(records)
    report.errors += checked.errors
    report.warnings += checked.warnings
    return records, report


def init(path: str | Path) -> Path:
    """Create an empty manifest containing only the header row.

    Refuses to touch an existing file so recorded sessions can never be
    wiped by accident.
    """
    path = Path(path)
    if path.exists():
        raise ManifestError(f"{path} already exists; not overwriting it")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(COLUMNS)
    return path


def append(path: str | Path, record: dict[str, str]) -> dict[str, str]:
    """Validate one session record and add it to the manifest.

    The row is checked on its own and against every row already in the file
    (duplicate IDs, overlapping sessions in one capture). Nothing is written
    unless all checks pass. Returns the row exactly as written.
    """
    path = Path(path)
    unknown = set(record) - set(COLUMNS)
    if unknown:
        raise ManifestError(f"unknown field(s): {', '.join(sorted(unknown))}")

    row = {c: str(record.get(c, "")).strip() for c in COLUMNS}
    for col in FREE_TEXT_COLUMNS:
        row[col] = sanitize_free_text(row[col])

    own = check_record(row)
    if own.errors:
        raise ManifestError("; ".join(own.errors))

    if not path.exists():
        init(path)
    existing, report = load(path)
    if report.errors:
        raise ManifestError(f"{path} is invalid, fix it before adding rows: " + "; ".join(report.errors))

    combined = check_records(existing + [row])
    if combined.errors:
        raise ManifestError("; ".join(combined.errors))

    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=COLUMNS).writerow(row)
    return row


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    usage = "usage: python scripts/manifest.py {init|validate} <manifest.csv>"
    if len(argv) != 2 or argv[0] not in ("init", "validate"):
        print(usage, file=sys.stderr)
        return 2
    command, path = argv

    if command == "init":
        try:
            print(f"created {init(path)}")
            return 0
        except ManifestError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    if not Path(path).is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 1
    records, report = load(path)
    for e in report.errors:
        print(f"ERROR   {e}")
    for w in report.warnings:
        print(f"WARNING {w}")
    print(f"{len(records)} session(s), {len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
