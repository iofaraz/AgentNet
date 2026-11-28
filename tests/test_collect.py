"""Tests for the benign collection run (scripts/collect.py).

Schedule and resume logic are tested with a fake session runner; verify and
backup on hand-made files; one test runs a real two-session batch end to end.
"""

import csv
from collections import Counter

import pytest

import collect as C
import manifest
import runner
import testbed

SMALL_MIX = {"mcp-scripted": 0.5, "a2a": 0.5}


# ======================================================================
# Schedule
# ======================================================================

def test_agreed_schedule_has_exact_mix_in_every_batch():
    slots = C.schedule()
    assert len(slots) == 2500
    assert [s.index for s in slots] == list(range(2500))
    for batch in range(1, 11):
        kinds = Counter(s.kind for s in slots if s.batch == batch)
        assert kinds == {"mcp-scripted": 100, "mcp-llm": 75, "a2a": 75}


def test_seeds_never_repeat_within_a_kind_and_skip_the_pilot():
    slots = C.schedule()
    for kind in C.BENIGN_MIX:
        seeds = [s.seed for s in slots if s.kind == kind]
        assert seeds == list(range(C.SEED_START, C.SEED_START + len(seeds)))
    assert C.SEED_START > 100      # the pilot used seeds 1-100


def test_schedule_is_reproducible_and_shuffled_per_batch():
    a, b = C.schedule(), C.schedule()
    assert a == b
    orders = {tuple(s.kind for s in a if s.batch == n) for n in range(1, 11)}
    assert len(orders) == 10                      # every batch in a different order
    first = [s.kind for s in a if s.batch == 1]
    assert first != sorted(first)                 # kinds interleaved, not in blocks


def test_kinds_per_batch_rounds_to_the_batch_size():
    assert C.kinds_per_batch(250, C.BENIGN_MIX) == {"mcp-scripted": 100, "mcp-llm": 75, "a2a": 75}
    assert sum(C.kinds_per_batch(7, {"mcp-scripted": 1 / 3, "mcp-llm": 1 / 3, "a2a": 1 / 3}).values()) == 7
    with pytest.raises(ValueError):
        C.kinds_per_batch(10, {"mcp-scripted": 0.5, "a2a": 0.4})


@pytest.mark.parametrize("kwargs", [dict(total=250, size=100), dict(total=0, size=10),
                                    dict(mix={"mcp-scripted": 0.5, "nope": 0.5})])
def test_bad_schedules_are_rejected(kwargs):
    with pytest.raises(ValueError):
        C.schedule(**kwargs)


def test_run_ids_follow_the_runner_rules():
    assert C.run_id_for(1) == "S-BENIGN3-01"
    assert C.run_id_for(1) != "S-BENIGN-01"        # the pilot's run ID is never reused
    runner.SessionRunner(run_id=C.run_id_for(10))   # accepted by the runner's run_id check


# ======================================================================
# Running batches (fake runner)
# ======================================================================

class FakeRunner:
    """Returns scripted results; statuses is a list consumed one per session."""

    def __init__(self, run_id, statuses=None):
        self.run_id = run_id
        self.statuses = list(statuses or [])
        self.calls = []
        self.n = Counter()

    def run(self, scenario):
        kind, seed = scenario
        self.calls.append(scenario)
        status = self.statuses.pop(0) if self.statuses else runner.VALID
        if status == "interrupt":
            raise KeyboardInterrupt
        prefix = "MCP-S-B" if kind.startswith("mcp") else "A2A-S-B"
        self.n[prefix] += 1
        reason = "" if status == runner.VALID else "scenario error: RuntimeError: boom"
        return runner.SessionResult(f"{prefix}{self.n[prefix]:04d}", "x.pcapng", status, reason, None, None)


def _run(tmp_path, batch=1, statuses=None, **kw):
    slots = kw.pop("slots", C.schedule(total=4, size=2, mix=SMALL_MIX))
    fake = FakeRunner(C.run_id_for(batch), statuses)
    counts = C.run_batch(batch, slots=slots, session_runner=fake, build=lambda k, s: (k, s),
                         progress_path=tmp_path / "progress.csv", servers=_null(), preflight=kw.pop("preflight", None),
                         backend_check=kw.pop("backend_check", None),
                         echo=lambda _: None, **kw)
    return counts, fake, C.read_progress(tmp_path / "progress.csv")


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_batch_runs_only_its_own_slots_and_records_them(tmp_path):
    counts, fake, rows = _run(tmp_path, batch=2)
    slots = C.schedule(total=4, size=2, mix=SMALL_MIX)
    assert fake.calls == [(s.kind, s.seed) for s in slots if s.batch == 2]
    assert counts["valid"] == 2
    assert [r["index"] for r in rows] == ["2", "3"]
    assert {r["run_id"] for r in rows} == {C.run_id_for(2)}
    assert all(r["session_id"] and r["status"] == "valid" for r in rows)


def test_rerunning_a_finished_batch_does_nothing(tmp_path):
    _run(tmp_path)
    counts, fake, rows = _run(tmp_path)
    assert fake.calls == [] and counts["skipped"] == 2 and len(rows) == 2


def test_excluded_session_is_retried_until_valid(tmp_path):
    counts, fake, rows = _run(tmp_path, statuses=["excluded", "valid"])
    assert len(fake.calls) == 3                       # slot 0 twice, slot 1 once
    assert fake.calls[0] == fake.calls[1]             # retry uses the same kind and seed
    assert [r["attempt"] for r in rows] == ["1", "2", "1"]
    assert counts["valid"] == 2 and counts["excluded"] == 1


def test_slot_is_given_up_after_max_attempts(tmp_path):
    counts, fake, rows = _run(tmp_path, statuses=["excluded"] * 3, max_attempts=3, max_consecutive=10)
    assert counts["gave_up"] == 1 and counts["valid"] == 1
    assert C.slot_state([r for r in rows if r["index"] == "0"]) == "gave_up"
    counts, fake, _ = _run(tmp_path)                  # resume: the given-up slot is not retried
    assert fake.calls == []


def test_consecutive_exclusions_stop_the_batch(tmp_path):
    slots = C.schedule(total=4, size=4, mix=SMALL_MIX)
    with pytest.raises(C.CollectionError, match="in a row"):
        _run(tmp_path, statuses=["excluded"] * 4, slots=slots, max_consecutive=4, max_attempts=3)
    rows = C.read_progress(tmp_path / "progress.csv")
    assert len(rows) == 4                             # every attempt was recorded before stopping


def test_a_valid_session_resets_the_consecutive_count(tmp_path):
    # excluded, valid, excluded, valid: never two in a row, so the batch must finish
    counts, _, _ = _run(tmp_path, statuses=["excluded", "valid", "excluded", "valid"], max_consecutive=2)
    assert counts["valid"] == 2 and counts["excluded"] == 2


def test_interrupted_attempt_is_recorded_and_does_not_count(tmp_path):
    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, statuses=["interrupt"])
    rows = C.read_progress(tmp_path / "progress.csv")
    assert rows[0]["reason"] == C.INTERRUPTED
    assert C.slot_state(rows, max_attempts=1) == "pending"
    counts, fake, _ = _run(tmp_path)                  # resume completes the batch
    assert counts["valid"] == 2


def test_progress_from_a_different_schedule_is_refused(tmp_path):
    _run(tmp_path)
    other = C.schedule(total=4, size=2, mix={"mcp-scripted": 1.0})
    with pytest.raises(C.CollectionError, match="schedule"):
        _run(tmp_path, slots=other)


def test_runner_with_wrong_run_id_is_refused(tmp_path):
    slots = C.schedule(total=4, size=2, mix=SMALL_MIX)
    with pytest.raises(ValueError, match="run_id"):
        C.run_batch(1, slots=slots, session_runner=FakeRunner(C.run_id_for(2)), build=lambda k, s: (k, s),
                    progress_path=tmp_path / "p.csv", servers=_null(), preflight=None)


def test_preflight_runs_only_when_llm_sessions_are_pending(tmp_path):
    calls = []
    slots = C.schedule(total=2, size=2, mix={"mcp-scripted": 1.0})
    C.run_batch(1, slots=slots, session_runner=FakeRunner(C.run_id_for(1)), build=lambda k, s: (k, s),
                progress_path=tmp_path / "p.csv", servers=_null(), preflight=lambda: calls.append(1),
                echo=lambda _: None)
    assert calls == []
    with pytest.raises(C.CollectionError, match="Ollama"):
        def down():
            raise C.CollectionError("Ollama is not ready")
        _run(tmp_path / "x", preflight=down)


def _ollama_up():
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3)
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ollama_up(), reason="Ollama not running")
def test_real_ollama_preflight_passes():
    C.check_ollama()


def test_real_ollama_preflight_reports_a_missing_model(monkeypatch):
    import agent
    monkeypatch.setattr(agent, "DEFAULT_MODEL", "no-such-model:0b")
    with pytest.raises(C.CollectionError, match="no-such-model"):
        C.check_ollama()


def test_next_batch(tmp_path):
    slots = C.schedule(total=4, size=2, mix=SMALL_MIX)
    p = tmp_path / "progress.csv"
    assert C.next_batch(slots, p) == 1
    _run(tmp_path)
    assert C.next_batch(slots, p) == 2
    _run(tmp_path, batch=2)
    assert C.next_batch(slots, p) is None


# ======================================================================
# Verify and backup (hand-made files)
# ======================================================================

def _verify(**kw):
    """verify() without the repository's real excluded-runs file."""
    kw.setdefault("excluded_runs_path", kw["progress_path"].parent / "no-excluded-runs.csv")
    return C.verify(**kw)


def _backup(dest, **kw):
    """backup() without the repository's real pilot/excluded-runs files."""
    return C.backup(dest, extra_labels=(), **kw)


def _make_dataset(tmp_path):
    """One valid MCP session for slot 0 of a 2-slot scripted schedule, plus one excluded attempt."""
    slots = C.schedule(total=2, size=2, mix={"mcp-scripted": 1.0})
    rid, seed = C.run_id_for(1), slots[0].seed
    pcaps = tmp_path / "pcaps"
    pcaps.mkdir(parents=True)
    paths = dict(manifest_path=tmp_path / "manifest.csv", log_path=tmp_path / "log.csv",
                 capture_dir=pcaps, progress_path=tmp_path / "progress.csv")
    log = []
    for n, (status, body) in enumerate([("excluded", b"broken"), ("valid", b"packets")], start=1):
        name = f"mcp_benign_software_{n:04d}.pcapng"
        (pcaps / name).write_bytes(body)
        log.append({c: "" for c in runner.LOG_COLUMNS} | {
            "session_id": f"MCP-S-B{n:04d}", "run_id": rid, "scenario": "benign-mcp-scripted",
            "status": status, "capture_file": name, "sha256": C.capture.sha256_of(pcaps / name),
            "packets_captured": "40"})
        C._append_progress(paths["progress_path"], {
            "index": 0, "batch": 1, "run_id": rid, "kind": "mcp-scripted", "seed": seed,
            "attempt": n, "session_id": f"MCP-S-B{n:04d}", "status": status,
            "reason": "" if status == "valid" else "scenario error: X"})
    with open(paths["log_path"], "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=runner.LOG_COLUMNS)
        w.writeheader()
        w.writerows(log)
    manifest.append(paths["manifest_path"], {
        "session_id": "MCP-S-B0002", "label": "Benign", "attack_id": "AT-00", "protocol": "MCP",
        "transport": "HTTP", "environment": "Software", "capture_file": "mcp_benign_software_0002.pcapng",
        "outcome": "N/A", "start_time": "2026-11-23T10:00:00.000+05:00",
        "end_time": "2026-11-23T10:00:02.500+05:00", "run_id": rid, "attack_variant": "N/A",
        "source_device": "", "destination_device": "",
        "notes": f"scenario=benign-mcp-scripted; seed={seed}; principal=alice"})
    return slots, paths


def test_verify_passes_on_consistent_data(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    rep = _verify(slots=slots, **paths)
    assert rep.ok, rep.errors
    text = "\n".join(rep.lines)
    assert "mcp-scripted" in text and "scenario error x1" in text


def test_verify_detects_a_changed_capture(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    p = paths["capture_dir"] / "mcp_benign_software_0002.pcapng"
    p.write_bytes(b"tampered")
    rep = _verify(slots=slots, **paths)
    assert any("SHA-256" in e for e in rep.errors)
    assert _verify(slots=slots, check_hashes=False, **paths).ok


def test_verify_detects_missing_valid_capture_and_wrong_seed(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    (paths["capture_dir"] / "mcp_benign_software_0002.pcapng").unlink()
    rep = _verify(slots=slots, **paths)
    assert any("missing" in e for e in rep.errors)

    slots, paths = _make_dataset(tmp_path / "b")
    text = paths["manifest_path"].read_text(encoding="utf-8").replace(f"seed={slots[0].seed};", "seed=9;")
    paths["manifest_path"].write_text(text, encoding="utf-8")
    rep = _verify(slots=slots, **paths)
    assert any(f"seed {slots[0].seed}" in e for e in rep.errors)


def test_verify_lists_excluded_runs_and_chain_share(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    excl = tmp_path / "excluded.csv"
    excl.write_text("run_id,environment,reason,decided_on\n"
                    f"{C.run_id_for(1)},Software,pilot,2026-11-23\n", encoding="utf-8")
    rep = _verify(slots=slots, excluded_runs_path=excl, **paths)
    assert rep.ok and any("excluded from the final dataset" in l and "1 manifest rows" in l for l in rep.lines)
    excl.write_text("wrong,header\n", encoding="utf-8")
    assert not _verify(slots=slots, excluded_runs_path=excl, **paths).ok


def test_tool_calls_are_counted_from_notes():
    assert C._tool_calls("scenario=benign-mcp-llm; seed=5; tools=search_files,read_file; tool_errors=0") == 2
    assert C._tool_calls("scenario=benign-mcp-llm; tools=-; finished=True") == 0
    assert C._tool_calls("scenario=benign-mcp-scripted; seed=1") == 0


def test_real_excluded_runs_file_lists_the_pilot():
    runs = C.excluded_runs()
    assert "S-BENIGN-01" in runs and runs["S-BENIGN-01"]["environment"] == "Software"


def test_verify_detects_manifest_and_log_disagreeing(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    text = paths["log_path"].read_text(encoding="utf-8").replace(",valid,", ",excluded,")
    paths["log_path"].write_text(text, encoding="utf-8")
    rep = _verify(slots=slots, **paths)
    assert any("not logged as a valid capture" in e for e in rep.errors)


def test_backup_copies_verifies_and_skips_unchanged(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    dest = tmp_path / "drive"
    dest.mkdir()
    kw = {k: v for k, v in paths.items()} | {"server_log_dir": tmp_path / "nologs"}
    rep = _backup(dest, **kw)
    assert rep.copied == 2 and rep.unchanged == 0 and not rep.errors
    root = dest / "AgentNet-software"
    assert (root / "pcaps" / "mcp_benign_software_0002.pcapng").read_bytes() == b"packets"
    assert {p.name for p in (root / "labels").iterdir()} == {"manifest.csv", "log.csv", "progress.csv"}
    sums = (root / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert "pcaps/mcp_benign_software_0002.pcapng" in sums and "labels/manifest.csv" in sums

    rep = _backup(dest, **kw)
    assert rep.copied == 0 and rep.unchanged == 2

    (root / "pcaps" / "mcp_benign_software_0002.pcapng").write_bytes(b"bad copy")
    rep = _backup(dest, **kw)
    assert rep.copied == 1 and (root / "pcaps" / "mcp_benign_software_0002.pcapng").read_bytes() == b"packets"


def test_backup_refuses_corrupt_source_and_missing_folder(tmp_path):
    slots, paths = _make_dataset(tmp_path)
    (paths["capture_dir"] / "mcp_benign_software_0002.pcapng").write_bytes(b"tampered")
    dest = tmp_path / "drive"
    dest.mkdir()
    rep = _backup(dest, server_log_dir=tmp_path / "nologs", **paths)
    assert any("does not match" in e for e in rep.errors)
    assert not (dest / "AgentNet-software" / "pcaps" / "mcp_benign_software_0002.pcapng").exists()
    with pytest.raises(C.CollectionError, match="does not exist"):
        _backup(tmp_path / "no-such-folder", **paths)


# ======================================================================
# Real batch
# ======================================================================

@pytest.mark.skipif(testbed.MCP_SERVER.in_use(), reason="testbed addresses in use")
def test_real_batch_then_verify_and_backup(tmp_path):
    slots = C.schedule(total=2, size=2, mix={"mcp-scripted": 1.0})
    paths = dict(manifest_path=tmp_path / "m.csv", log_path=tmp_path / "l.csv",
                 capture_dir=tmp_path / "pcaps", progress_path=tmp_path / "progress.csv")
    run = runner.SessionRunner(manifest_path=paths["manifest_path"], log_path=paths["log_path"],
                               capture_dir=paths["capture_dir"], run_id=C.run_id_for(1))
    servers = testbed.running(testbed.MCP_SERVER, log_dir=tmp_path / "logs", run_id=C.run_id_for(1))
    counts = C.run_batch(1, slots=slots, session_runner=run, progress_path=paths["progress_path"],
                         servers=servers, preflight=None, echo=lambda _: None)
    assert counts["valid"] == 2, C.read_progress(paths["progress_path"])
    rep = _verify(slots=slots, **paths)
    assert rep.ok, rep.errors
    dest = tmp_path / "drive"
    dest.mkdir()
    b = _backup(dest, server_log_dir=tmp_path / "logs", **paths)
    assert b.copied == 2 and not b.errors
    assert any((dest / "AgentNet-software" / "server-logs").glob("*.log"))
    assert any((dest / "AgentNet-software" / "server-logs").glob("*_audit.jsonl"))


def test_server_log_label_gives_resumed_batches_new_names(tmp_path):
    assert C.server_log_label("S-BENIGN3-02", tmp_path) == "S-BENIGN3-02"
    (tmp_path / "S-BENIGN3-02_mcp-server.log").write_text("")
    assert C.server_log_label("S-BENIGN3-02", tmp_path) == "S-BENIGN3-02_part2"
    (tmp_path / "S-BENIGN3-02_part2_mcp-server.log").write_text("")
    assert C.server_log_label("S-BENIGN3-02", tmp_path) == "S-BENIGN3-02_part3"
    assert C.server_log_label("S-BENIGN3-03", tmp_path) == "S-BENIGN3-03"


def test_backend_outage_attempts_do_not_use_up_tries(tmp_path):
    # Every session fails while "the tunnel is down"; the check reports a recovery each time.
    slots = C.schedule(total=2, size=2, mix={"mcp-llm": 1.0})
    fails = [runner.EXCLUDED] * 6
    checks = []
    def check(echo):
        checks.append(1)
        return "recovered" if len(checks) <= 6 else "up"
    counts, fake, _ = _run(tmp_path, statuses=fails, slots=slots, backend_check=check)
    assert counts["valid"] == 2 and counts["gave_up"] == 0       # 6 outage attempts, then success
    rows = C.read_progress(tmp_path / "progress.csv")
    assert sum(r["reason"].startswith(C.BACKEND_DOWN) for r in rows) == 6


def test_backend_that_stays_down_stops_the_batch(tmp_path):
    slots = C.schedule(total=2, size=2, mix={"mcp-llm": 1.0})
    with pytest.raises(C.CollectionError, match="did not come back"):
        _run(tmp_path, statuses=[runner.EXCLUDED], slots=slots, backend_check=lambda echo: "down")
    rows = C.read_progress(tmp_path / "progress.csv")
    assert len(rows) == 1 and rows[0]["reason"].startswith(C.BACKEND_DOWN)
    assert C.slot_state(rows) == "pending"                        # the slot keeps all its tries


def test_real_session_failures_still_count_when_backend_is_up(tmp_path):
    slots = C.schedule(total=2, size=2, mix={"mcp-llm": 1.0})
    counts, _, _ = _run(tmp_path, statuses=[runner.EXCLUDED] * 3, slots=slots, backend_check=lambda echo: "up")
    assert counts["gave_up"] == 1


def test_scripted_failures_never_wait_for_the_backend(tmp_path):
    slots = C.schedule(total=2, size=2, mix={"mcp-scripted": 1.0})
    def check(echo):
        raise AssertionError("scripted sessions do not need the LLM")
    _run(tmp_path, statuses=[runner.EXCLUDED], slots=slots, backend_check=check)


def test_ollama_backend_check_waits_and_reports():
    seq = iter([False, False, True])
    out = C.ollama_backend_check(lambda m: None, reachable=lambda: next(seq), wait_s=100, poll_s=10, sleep=lambda s: None)
    assert out == "recovered"
    assert C.ollama_backend_check(lambda m: None, reachable=lambda: True) == "up"
    assert C.ollama_backend_check(lambda m: None, reachable=lambda: False, wait_s=30, poll_s=10,
                                  sleep=lambda s: None) == "down"
