"""Tests for the benign scenario catalogue (scripts/benign_scenarios.py).

Plan tests generate thousands of plans without a network and check the
realism rules. Execution tests run real captured sessions.
"""

import asyncio
import re
import sys
from collections import Counter

import pytest

import benign_scenarios as B
import manifest
import runner
import testbed

sys.path.insert(0, str(testbed.TESTBED / "mcp"))
import audit as A          # noqa: E402
import workspace as W      # noqa: E402

N = 2000
SCRIPTED = [B.plan_mcp_scripted(s) for s in range(1, N + 1)]
ROLES = {p: W.World().users[p] for p in W.World().users}
PUBLIC = {"get_weather", "calculate", "get_server_status"}
ACTUATORS = {"set_led", "sound_buzzer"}


def role_of(principal):
    return "anonymous" if principal is None else ROLES[principal]


# ======================================================================
# Scripted MCP plans
# ======================================================================

def test_plans_are_reproducible_and_seed_dependent():
    assert B.plan_mcp_scripted(42) == B.plan_mcp_scripted(42)
    assert B.plan_mcp_scripted(42) != B.plan_mcp_scripted(43)
    assert B.plan_task(7, "a2a") == B.plan_task(7, "a2a")


def test_every_identity_appears_with_roughly_the_planned_weights():
    counts = Counter(p.principal for p in SCRIPTED)
    total = sum(B.PRINCIPAL_WEIGHTS.values())
    assert set(counts) == set(B.PRINCIPAL_WEIGHTS)
    for principal, weight in B.PRINCIPAL_WEIGHTS.items():
        expected = N * weight / total
        assert abs(counts[principal] - expected) < 0.25 * expected, (principal, counts[principal], expected)


def test_both_handshakes_and_timings_occur():
    modes = Counter(p.mode for p in SCRIPTED)
    assert 0.6 < modes["auto"] / N < 0.8 and modes["legacy"] > 0
    timings = Counter(p.timing for p in SCRIPTED)
    assert set(timings) == {"interactive", "automation"} and min(timings.values()) > 0.4 * N


def test_step_counts_and_delays_are_bounded():
    lengths = Counter(len(p.steps) for p in SCRIPTED)
    assert min(lengths) == 1 and max(lengths) == 8 and len(lengths) == 8
    for p in SCRIPTED:
        for s in p.steps:
            assert 0 < s.delay <= 6.0
            if p.timing == "automation":
                assert s.delay <= 0.3


def test_honest_mistakes_occur_at_about_five_percent():
    steps = [s for p in SCRIPTED for s in p.steps]
    rate = sum(s.mistake for s in steps) / len(steps)
    assert 0.03 < rate < 0.07, rate


def test_normal_steps_respect_the_role():
    """Outside of deliberate mistakes, nobody plans a call their role forbids."""
    for p in SCRIPTED:
        role = role_of(p.principal)
        for s in p.steps:
            if s.mistake:
                continue
            if role == "anonymous":
                assert s.tool in PUBLIC, (p.seed, s)
            if s.tool in ACTUATORS:
                assert role in ("operator", "admin"), (p.seed, s)
            if s.tool == "read_file" and s.args["path"].startswith(W.RESTRICTED_FOLDERS):
                assert role == "admin", (p.seed, s)


def test_admins_legitimately_read_restricted_files():
    # So that "reads a secret file" is not by itself a sign of attack.
    legit = [s for p in SCRIPTED if role_of(p.principal) == "admin" for s in p.steps
             if s.tool == "read_file" and s.args["path"].startswith(W.RESTRICTED_FOLDERS)]
    assert len(legit) >= 10


def test_note_references_follow_a_created_note():
    for p in SCRIPTED:
        has_note = False
        for s in p.steps:
            if s.tool == "create_note" and not s.mistake:
                has_note = True
            if s.args.get("note_id") == B.NOTE_REF:
                assert has_note, (p.seed, p.steps)
            if s.tool == "delete_note" and s.args.get("note_id") == B.NOTE_REF:
                has_note = False


def test_sessions_differ():
    # Short polling sessions (one sensor read, one status check) legitimately
    # repeat — dashboards do exactly that — but no plan may dominate.
    # Measured over 2,000 plans: 93% of full plans distinct, top 0.35%;
    # the most frequent call sequence alone (one sensor read) 3.55%.
    calls = Counter(tuple((s.tool, tuple(sorted(s.args.items()))) for s in p.steps) for p in SCRIPTED)
    full = Counter((p.principal, p.mode, p.timing, p.list_tools_first,
                    tuple((s.tool, tuple(sorted(s.args.items()))) for s in p.steps)) for p in SCRIPTED)
    assert len(full) / N > 0.85, "what reaches the wire (user, handshake, timing, calls) must be varied"
    assert full.most_common(1)[0][1] / N < 0.015
    assert calls.most_common(1)[0][1] / N < 0.05, "no call sequence may dominate"
    single = sum(len(p.steps) == 1 for p in SCRIPTED) / N
    assert 0.20 < single < 0.35, single


def test_kinds_use_independent_random_streams():
    # Regression: the same seed once gave mcp-llm and a2a the same user, task and model seed.
    same = sum(B.plan_task(s, "mcp-llm").tasks[0] == B.plan_task(s, "a2a").tasks[0]
               and B.plan_task(s, "mcp-llm").principal == B.plan_task(s, "a2a").principal for s in range(1, 300))
    assert same < 30
    assert all(B.plan_task(s, "mcp-llm").llm_seed != B.plan_task(s, "a2a").llm_seed for s in range(1, 300))


def test_planned_arguments_are_valid_for_the_server():
    """Every non-mistake call would be accepted by the server's own validation."""
    world = W.World()
    for p in SCRIPTED[:400]:
        caller = W.ANONYMOUS if p.principal is None else world.caller(f"Bearer {world.token_for(p.principal)}")
        note_id = None
        for s in p.steps:
            if s.mistake:
                continue
            args = dict(s.args)
            if args.get("note_id") == B.NOTE_REF:
                if note_id is None:
                    continue
                args["note_id"] = note_id
            if s.tool in PUBLIC:
                fn = {"get_weather": lambda **a: world.weather(**a),
                      "calculate": lambda **a: W.World.calculate(**a),
                      "get_server_status": lambda **a: world.status(14)}[s.tool]
                fn(**args)
                continue
            result = getattr(world, s.tool)(caller, **args)
            if s.tool == "create_note":
                note_id = result["id"]
            if s.tool == "delete_note":
                note_id = None


# ======================================================================
# Task plans (LLM over MCP, A2A)
# ======================================================================

TASKS = [B.plan_task(s, k) for s in range(1, 801) for k in ("mcp-llm", "a2a")]


def test_tasks_are_fully_filled():
    for t in (task for plan in TASKS for task in plan.tasks):
        assert "{" not in t and "}" not in t, t


def test_task_counts_per_kind():
    assert all(len(p.tasks) == 1 for p in TASKS[0::2])          # mcp-llm
    assert {len(p.tasks) for p in TASKS[1::2]} == {1, 2, 3, 4}  # a2a


def test_anonymous_and_viewer_tasks_stay_in_role_except_mistakes():
    operator_like = re.compile(r"LED|buzzer")
    admin_like = re.compile(r"payroll|api_keys")
    for p in TASKS:
        role = role_of(p.principal)
        beyond = sum(bool(operator_like.search(t)) for t in p.tasks) if role in ("anonymous", "viewer") else 0
        assert beyond == p.beyond_role, (p.seed, p.tasks)
        if role != "admin":
            assert not any(admin_like.search(t) for t in p.tasks)


def test_task_mistake_rate():
    eligible = [p for p in TASKS if role_of(p.principal) in ("anonymous", "viewer")]
    rate = sum(p.beyond_role for p in eligible) / sum(len(p.tasks) for p in eligible)
    assert 0.02 < rate < 0.09, rate


def test_chain_tasks_are_about_forty_percent_and_recorded():
    tasks = [t for p in TASKS for t in p.tasks]
    chained = sum(p.chain_tasks for p in TASKS)
    assert 0.30 < chained / len(tasks) < 0.50, chained / len(tasks)
    assert all(f"chain_tasks={p.chain_tasks}" in p.summary() for p in TASKS[:50])
    assert all(0 <= p.chain_tasks <= len(p.tasks) for p in TASKS)


def test_every_role_gets_chain_tasks():
    for role in ("anonymous", "viewer", "operator", "admin"):
        assert any(t in B.CHAIN_TASKS for t in B.tasks_for(role)), role


def test_llm_seeds_differ_between_sessions():
    seeds = [p.llm_seed for p in TASKS]
    assert len(set(seeds)) == len(seeds)


# ======================================================================
# Scenarios
# ======================================================================

@pytest.mark.parametrize("kind", B.KINDS)
def test_built_scenarios_are_valid_benign_scenarios(kind):
    for seed in range(1, 30):
        s = B.build(kind, seed)
        runner.check_scenario(s)
        assert s.attack_id == manifest.BENIGN_ID and s.name == f"benign-{kind}"
        assert s.protocol == B.DRIVERS[kind][0]
        assert s.bpf == testbed.TESTBED_BPF
        ip = s.source_device.split("@")[1]
        assert ip in testbed.addresses.WORKSTATIONS.values()


def test_unknown_kind():
    with pytest.raises(ValueError):
        B.build("mcp-telepathy", 1)


def test_driver_mix_is_declared_for_every_kind():
    # Part 4 must reproduce this mix per protocol (D13).
    assert set(B.DRIVERS) == set(B.KINDS)
    assert {d for _, d in B.DRIVERS.values()} == {"scripted", "llm"}


# ======================================================================
# Real sessions
# ======================================================================

servers_free = pytest.mark.skipif(testbed.MCP_SERVER.in_use() or testbed.A2A_SERVER.in_use(),
                                  reason="testbed addresses in use")


def _seed_where(predicate, limit=5000):
    for seed in range(1, limit):
        if predicate(B.plan_mcp_scripted(seed)):
            return seed
    raise AssertionError("no matching plan")


def expected_calls(plan):
    """The calls a plan sends: a note reference is skipped when no note exists (as run_mcp_plan does)."""
    calls, has_note = [], False
    for s in plan.steps:
        if s.args.get("note_id") == B.NOTE_REF and not has_note:
            continue
        calls.append(s.tool)
        if s.tool == "create_note" and not s.mistake:
            has_note = True
        if s.tool == "delete_note" and s.args.get("note_id") == B.NOTE_REF:
            has_note = False
    return calls


@servers_free
def test_scripted_sessions_run_exactly_as_planned(tmp_path):
    """Captured scripted sessions: valid, and the server saw exactly the planned calls."""
    seeds = [
        _seed_where(lambda p: p.mode == "legacy" and len(p.steps) >= 3),
        _seed_where(lambda p: any(s.mistake for s in p.steps)),
        _seed_where(lambda p: any(s.args.get("note_id") == B.NOTE_REF for s in p.steps)),
        _seed_where(lambda p: p.principal == "dana" and any(
            s.tool == "read_file" and s.args["path"].startswith("secrets/") for s in p.steps)),
    ]
    run = runner.SessionRunner(manifest_path=tmp_path / "m.csv", log_path=tmp_path / "l.csv",
                               capture_dir=tmp_path / "p", run_id="BENIGN-TEST")
    with testbed.running(testbed.MCP_SERVER, log_dir=tmp_path / "logs", run_id="BENIGN-TEST") as servers:
        results = [run.run(B.build("mcp-scripted", s)) for s in seeds]
        audit_path = servers[0].audit_path
    assert all(r.valid for r in results), [r.reason for r in results]
    rows = {r["session_id"]: r for r in manifest.load(tmp_path / "m.csv")[0]}
    entries = A.read(audit_path)
    from datetime import datetime
    for seed, res in zip(seeds, results):
        plan = B.plan_mcp_scripted(seed)
        row = rows[res.session_id]
        assert f"seed={seed};" in row["notes"]
        window = A.between(entries, datetime.fromisoformat(row["start_time"]), datetime.fromisoformat(row["end_time"]))
        assert [e["tool"] for e in window] == expected_calls(plan)
        assert {e["principal"] for e in window} == {plan.principal or "anonymous"}
        mistakes = sum(s.mistake for s in plan.steps)
        assert sum(e["decision"] != "allowed" for e in window) >= mistakes


def _ollama_ready():
    sys.path.insert(0, str(testbed.TESTBED / "llm"))
    import agent
    try:
        asyncio.run(agent.model_digest(agent.DEFAULT_MODEL))
        return True
    except Exception:
        return False


@servers_free
@pytest.mark.skipif(not _ollama_ready(), reason="Ollama model unavailable")
def test_sample_of_every_kind_is_valid_and_varied(tmp_path):
    report = B.run_sample(tmp_path / "sample", per_kind=2)
    assert len(report.rows) == 6
    assert all(r["status"] == "valid" for r in report.rows), report.rows
    assert report.distinct("packets")[0] >= 4, report.rows
    assert manifest.load(tmp_path / "sample" / "manifest.csv")[1].ok
    assert (tmp_path / "sample" / "sample_summary.csv").is_file()
