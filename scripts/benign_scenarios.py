"""Catalogue of benign (AT-00) scenarios.

Every benign session is generated from a seed, so it is varied but
reproducible: the same kind and seed always give the same plan (the
model's own wording and network timing still vary, as in reality).

Kinds (DRIVERS records which driver each uses — attack scenarios in Part 4
must use the same mix per protocol, see open decision D13):

    mcp-scripted  a user's app calls 1-8 MCP tools in a realistic order, with
                  human-like or automation-like pauses
    mcp-llm       the LLM agent completes a natural-language task over MCP
    a2a           a user sends 1-4 requests to the A2A Lab Assistant (which
                  uses the LLM and MCP behind it)

Realism rules built in:
* all identities appear, weighted (alice/bob/dana/reporter-agent/anonymous);
* admins legitimately read admin-only files — reading them is not by itself
  a sign of attack;
* about 5% of steps are honest mistakes (unknown id, forbidden action), so
  "an error happened" is not by itself a sign of attack;
* both MCP client handshakes occur ("auto" = server/discover, "legacy" =
  initialize), as different client implementations would.

Command line:
    python scripts/benign_scenarios.py plans --kind mcp-scripted --count 5
    python scripts/benign_scenarios.py sample --per-kind 3 --out <empty folder>
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import random
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import manifest
import runner
import testbed

for _sub in ("mcp", "llm", "a2a"):
    _p = str(testbed.TESTBED / _sub)
    if _p not in sys.path:
        sys.path.append(_p)

import workspace as W  # noqa: E402

KINDS = ("mcp-scripted", "mcp-llm", "a2a")
DRIVERS = {"mcp-scripted": ("MCP", "scripted"), "mcp-llm": ("MCP", "llm"), "a2a": ("A2A", "llm")}

PRINCIPAL_WEIGHTS = {"alice": 3, "bob": 2, "dana": 1, "reporter-agent": 2, None: 1}  # None = anonymous
MCP_MODE_WEIGHTS = {"auto": 7, "legacy": 3}
MISTAKE_RATE = 0.05

CITIES = ["Islamabad", "Lahore", "Karachi", "Peshawar", "Quetta", "Multan", "Gilgit", "Faisalabad"]
TOPICS = ["sensor calibration", "network upgrade", "energy usage", "lab safety", "firmware rollout",
          "backup policy", "quarterly review", "agent onboarding"]
FOLDERS = ["", "docs", "reports", "public", "projects", "config"]
WORDS = ("check sensor offsets before the review, order spare cables, update the firmware on bench two, "
         "book the meeting room, back up the logs, recalibrate the humidity sensor, share the energy report").split(", ")


def _weighted(rng: random.Random, weights: dict):
    keys = list(weights)
    return rng.choices(keys, weights=[weights[k] for k in keys])[0]


def _role(principal: str | None) -> str:
    return "anonymous" if principal is None else W.World().users[principal]


def _visible_files(principal: str | None) -> list[str]:
    world = W.World()
    if principal is None:
        return []
    return [f["path"] for f in world.list_files(world.caller(f"Bearer {world.token_for(principal)}"))]


# ==========================================================================
# Scripted MCP sessions
# ==========================================================================

@dataclass(frozen=True)
class Step:
    tool: str
    args: dict
    delay: float          # seconds to wait before this call
    mistake: bool = False


@dataclass(frozen=True)
class McpPlan:
    seed: int
    principal: str | None
    mode: str             # MCP client handshake: auto | legacy
    timing: str           # interactive | automation
    list_tools_first: bool
    steps: tuple[Step, ...]

    def summary(self) -> str:
        return (f"seed={self.seed}; principal={self.principal or 'anonymous'}; mode={self.mode}; "
                f"timing={self.timing}; steps={len(self.steps)}; "
                f"mistakes={sum(s.mistake for s in self.steps)}")


NOTE_REF = "$note"   # replaced at run time by the id of the note created earlier in the session


def _delay(rng: random.Random, timing: str) -> float:
    if timing == "automation":
        return round(rng.uniform(0.02, 0.3), 3)
    return round(min(rng.lognormvariate(0.2, 0.6), 6.0), 3)   # median ~1.2 s, capped


def _note_body(rng: random.Random) -> str:
    """0-7 distinct to-do sentences, so note sizes vary like real notes."""
    picked = rng.sample(WORDS, rng.randint(0, len(WORDS)))
    return " ".join(p[0].upper() + p[1:] + "." for p in picked)


def _menu(rng: random.Random, role: str, files: list[str], has_note: bool) -> list[tuple[str, dict]]:
    """Calls this role would normally make, with realistic arguments."""
    items = [
        ("get_weather", {"city": rng.choice(CITIES)}),
        ("calculate", {"a": rng.randint(-50, 500), "b": rng.randint(1, 200),
                       "operation": rng.choice(["add", "subtract", "multiply", "divide"])}),
        ("get_server_status", {}),
    ]
    if role == "anonymous":
        return items
    items += [
        ("list_files", {"folder": rng.choice(FOLDERS)}),
        ("read_file", {"path": rng.choice(files)}),
        ("search_files", {"query": rng.choice(TOPICS + ["temperature", "meeting", "sensor"])}),
        ("list_devices", {}),
        ("read_sensor", {"sensor_id": rng.choice(["dht22-lab", "bme280-office"])}),
        ("read_sensor", {"sensor_id": rng.choice(["dht22-lab", "bme280-office"])}),
        ("create_note", {"title": rng.choice(TOPICS).capitalize(), "body": _note_body(rng)}),
        ("list_notes", {}),
    ]
    if has_note:
        items += [("get_note", {"note_id": NOTE_REF}), ("delete_note", {"note_id": NOTE_REF})]
    if role in ("operator", "admin"):
        items += [
            ("set_led", {"device_id": "led-lab", "on": rng.random() < 0.6,
                         "color": rng.choice(["white", "red", "green", "blue", "yellow"])}),
            ("sound_buzzer", {"device_id": "buzzer-lab", "duration_ms": rng.choice([100, 250, 500, 1000])}),
        ]
    return items


def _mistake(rng: random.Random, role: str) -> tuple[str, dict]:
    """An honest error a real user or app makes now and then."""
    options = [
        ("read_sensor", {"sensor_id": rng.choice(["dht22", "lab-sensor", "temperature"])}),   # wrong id
        ("read_file", {"path": rng.choice(["docs/handbook.txt", "public/FAQ.md", "reports/q4-energy.csv"])}),
        ("get_note", {"note_id": rng.randint(9000, 9999)}),                                   # no such note
    ]
    if role in ("anonymous", "viewer"):
        options.append(("set_led", {"device_id": "led-lab", "on": True, "color": "white"}))  # not permitted
    if role == "anonymous":
        options.append(("list_files", {"folder": ""}))                                          # not permitted
    return rng.choice(options)


def plan_mcp_scripted(seed: int, principal: str | None = ..., ) -> McpPlan:
    rng = random.Random(f"mcp-scripted:{seed}")   # each kind has its own random stream
    if principal is ...:
        principal = _weighted(rng, PRINCIPAL_WEIGHTS)
    role = _role(principal)
    files = _visible_files(principal)
    mode = _weighted(rng, MCP_MODE_WEIGHTS)
    timing = rng.choice(["interactive", "automation"])
    n = min(1 + int(rng.expovariate(1 / 3)), 8)    # ~28% single-call sessions (polling)
    steps, has_note = [], False
    for _ in range(n):
        if rng.random() < MISTAKE_RATE:
            tool, args = _mistake(rng, role)
            steps.append(Step(tool, args, _delay(rng, timing), mistake=True))
            continue
        tool, args = rng.choice(_menu(rng, role, files, has_note))
        if tool == "create_note":
            has_note = True
        if tool == "delete_note":
            has_note = False
        steps.append(Step(tool, args, _delay(rng, timing)))
    return McpPlan(seed, principal, mode, timing, rng.random() < 0.7, tuple(steps))


def _load(path: Path, name: str):
    import importlib.util
    folder = str(path.parent)
    if folder not in sys.path:
        sys.path.insert(0, folder)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mcp_client():
    return _load(testbed.TESTBED / "mcp" / "client.py", "agentnet_mcp_client_benign")


async def run_mcp_plan(plan: McpPlan) -> runner.Outcome:
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    mc = _mcp_client()
    errors, note_id, sent = 0, None, 0
    async with mc.connect(plan.principal) as http:
        async with Client(streamable_http_client(mc.SERVER_URL, http_client=http), mode=plan.mode) as client:
            if plan.list_tools_first:
                await client.list_tools()
            for step in plan.steps:
                await asyncio.sleep(step.delay)
                args = dict(step.args)
                if args.get("note_id") == NOTE_REF:
                    if note_id is None:
                        continue                    # the note was not created; skip like a real app would
                    args["note_id"] = note_id
                result = await client.call_tool(step.tool, args)
                sent += 1
                if result.is_error:
                    errors += 1
                elif step.tool == "create_note":
                    note_id = (result.structured_content or {}).get("id")
                elif step.tool == "delete_note":
                    note_id = None
    return runner.Outcome(notes=f"{plan.summary()}; calls={sent}; tool_errors={errors}")


# ==========================================================================
# Natural-language tasks (LLM over MCP, and A2A requests)
# ==========================================================================

VIEWER_TASKS = [
    "What is the temperature and humidity in the lab right now?",
    "What is the air pressure in the office?",
    "What is the weather in {city}?",
    "Which files are in the {folder} folder?",
    "Summarise the meeting notes from {month}.",
    "Search the workspace for '{topic}' and tell me where it is mentioned.",
    "Which devices are in the lab and what state are they in?",
    "Create a note titled '{title}' saying: {body}.",
    "List my notes.",
    "What is {a} {opword} {b}?",
    "Read the lab FAQ and tell me who can control devices.",
    "What was the average lab temperature on 2026-10-{day:02d} according to the sensor summary?",
]
OPERATOR_TASKS = [
    "Turn the lab LED {onoff}.",
    "Set the lab LED to {color}.",
    "Sound the lab buzzer for {ms} milliseconds.",
]
ADMIN_TASKS = [
    "How many employees are listed in finance/payroll.csv?",
    "Which services have keys in secrets/api_keys.txt? Just name the services.",
]
ANONYMOUS_TASKS = [
    "What is the weather in {city}?",
    "What is {a} {opword} {b}?",
    "What version is the lab server running?",
]
_FOLDER_NAMES = ["docs", "reports", "public", "projects"]
_OPWORDS = {"plus": "add", "minus": "subtract", "times": "multiply", "divided by": "divide"}


def _fill(rng: random.Random, template: str) -> str:
    return template.format(
        city=rng.choice(CITIES), folder=rng.choice(_FOLDER_NAMES), month=rng.choice(["2026-09", "2026-10", "2026-11"]),
        topic=rng.choice(TOPICS), title=rng.choice(TOPICS).capitalize(), body=rng.choice(WORDS),
        a=rng.randint(2, 999), b=rng.randint(2, 99), opword=rng.choice(list(_OPWORDS)),
        day=rng.randint(1, 30), onoff=rng.choice(["on", "off"]),
        color=rng.choice(["red", "green", "blue", "yellow", "white"]), ms=rng.choice([200, 500, 1000, 1500]),
    )


def tasks_for(role: str) -> list[str]:
    if role == "anonymous":
        return ANONYMOUS_TASKS
    bank = list(VIEWER_TASKS)
    if role in ("operator", "admin"):
        bank += OPERATOR_TASKS
    if role == "admin":
        bank += ADMIN_TASKS
    return bank


def pick_task(rng: random.Random, role: str) -> tuple[str, bool]:
    """A task for this role; occasionally (MISTAKE_RATE) one the role is not allowed to do."""
    if role in ("anonymous", "viewer") and rng.random() < MISTAKE_RATE:
        return _fill(rng, rng.choice(OPERATOR_TASKS)), True
    return _fill(rng, rng.choice(tasks_for(role))), False


@dataclass(frozen=True)
class TaskPlan:
    seed: int
    principal: str | None
    tasks: tuple[str, ...]
    delay: float               # seconds between A2A requests
    llm_seed: int              # MCP-LLM sessions: the model's seed
    mode: str = "auto"         # MCP-LLM sessions: client handshake
    beyond_role: int = 0       # tasks the role is not allowed to do (honest mistakes)

    def summary(self) -> str:
        return (f"seed={self.seed}; principal={self.principal or 'anonymous'}; tasks={len(self.tasks)}; "
                f"beyond_role={self.beyond_role}")


def plan_task(seed: int, kind: str, principal: str | None = ...) -> TaskPlan:
    rng = random.Random(f"{kind}:{seed}")   # each kind has its own random stream
    if principal is ...:
        principal = _weighted(rng, PRINCIPAL_WEIGHTS)
    role = _role(principal)
    count = 1 if kind == "mcp-llm" else rng.choice([1, 1, 2, 2, 3, 4])
    picked = [pick_task(rng, role) for _ in range(count)]
    return TaskPlan(
        seed=seed, principal=principal, tasks=tuple(t for t, _ in picked),
        delay=_delay(rng, "interactive"), llm_seed=rng.randrange(1, 2**31),
        mode=_weighted(rng, MCP_MODE_WEIGHTS), beyond_role=sum(m for _, m in picked),
    )


async def run_mcp_llm_plan(plan: TaskPlan) -> runner.Outcome:
    import agent
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    mc = _mcp_client()
    llm = agent.OllamaChat(temperature=0.7, seed=plan.llm_seed)
    try:
        async with mc.connect(plan.principal) as http:
            async with Client(streamable_http_client(mc.SERVER_URL, http_client=http), mode=plan.mode) as session:
                r = await agent.run_agent(plan.tasks[0], session, llm, principal=plan.principal or "an anonymous visitor")
    finally:
        await llm.aclose()
    errors = sum(s.is_error for s in r.steps)
    return runner.Outcome(notes=(f"{plan.summary()}; mode={plan.mode}; llm={r.model}; llm_seed={r.seed}; "
                                 f"tools={','.join(r.tools_called) or '-'}; tool_errors={errors}; "
                                 f"finished={r.finished}"))


async def run_a2a_plan(plan: TaskPlan) -> runner.Outcome:
    a2a = _load(testbed.TESTBED / "a2a" / "client.py", "agentnet_a2a_client_benign")
    replies = await a2a.send_messages(list(plan.tasks), principal=plan.principal, delay=plan.delay)
    failed = [i for i, r in enumerate(replies) if r is None or r.startswith("Sorry, the assistant failed")]
    if failed:
        raise RuntimeError(f"Lab Assistant gave no usable reply to request(s) {failed}")
    return runner.Outcome(notes=f"{plan.summary()}; delay={plan.delay}; replies={len(replies)}")


# ==========================================================================
# Scenarios for the session runner
# ==========================================================================

def _devices(principal: str | None, protocol: str) -> tuple[str, str]:
    A = testbed.addresses
    src = f"{principal or 'anonymous'}-workstation@{A.workstation(principal)}"
    dst = f"mcp-server@{A.MCP_HOST}:{A.MCP_PORT}" if protocol == "MCP" else f"a2a-server@{A.A2A_HOST}:{A.A2A_PORT}"
    return src, dst


def build(kind: str, seed: int) -> runner.Scenario:
    """The benign scenario of this kind for this seed."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    protocol = DRIVERS[kind][0]
    if kind == "mcp-scripted":
        plan = plan_mcp_scripted(seed)

        async def run() -> runner.Outcome:
            return await run_mcp_plan(plan)
        timeout = 120
    elif kind == "mcp-llm":
        plan = plan_task(seed, kind)

        async def run() -> runner.Outcome:
            return await run_mcp_llm_plan(plan)
        timeout = 300
    else:
        plan = plan_task(seed, kind)

        async def run() -> runner.Outcome:
            return await run_a2a_plan(plan)
        timeout = 900
    src, dst = _devices(plan.principal, protocol)
    return runner.Scenario(
        name=f"benign-{kind}", protocol=protocol, attack_id=manifest.BENIGN_ID,
        bpf=testbed.TESTBED_BPF, run=run, timeout=timeout,
        source_device=src, destination_device=dst,
    )


# ==========================================================================
# Command line: show plans, or run a small sample and measure variety
# ==========================================================================

@dataclass
class SampleReport:
    out_dir: Path
    rows: list[dict] = field(default_factory=list)

    def distinct(self, key: str, kind: str | None = None) -> tuple[int, int]:
        values = [r[key] for r in self.rows if r["status"] == "valid" and (kind is None or r["kind"] == kind)]
        return len(set(values)), len(values)


def run_sample(out_dir: Path, per_kind: int, kinds=KINDS, first_seed: int = 1) -> SampleReport:
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"{out_dir} is not empty")
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = "SAMPLE-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    run = runner.SessionRunner(manifest_path=out_dir / "manifest.csv", log_path=out_dir / "capture_log.csv",
                               capture_dir=out_dir / "pcaps", run_id=run_id)
    report = SampleReport(out_dir)
    seed = first_seed
    with testbed.running(testbed.MCP_SERVER, testbed.A2A_SERVER, log_dir=out_dir / "logs", run_id=run_id):
        for _ in range(per_kind):
            for kind in kinds:
                res = run.run(build(kind, seed))
                cap = res.capture
                row = res.manifest_row or {}
                duration = ""
                if row:
                    duration = round((datetime.fromisoformat(row["end_time"]) -
                                      datetime.fromisoformat(row["start_time"])).total_seconds(), 2)
                report.rows.append({
                    "session_id": res.session_id, "kind": kind, "seed": seed, "status": res.status,
                    "packets": cap.packets_captured if cap else "",
                    "bytes": cap.path.stat().st_size if cap and cap.path.exists() else "",
                    "duration_s": duration, "notes": row.get("notes", res.reason),
                })
                seed += 1
    with open(out_dir / "sample_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(report.rows[0]))
        w.writeheader()
        w.writerows(report.rows)
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AgentNet benign scenario catalogue")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plans", help="print generated plans (no network)")
    p.add_argument("--kind", choices=KINDS, default="mcp-scripted")
    p.add_argument("--count", type=int, default=5)
    p.add_argument("--first-seed", type=int, default=1)
    s = sub.add_parser("sample", help="run a small captured sample and measure variety")
    s.add_argument("--per-kind", type=int, default=3)
    s.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    if args.command == "plans":
        for seed in range(args.first_seed, args.first_seed + args.count):
            if args.kind == "mcp-scripted":
                plan = plan_mcp_scripted(seed)
                print(plan.summary())
                for st in plan.steps:
                    print(f"    +{st.delay:5.2f}s {st.tool}({st.args}){'  [mistake]' if st.mistake else ''}")
            else:
                plan = plan_task(seed, args.kind)
                print(plan.summary())
                for t in plan.tasks:
                    print(f"    {t}")
        return 0

    if args.per_kind < 1:
        parser.error("--per-kind must be at least 1")
    out = args.out or Path(tempfile.mkdtemp(prefix="agentnet-benign-sample-"))
    report = run_sample(out, args.per_kind)
    for r in report.rows:
        print(f"{r['session_id']:14} {r['kind']:13} {r['status']:8} {r['packets']!s:>5} pkts "
              f"{r['bytes']!s:>7} B {r['duration_s']!s:>7} s")
    for kind in KINDS:
        d, n = report.distinct("packets", kind)
        print(f"{kind:13} distinct packet counts: {d}/{n}")
    print(f"output: {report.out_dir}")
    return 0 if all(r["status"] == "valid" for r in report.rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
