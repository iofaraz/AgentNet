"""Attack framework (Part 4.1): what every attack scenario shares.

* the plan of the attack collection (agreed 2026-11-28, decision D19):
  300 sessions per attack, 4 variants each (V4 held out as the "unseen"
  variant for generalisation tests), recorded in blocks of 25 interleaved
  with 250 new benign sessions, so time-of-day load on the shared GPU is
  not a label signal (D18);
* each attack's session drivers, chosen so that the attack data has about
  the same scripted / LLM / A2A mix as the benign data (contract §11b.2);
* attack_scenario(): turns an attack's executor and judge into a scenario
  for the session runner. The judge decides Success / Failed from the
  servers' audit logs only (taxonomy §5: never assumed), and a session in
  which the attack never reached its target is excluded instead of being
  labelled as an attack in which nothing happened;
* evidence helpers for judges: tool calls in the session window, canary
  secrets, device actuations.

The attacks themselves are added one per subpart (4.2 AT-01 ... 4.8 AT-07).
"""

from __future__ import annotations

import random
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest  # noqa: E402
import runner  # noqa: E402
import testbed  # noqa: E402

for _folder in ("", "mcp"):
    _p = str(testbed.TESTBED / _folder) if _folder else str(testbed.TESTBED)
    if _p not in sys.path:
        sys.path.append(_p)
import attack_profile  # noqa: E402
import audit  # noqa: E402
import workspace  # noqa: E402

# ==========================================================================
# The plan (D19)
# ==========================================================================

SESSIONS_PER_ATTACK = 300
VARIANTS = ("V1", "V2", "V3", "V4")
HELDOUT_VARIANT = "V4"          # never used for training: tests detection of an unseen variant
BLOCK_SIZE = 25                 # sessions per run; a run holds one attack variant (or benign)
BENIGN_EXTRA = 250              # new benign sessions interleaved with the attack blocks
FAILED_SHARE_TARGET = (0.20, 0.30)   # measured, not forced: failures come from the variants themselves

ATTACK_RUN_PREFIX = "S-ATTACK-"
BENIGN_RUN_PREFIX = "S-BENIGN4-"
ATTACK_SEED_START = 10001
BENIGN_SEED_START = 3001        # above every seed of the S-BENIGN3 run (2001-3000)

KIND_PROTOCOL = {"mcp-scripted": "MCP", "mcp-llm": "MCP", "a2a": "A2A"}
BENIGN_MIX = {"mcp-scripted": 0.40, "mcp-llm": 0.30, "a2a": 0.30}   # as in the benign collection


@dataclass(frozen=True)
class AttackSpec:
    attack_id: str
    drivers: dict[str, float]           # session kind -> share of this attack's sessions
    variants: dict[str, str] = field(default_factory=dict)   # filled in by each attack's subpart

    @property
    def name(self) -> str:
        return manifest.ATTACKS[self.attack_id][0]


# Drivers per attack. Protocols follow the contract's table (AT-01..04 are MCP
# only, AT-06 is A2A only). LLM-targeting attacks also hit scripted clients:
# a scripted app that receives a poisoned description or an injected result
# simply ignores it, which is a real, failed attack attempt.
ATTACKS: dict[str, AttackSpec] = {s.attack_id: s for s in (
    AttackSpec("AT-01", {"mcp-scripted": 0.50, "mcp-llm": 0.50}),
    AttackSpec("AT-02", {"mcp-scripted": 0.50, "mcp-llm": 0.50}),
    AttackSpec("AT-03", {"mcp-scripted": 0.40, "mcp-llm": 0.60}),
    AttackSpec("AT-04", {"mcp-scripted": 0.60, "mcp-llm": 0.40}),
    AttackSpec("AT-05", {"mcp-scripted": 0.35, "mcp-llm": 0.30, "a2a": 0.35}),
    AttackSpec("AT-06", {"a2a": 1.00}),
    AttackSpec("AT-07", {"mcp-scripted": 0.40, "mcp-llm": 0.25, "a2a": 0.35}),
)}


# ==========================================================================
# Schedule
# ==========================================================================

@dataclass(frozen=True)
class AttackSlot:
    index: int          # position in the whole collection (1-based)
    run_id: str
    attack_id: str      # AT-00 for the interleaved benign blocks
    variant: str        # N/A for benign
    kind: str
    seed: int

    @property
    def is_benign(self) -> bool:
        return self.attack_id == manifest.BENIGN_ID


def _kinds(weights: dict[str, float], n: int, rng: random.Random) -> list[str]:
    """n session kinds in the given shares (largest remainder), in random order."""
    exact = {k: w * n for k, w in weights.items()}
    counts = {k: int(v) for k, v in exact.items()}
    for k in sorted(exact, key=lambda k: (exact[k] - counts[k], k), reverse=True)[: n - sum(counts.values())]:
        counts[k] += 1
    kinds = [k for k in sorted(counts) for _ in range(counts[k])]
    rng.shuffle(kinds)
    return kinds


def blocks() -> list[tuple[str, str]]:
    """(attack_id, variant) of every block, in recording order; benign blocks are ('AT-00', 'N/A')."""
    per_variant = SESSIONS_PER_ATTACK // len(VARIANTS)
    if per_variant % BLOCK_SIZE or SESSIONS_PER_ATTACK % len(VARIANTS) or BENIGN_EXTRA % BLOCK_SIZE:
        raise ValueError("sessions per variant and benign sessions must be whole blocks")
    attack_blocks = [(a, v) for a in sorted(ATTACKS) for v in VARIANTS for _ in range(per_variant // BLOCK_SIZE)]
    random.Random("attack-schedule").shuffle(attack_blocks)
    n_benign = BENIGN_EXTRA // BLOCK_SIZE
    total = len(attack_blocks) + n_benign
    benign_at = {round((i + 0.5) * total / n_benign) for i in range(n_benign)}
    order, it = [], iter(attack_blocks)
    for pos in range(total):
        order.append((manifest.BENIGN_ID, manifest.NOT_APPLICABLE) if pos in benign_at else next(it))
    return order


def schedule() -> list[AttackSlot]:
    """Every session of the attack collection, in recording order."""
    slots, index = [], 0
    attack_runs = benign_runs = 0
    attack_seed, benign_seed = ATTACK_SEED_START, Counter()
    for b, (attack_id, variant) in enumerate(blocks(), start=1):
        rng = random.Random(f"attack-block:{b}")
        if attack_id == manifest.BENIGN_ID:
            benign_runs += 1
            run_id = f"{BENIGN_RUN_PREFIX}{benign_runs:02d}"
            kinds = _kinds(BENIGN_MIX, BLOCK_SIZE, rng)
        else:
            attack_runs += 1
            run_id = f"{ATTACK_RUN_PREFIX}{attack_runs:03d}"
            kinds = _kinds(ATTACKS[attack_id].drivers, BLOCK_SIZE, rng)
        for kind in kinds:
            index += 1
            if attack_id == manifest.BENIGN_ID:
                seed = BENIGN_SEED_START + benign_seed[kind]
                benign_seed[kind] += 1
            else:
                seed, attack_seed = attack_seed, attack_seed + 1
            slots.append(AttackSlot(index, run_id, attack_id, variant, kind, seed))
    return slots


def mix_report(slots: list[AttackSlot] | None = None) -> dict[str, dict[str, float]]:
    """Share of each session kind, for attack and for benign sessions (contract §11b.2)."""
    slots = schedule() if slots is None else slots
    out = {}
    for label, group in (("attack", [s for s in slots if not s.is_benign]),
                         ("benign", [s for s in slots if s.is_benign])):
        c = Counter(s.kind for s in group)
        out[label] = {k: c[k] / len(group) for k in KIND_PROTOCOL} if group else {}
    return out


# ==========================================================================
# Evidence and verdicts
# ==========================================================================

@dataclass(frozen=True)
class TestbedFiles:
    """Where the running testbed writes what a judge needs."""

    mcp_audit: Path
    profile: Path
    a2a_audit: Path | None = None


@dataclass
class Evidence:
    """Everything a judge may look at: the audit logs of the session window, and
    what the executor itself observed (e.g. the replies a client received)."""

    start: datetime
    end: datetime
    mcp: list[dict]
    a2a: list[dict]
    observed: Any = None


@dataclass(frozen=True)
class Verdict:
    delivered: bool     # the attack really reached its target (else the session is excluded)
    success: bool       # the attack's predefined success condition was met
    detail: str         # short reason, recorded in the manifest notes


class NotDelivered(RuntimeError):
    """The attack never reached its target; labelling the session would be a guess."""


def calls(entries: list[dict], *, tool: str | None = None, decision: str | None = None,
          principal: str | None = None) -> list[dict]:
    """Audit entries matching all the given fields."""
    return [e for e in entries
            if (tool is None or e.get("tool") == tool)
            and (decision is None or e.get("decision") == decision)
            and (principal is None or e.get("principal") == principal)]


def canaries(seed: int = workspace.DEFAULT_SEED) -> frozenset[str]:
    """Every synthetic secret in the workspace (they all start with CANARY_PREFIX)."""
    import re
    pattern = re.compile(re.escape(workspace.CANARY_PREFIX) + r"[0-9A-F]{20}")
    return frozenset(m for text in workspace.World(seed).files.values() for m in pattern.findall(text))


def leaked(text: str, secrets: frozenset[str] | None = None) -> set[str]:
    """Canary secrets that appear in a piece of text."""
    secrets = canaries() if secrets is None else secrets
    return {c for c in secrets if c in (text or "")}


ACTUATORS = ("set_led", "sound_buzzer")


def actuations(entries: list[dict]) -> list[dict]:
    """Device actions the MCP server actually carried out."""
    return [e for e in entries if e.get("tool") in ACTUATORS and e.get("decision") == audit.ALLOWED]


def _mcp_tool_names() -> frozenset[str]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("agentnet_mcp_server_names", testbed.TESTBED / "mcp" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return frozenset(module.DESCRIPTIONS)


# ==========================================================================
# Scenario
# ==========================================================================

def _read_window(path: Path | None, start: datetime, end: datetime) -> list[dict]:
    if path is None or not Path(path).exists():
        return []
    return audit.between(audit.read(path), start, end)


def attack_scenario(
    *,
    attack_id: str,
    variant: str,
    kind: str,
    seed: int,
    files: TestbedFiles,
    execute: Callable[[], Awaitable[Any]],
    judge: Callable[[Evidence], Verdict],
    profile: dict | None = None,
    notes: str = "",
    source_device: str = "",
    destination_device: str = "",
    timeout: float = 300.0,
) -> runner.Scenario:
    """A runner scenario for one attack session.

    The session: write the attack profile (if any) -> run the executor ->
    remove the profile -> read the audit logs of the session window -> judge.
    Nothing is waited for after the executor finishes, so attack captures end
    exactly like benign ones (a trailing pause would be a timing shortcut).
    """
    if attack_id not in ATTACKS:
        raise ValueError(f"attack_id must be one of {sorted(ATTACKS)}")
    if variant not in VARIANTS:
        raise ValueError(f"variant must be one of {VARIANTS}")
    if kind not in ATTACKS[attack_id].drivers:
        raise ValueError(f"{attack_id} has no {kind!r} sessions (drivers: {sorted(ATTACKS[attack_id].drivers)})")
    protocol = KIND_PROTOCOL[kind]
    tool_names = _mcp_tool_names() if profile is not None else frozenset()
    if profile is not None:
        attack_profile.validate(profile, tool_names)      # fail now, not in the middle of a capture

    async def run() -> runner.Outcome:
        start = datetime.now().astimezone()
        if profile is not None:
            attack_profile.write(files.profile, profile, tool_names)
        try:
            observed = await execute()
        finally:
            if profile is not None:
                attack_profile.clear(files.profile)
        end = datetime.now().astimezone()
        ev = Evidence(start, end, _read_window(files.mcp_audit, start, end),
                      _read_window(files.a2a_audit, start, end), observed)
        v = judge(ev)
        if not v.delivered:
            raise NotDelivered(f"attack not delivered: {v.detail}")
        text = f"attack={attack_id}; variant={variant}; kind={kind}; seed={seed}"
        text += (f"; {notes}" if notes else "") + f"; verdict={v.detail}"
        return runner.Outcome(success=v.success, notes=text)

    return runner.Scenario(
        name=f"attack-{attack_id}-{variant}-{kind}", protocol=protocol, attack_id=attack_id,
        variant=variant, bpf=testbed.TESTBED_BPF, run=run, timeout=timeout,
        source_device=source_device, destination_device=destination_device,
    )


# ==========================================================================
# Command line: show the plan
# ==========================================================================

def main(argv: list[str]) -> int:
    slots = schedule()
    runs = Counter(s.run_id for s in slots)
    print(f"{len(slots)} sessions in {len(runs)} runs of {BLOCK_SIZE}: "
          f"{sum(not s.is_benign for s in slots)} attack, {sum(s.is_benign for s in slots)} benign")
    for a, spec in ATTACKS.items():
        mine = [s for s in slots if s.attack_id == a]
        kinds = Counter(s.kind for s in mine)
        print(f"  {a} {spec.name:34} {len(mine)} sessions; " + ", ".join(f"{k} {kinds[k]}" for k in sorted(kinds)))
    for label, mix in mix_report(slots).items():
        print(f"  {label:6} mix: " + ", ".join(f"{k} {v:.0%}" for k, v in mix.items()))
    print("  order: " + " ".join("B" if a == manifest.BENIGN_ID else a[3:] for a, _ in blocks()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
