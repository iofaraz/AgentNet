"""Tests for the AgentNet MCP server (software_testbed/mcp).

* World: permission rules and synthetic data, tested directly (no network);
* MCP in-process: tool list, schemas, annotations, error masking, audit;
* MCP over real HTTP: bearer tokens -> roles, audit log written by the server.
"""

import asyncio
import getpass
import importlib.util
import json
import platform
import socket
import sys

import pytest

import testbed

MCP_DIR = testbed.TESTBED / "mcp"
sys.path.insert(0, str(MCP_DIR))   # for the server's sibling modules (workspace, audit)

import audit as A          # noqa: E402
import workspace as W      # noqa: E402


def _load(name, filename):
    # server.py / client.py share their names with the A2A testbed's files,
    # so load them under unique module names.
    spec = importlib.util.spec_from_file_location(name, MCP_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


S = _load("agentnet_mcp_server", "server.py")
C = _load("agentnet_mcp_client_t", "client.py")


@pytest.fixture
def world():
    return W.World()


def who(world, name):
    return world.caller(f"Bearer {world.token_for(name)}")


# ======================================================================
# Identity and roles
# ======================================================================

def test_no_header_is_anonymous(world):
    assert world.caller(None) == W.ANONYMOUS
    assert world.caller("") == W.ANONYMOUS


@pytest.mark.parametrize("name, role", [("alice", "viewer"), ("bob", "operator"),
                                        ("dana", "admin"), ("reporter-agent", "viewer"),
                                        ("ops-agent", "admin")])
def test_tokens_resolve_to_roles(world, name, role):
    assert who(world, name) == W.Caller(name, role)


@pytest.mark.parametrize("header", ["Bearer nope", "Basic abc", "Bearer", "token-without-scheme"])
def test_bad_credentials_are_rejected_not_downgraded(world, header):
    with pytest.raises(W.AccessDenied):
        world.caller(header)


def test_tokens_are_opaque_and_seed_specific():
    a, b = W.World(1), W.World(2)
    for name in a.users:
        assert name not in a.token_for(name), "tokens must not reveal the user name"
        assert a.token_for(name) != b.token_for(name)


def test_role_order():
    assert W.Caller("x", "admin").at_least("operator")
    assert not W.Caller("x", "viewer").at_least("operator")


# ======================================================================
# Files
# ======================================================================

def test_viewer_cannot_see_restricted_files(world):
    paths = [f["path"] for f in world.list_files(who(world, "alice"))]
    assert "public/faq.md" in paths
    assert not any(p.startswith(W.RESTRICTED_FOLDERS) for p in paths)


def test_admin_sees_and_reads_restricted_files(world):
    admin = who(world, "dana")
    paths = [f["path"] for f in world.list_files(admin)]
    assert "finance/payroll.csv" in paths and "secrets/api_keys.txt" in paths
    assert W.CANARY_PREFIX in world.read_file(admin, "secrets/api_keys.txt")


@pytest.mark.parametrize("path", ["finance/payroll.csv", "secrets/api_keys.txt"])
@pytest.mark.parametrize("user", ["alice", "bob", "reporter-agent"])
def test_non_admins_cannot_read_restricted(world, user, path):
    with pytest.raises(W.AccessDenied):
        world.read_file(who(world, user), path)


def test_anonymous_cannot_use_files(world):
    with pytest.raises(W.AccessDenied):
        world.list_files(W.ANONYMOUS)
    with pytest.raises(W.AccessDenied):
        world.read_file(W.ANONYMOUS, "public/faq.md")


@pytest.mark.parametrize("path", ["../secrets/api_keys.txt", "public/../secrets/api_keys.txt",
                                  "/etc/passwd", "\\windows\\win.ini", "public\\faq.md",
                                  "public/faq.md\x00"])
def test_bad_paths_rejected_by_the_path_rule(world, path):
    # The path rule itself must fire (not merely "no such file"), so the
    # check still protects if the workspace ever gains real folders.
    with pytest.raises(W.InvalidRequest, match="relative"):
        world.read_file(who(world, "dana"), path)


@pytest.mark.parametrize("path", ["", "a" * 201])
def test_bad_path_lengths_rejected(world, path):
    with pytest.raises(W.InvalidRequest, match="characters"):
        world.read_file(who(world, "dana"), path)


def test_missing_file(world):
    with pytest.raises(W.InvalidRequest, match="no such file"):
        world.read_file(who(world, "alice"), "public/nothing.md")


def test_search_hides_restricted_content_from_viewers(world):
    assert world.search_files(who(world, "alice"), W.CANARY_PREFIX) == []
    assert world.search_files(who(world, "dana"), W.CANARY_PREFIX)


def test_search_is_bounded(world):
    hits = world.search_files(who(world, "dana"), "a")
    assert len(hits) == W.MAX_SEARCH_HITS
    with pytest.raises(W.InvalidRequest):
        world.search_files(who(world, "alice"), "x" * (W.MAX_QUERY + 1))


def test_files_vary_in_size(world):
    sizes = {len(c) for c in world.files.values()}
    assert min(sizes) < 400 and max(sizes) > 2000, "responses must differ in size"


def test_synthetic_data_is_deterministic_per_seed():
    assert W.World(7).files == W.World(7).files
    assert W.World(7).files["secrets/api_keys.txt"] != W.World(8).files["secrets/api_keys.txt"]


# ======================================================================
# Notes
# ======================================================================

def test_notes_lifecycle(world):
    alice = who(world, "alice")
    note = world.create_note(alice, "Calibration", "Check DHT22 offset")
    assert world.list_notes(alice) == [{"id": note["id"], "title": "Calibration"}]
    assert world.get_note(alice, note["id"])["body"] == "Check DHT22 offset"
    assert world.delete_note(alice, note["id"]) == {"deleted": note["id"]}
    assert world.list_notes(alice) == []


def test_notes_are_private(world):
    note = world.create_note(who(world, "alice"), "mine", "")
    bob = who(world, "bob")
    assert world.list_notes(bob) == []
    with pytest.raises(W.InvalidRequest):
        world.get_note(bob, note["id"])
    with pytest.raises(W.InvalidRequest):
        world.delete_note(bob, note["id"])


def test_note_limits(world, monkeypatch):
    alice = who(world, "alice")
    with pytest.raises(W.InvalidRequest):
        world.create_note(alice, "", "x")
    with pytest.raises(W.InvalidRequest):
        world.create_note(alice, "t", "x" * (W.MAX_BODY + 1))
    monkeypatch.setattr(W, "MAX_NOTES_PER_USER", 2)
    world.create_note(alice, "1", "")
    world.create_note(alice, "2", "")
    with pytest.raises(W.InvalidRequest, match="limit"):
        world.create_note(alice, "3", "")


# ======================================================================
# Devices
# ======================================================================

@pytest.mark.parametrize("user", ["alice", "reporter-agent"])
def test_viewers_cannot_actuate(world, user):
    with pytest.raises(W.AccessDenied):
        world.set_led(who(world, user), "led-lab", True)
    with pytest.raises(W.AccessDenied):
        world.sound_buzzer(who(world, user), "buzzer-lab", 100)
    assert world.actuation_history == []
    assert world.devices["led-lab"].state["on"] is False


def test_operator_actuation_is_recorded(world):
    bob = who(world, "bob")
    assert world.set_led(bob, "led-lab", True, "red") == {"device": "led-lab", "on": True, "color": "red"}
    world.sound_buzzer(bob, "buzzer-lab", 250)
    history = world.actuation_history
    assert [h["action"] for h in history] == ["set_led", "sound_buzzer"]
    assert all(h["principal"] == "bob" and h["role"] == "operator" for h in history)


@pytest.mark.parametrize("call, args", [
    ("set_led", ("buzzer-lab", True)),          # wrong device type
    ("set_led", ("led-x", True)),               # unknown device
    ("set_led", ("led-lab", True, "purple")),   # bad colour
    ("sound_buzzer", ("buzzer-lab", 0)),
    ("sound_buzzer", ("buzzer-lab", W.BUZZER_MAX_MS + 1)),
])
def test_bad_actuation_requests(world, call, args):
    with pytest.raises(W.InvalidRequest):
        getattr(world, call)(who(world, "bob"), *args)
    assert world.actuation_history == []


def test_sensor_readings_are_plausible_and_vary(world):
    alice = who(world, "alice")
    readings = [world.read_sensor(alice, "dht22-lab") for _ in range(20)]
    temps = [r["temperature_c"] for r in readings]
    assert all(10 < t < 40 for t in temps) and len(set(temps)) > 1
    assert "pressure_hpa" not in readings[0]
    bme = world.read_sensor(alice, "bme280-office")
    assert 950 < bme["pressure_hpa"] < 1060


def test_unknown_or_non_sensor(world):
    for sid in ("nope", "led-lab"):
        with pytest.raises(W.InvalidRequest):
            world.read_sensor(who(world, "alice"), sid)


# ======================================================================
# Utility
# ======================================================================

@pytest.mark.parametrize("op, expected", [("add", 30), ("subtract", -10), ("multiply", 200), ("divide", 0.5)])
def test_calculate(op, expected):
    assert W.World.calculate(10, 20, op) == expected


@pytest.mark.parametrize("a, b, op", [(1, 0, "divide"), (float("inf"), 1, "add"), (1, 2, "power")])
def test_calculate_rejects(a, b, op):
    with pytest.raises(W.InvalidRequest):
        W.World.calculate(a, b, op)


def test_weather(world):
    w = world.weather("Islamabad")
    assert w["city"] == "Islamabad" and w["source"] == "synthetic"
    assert world.weather("Islamabad")["condition"] == w["condition"]   # stable within the hour
    assert world.weather("Atlantis")["city"] == "Atlantis"
    with pytest.raises(W.InvalidRequest):
        world.weather("x" * (W.MAX_CITY + 1))


# ======================================================================
# D9: no real host information anywhere
# ======================================================================

def _host_markers():
    markers = {platform.machine(), platform.python_version(), socket.gethostname(), getpass.getuser(),
               platform.node(), platform.release()}
    if platform.system() != "Linux":   # "Linux" may legitimately appear in text
        markers.add(platform.system())
    return {m for m in markers if m and len(m) >= 3}


def test_no_host_information_in_any_output(world):
    admin, bob = who(world, "dana"), who(world, "bob")
    outputs = [
        world.status(14), world.weather("Islamabad"), world.list_devices(admin),
        world.read_sensor(admin, "dht22-lab"), world.read_sensor(admin, "bme280-office"),
        world.list_files(admin), world.set_led(bob, "led-lab", True),
        *world.files.values(),
    ]
    text = json.dumps(outputs, default=str)
    leaked = [m for m in _host_markers() if m in text]
    assert not leaked, f"host details leaked into tool output: {leaked}"


def test_server_source_does_not_query_the_host():
    for f in ("server.py", "workspace.py", "audit.py"):
        src = (MCP_DIR / f).read_text(encoding="utf-8")
        for forbidden in ("import platform", "sys.version", "gethostname", "getpass", "os.environ['USER"):
            assert forbidden not in src, f"{f} uses {forbidden}"


# ======================================================================
# MCP in-process (no network): tool list, schemas, errors, audit
# ======================================================================

def _run(coro):
    return asyncio.run(coro)


async def _with_client(world, audit_log, fn):
    from mcp import Client
    async with Client(S.create_server(world, audit_log)) as client:
        return await fn(client)


def test_tool_list_schemas_and_annotations(world):
    async def go(c):
        return (await c.list_tools()).tools
    tools = {t.name: t for t in _run(_with_client(world, A.AuditLog(None), go))}
    assert set(tools) == set(S.DESCRIPTIONS)
    for name, t in tools.items():
        assert t.description == S.DESCRIPTIONS[name]
        props = t.input_schema.get("properties", {})
        assert "caller" not in props and "ctx" not in props, f"{name} leaks internal parameters"
    assert tools["read_file"].annotations.read_only_hint is True
    assert tools["delete_note"].annotations.destructive_hint is True
    assert tools["set_led"].annotations.read_only_hint is False
    assert tools["calculate"].input_schema["properties"]["operation"]["enum"] == ["add", "subtract", "multiply", "divide"]


def test_anonymous_access_is_denied_and_audited(world, tmp_path):
    log = A.AuditLog(tmp_path / "audit.jsonl")

    async def go(c):
        ok = await c.call_tool("calculate", {"a": 1, "b": 2, "operation": "add"})
        denied = await c.call_tool("list_files", {})
        return ok, denied
    ok, denied = _run(_with_client(world, log, go))
    log.close()
    assert not ok.is_error and denied.is_error
    assert "Access denied" in denied.content[0].text
    entries = A.read(tmp_path / "audit.jsonl")
    assert [(e["tool"], e["principal"], e["decision"]) for e in entries] == [
        ("calculate", "anonymous", "allowed"), ("list_files", "anonymous", "denied")]


def test_internal_errors_are_masked_but_audited(world, tmp_path, monkeypatch):
    def broken(city):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(world, "weather", broken)
    log = A.AuditLog(tmp_path / "audit.jsonl")

    async def go(c):
        return await c.call_tool("get_weather", {"city": "Lahore"})
    r = _run(_with_client(world, log, go))
    log.close()
    assert r.is_error and "internal server error" in r.content[0].text
    assert "secret internal detail" not in r.content[0].text, "internals must not reach the client"
    entry = A.read(tmp_path / "audit.jsonl")[0]
    assert entry["decision"] == "error" and "secret internal detail" in entry["detail"]


def test_audit_truncates_long_arguments(tmp_path):
    log = A.AuditLog(tmp_path / "a.jsonl")
    e = log.record(tool="t", principal="p", role="r", args={"body": "x" * 1000}, decision="allowed")
    log.close()
    assert len(e["args"]["body"]) < 260 and "+800 chars" in e["args"]["body"]


def test_audit_between_selects_a_window(tmp_path):
    from datetime import datetime, timedelta
    log = A.AuditLog(tmp_path / "a.jsonl")
    log.record(tool="t", principal="p", role="r", args={}, decision="allowed")
    log.close()
    entries = A.read(tmp_path / "a.jsonl")
    now = datetime.now().astimezone()
    assert A.between(entries, now - timedelta(minutes=1), now + timedelta(minutes=1)) == entries
    assert A.between(entries, now + timedelta(minutes=1), now + timedelta(minutes=2)) == []


# ======================================================================
# MCP over real HTTP: tokens -> roles, audit log written by the server
# ======================================================================

needs_port = pytest.mark.skipif(testbed.MCP_SERVER.in_use(), reason="MCP server address already in use")


@needs_port
def test_roles_over_http(tmp_path):
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    async def call(principal, tool, args):
        async with C.connect(principal) as http:
            async with Client(streamable_http_client(C.SERVER_URL, http_client=http)) as c:
                return await c.call_tool(tool, args)

    async def scenario():
        return {
            "alice_files": await call("alice", "list_files", {}),
            "dana_files": await call("dana", "list_files", {}),
            "alice_led": await call("alice", "set_led", {"device_id": "led-lab", "on": True}),
            "bob_led": await call("bob", "set_led", {"device_id": "led-lab", "on": True, "color": "green"}),
            "anon_calc": await call(None, "calculate", {"a": 2, "b": 3, "operation": "multiply"}),
        }

    with testbed.running(testbed.MCP_SERVER, log_dir=tmp_path, run_id="T") as servers:
        r = asyncio.run(scenario())
        audit_path = servers[0].audit_path

    alice_paths = [f["path"] for f in C._value(r["alice_files"])]
    dana_paths = [f["path"] for f in C._value(r["dana_files"])]
    assert "finance/payroll.csv" not in alice_paths and "finance/payroll.csv" in dana_paths
    assert r["alice_led"].is_error and "Access denied" in r["alice_led"].content[0].text
    assert not r["bob_led"].is_error and C._value(r["bob_led"])["color"] == "green"
    assert C._value(r["anon_calc"]) == 6

    entries = A.read(audit_path)
    assert [(e["tool"], e["principal"], e["decision"]) for e in entries] == [
        ("list_files", "alice", "allowed"), ("list_files", "dana", "allowed"),
        ("set_led", "alice", "denied"), ("set_led", "bob", "allowed"),
        ("calculate", "anonymous", "allowed")]


@needs_port
def test_unknown_token_over_http_is_rejected(tmp_path):
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    async def go():
        async with httpx2.AsyncClient(headers={"Authorization": "Bearer forged"}, timeout=30) as http:
            async with Client(streamable_http_client(C.SERVER_URL, http_client=http)) as c:
                return await c.call_tool("calculate", {"a": 1, "b": 1, "operation": "add"})

    with testbed.running(testbed.MCP_SERVER, log_dir=tmp_path, run_id="T") as servers:
        r = asyncio.run(go())
        audit_path = servers[0].audit_path
    assert r.is_error and "Access denied" in r.content[0].text
    assert A.read(audit_path)[0]["decision"] == "denied"
