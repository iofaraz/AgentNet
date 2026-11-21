"""Tests for the A2A Lab Assistant (software_testbed/a2a).

* deputy.py: the requester-role check, against a fake MCP session backed by
  the real synthetic world;
* the policy agrees with the MCP server's own rules;
* the whole A2A server in-process (httpx ASGI transport, no network) with a
  scripted model: identity, refusals, audit log, error masking.
"""

import asyncio
import importlib.util
import json
import sys

import httpx
import pytest

import testbed

A2A_DIR, MCP_DIR = testbed.TESTBED / "a2a", testbed.TESTBED / "mcp"
for d in (A2A_DIR, MCP_DIR, testbed.TESTBED / "llm"):
    sys.path.insert(0, str(d))

import audit as A          # noqa: E402
import deputy as D         # noqa: E402
import workspace as W      # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MCP_SERVER = _load("agentnet_mcp_server_a", MCP_DIR / "server.py")
EXEC = _load("agentnet_a2a_executor", A2A_DIR / "agent_executor.py")
A2A_SERVER = _load("agentnet_a2a_server", A2A_DIR / "server.py")
A2A_CLIENT = _load("agentnet_a2a_client_a", A2A_DIR / "client.py")


# ---- a fake MCP session: real tool schemas, real world, admin service account

def _real_tool_list():
    from mcp import Client

    async def go():
        async with Client(MCP_SERVER.create_server(W.World(), A.AuditLog(None))) as c:
            return await c.list_tools()
    return asyncio.run(go())


TOOL_LIST = _real_tool_list()   # built once, outside any event loop


class _Text:
    def __init__(self, text):
        self.text, self.type = text, "text"


class _Result:
    def __init__(self, value=None, error=None):
        self.is_error = error is not None
        if error is not None:
            self.content, self.structured_content = [_Text(error)], None
        else:
            self.structured_content = value if isinstance(value, dict) else {"result": value}
            self.content = [_Text(json.dumps(value))]


class FakeMCP:
    """Behaves like an MCP session authenticated as ops-agent (admin)."""

    def __init__(self):
        self.world = W.World()
        self.caller = self.world.caller(f"Bearer {self.world.token_for('ops-agent')}")
        self.calls = []

    async def list_tools(self):
        return TOOL_LIST.model_copy(deep=True)   # the deputy filters the copy

    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        method = {"calculate": lambda **a: W.World.calculate(**a),
                  "get_weather": lambda **a: self.world.weather(**a),
                  "get_server_status": lambda **a: self.world.status(14)}.get(name)
        try:
            if method is None:
                value = getattr(self.world, name)(self.caller, **args)
            else:
                value = method(**args)
        except (W.AccessDenied, W.InvalidRequest) as e:
            return _Result(error=str(e))
        return _Result(value)


def deputy_for(role):
    fake = FakeMCP()
    return D.DeputySession(fake, role), fake


# ======================================================================
# Deputy check
# ======================================================================

@pytest.mark.parametrize("role, expected", [
    ("anonymous", {"calculate", "get_weather", "get_server_status"}),
    ("viewer", {"calculate", "get_weather", "get_server_status", "list_files", "read_file",
                "search_files", "list_devices", "read_sensor"}),
    ("operator", set(D.TOOL_MIN_ROLE)),
    ("admin", set(D.TOOL_MIN_ROLE)),
])
def test_model_only_sees_tools_the_requester_may_use(role, expected):
    deputy, _ = deputy_for(role)
    names = {t.name for t in asyncio.run(deputy.list_tools()).tools}
    assert names == expected
    assert not names & {"create_note", "list_notes", "get_note", "delete_note"}, "notes are never offered"


def test_forbidden_tool_is_refused_without_reaching_mcp():
    deputy, fake = deputy_for("viewer")
    r = asyncio.run(deputy.call_tool("set_led", {"device_id": "led-lab", "on": True}))
    assert r.is_error and "requires the operator role" in r.content[0].text
    assert fake.calls == [] and deputy.decisions[0].outcome == "refused"


def test_unoffered_tool_is_refused():
    deputy, fake = deputy_for("admin")
    r = asyncio.run(deputy.call_tool("delete_note", {"note_id": 1}))
    assert r.is_error and fake.calls == []


@pytest.mark.parametrize("role", ["anonymous", "viewer", "operator"])
@pytest.mark.parametrize("path", ["secrets/api_keys.txt", "finance/payroll.csv", "/secrets/api_keys.txt"])
def test_restricted_files_refused_for_non_admins(role, path):
    deputy, fake = deputy_for(role)
    r = asyncio.run(deputy.call_tool("read_file", {"path": path}))
    assert r.is_error and fake.calls == []
    assert W.CANARY_PREFIX not in r.content[0].text


def test_admin_requester_can_read_restricted_file():
    deputy, fake = deputy_for("admin")
    r = asyncio.run(deputy.call_tool("read_file", {"path": "secrets/api_keys.txt"}))
    assert not r.is_error and W.CANARY_PREFIX in r.content[0].text
    assert fake.calls == [("read_file", {"path": "secrets/api_keys.txt"})]


@pytest.mark.parametrize("folder", ["finance", "finance/", "/finance", " secrets ", "secrets/sub"])
def test_restricted_folder_listing_refused(folder):
    # Regression: "finance" without a trailing slash once slipped past the
    # folder rule (result filtering still caught it).
    deputy, fake = deputy_for("viewer")
    r = asyncio.run(deputy.call_tool("list_files", {"folder": folder}))
    assert r.is_error and fake.calls == []


@pytest.mark.parametrize("path", ["financial-report.md", "docs/finance/notes.md", "public/faq.md"])
def test_similar_names_are_not_restricted(path):
    assert not D._restricted(path)


@pytest.mark.parametrize("tool, args", [("list_files", {}), ("search_files", {"query": W.CANARY_PREFIX[:8]})])
def test_admin_only_entries_filtered_from_results(tool, args):
    deputy, fake = deputy_for("viewer")
    r = asyncio.run(deputy.call_tool(tool, args))
    text = json.dumps(r.structured_content)
    assert "finance/" not in text and "secrets/" not in text and W.CANARY_PREFIX not in text
    assert fake.calls, "the call itself is forwarded (the service account may list)"
    assert deputy.decisions[-1].outcome == "filtered"


def test_nothing_to_filter_is_passed_through_unchanged():
    deputy, _ = deputy_for("viewer")
    r = asyncio.run(deputy.call_tool("list_files", {"folder": "docs"}))
    assert not r.is_error and deputy.decisions[-1].outcome == "forwarded"


def test_unverifiable_listing_is_withheld():
    class Weird(FakeMCP):
        async def call_tool(self, name, args):
            r = _Result([])
            r.structured_content = "not inspectable"
            return r
    deputy = D.DeputySession(Weird(), "viewer")
    r = asyncio.run(deputy.call_tool("list_files", {}))
    assert r.is_error and "could not verify" in r.content[0].text


def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        D.DeputySession(FakeMCP(), "superuser")


def test_policy_agrees_with_the_mcp_server():
    """For every offered tool and role, the deputy allows exactly what the server allows."""
    world = W.World()
    samples = {
        "calculate": lambda c: W.World.calculate(1, 2, "add"),
        "get_weather": lambda c: world.weather("Lahore"),
        "get_server_status": lambda c: world.status(1),
        "list_files": lambda c: world.list_files(c),
        "read_file": lambda c: world.read_file(c, "public/faq.md"),
        "search_files": lambda c: world.search_files(c, "lab"),
        "list_devices": lambda c: world.list_devices(c),
        "read_sensor": lambda c: world.read_sensor(c, "dht22-lab"),
        "set_led": lambda c: world.set_led(c, "led-lab", False),
        "sound_buzzer": lambda c: world.sound_buzzer(c, "buzzer-lab", 10),
    }
    assert set(samples) == set(D.TOOL_MIN_ROLE)
    # public utility tools are not role-checked on the server
    public = {"calculate", "get_weather", "get_server_status"}
    for role in D.ROLES:
        caller = W.Caller("x", role)
        for tool, fn in samples.items():
            try:
                fn(caller)
                server_allows = True
            except W.AccessDenied:
                server_allows = False
            if tool in public:
                server_allows = True
            assert D.allowed(role, tool) == server_allows, f"{tool} for {role}"
    assert D.RESTRICTED_FOLDERS == W.RESTRICTED_FOLDERS


# ======================================================================
# The A2A server in-process
# ======================================================================

class FakeLLM:
    model, seed, temperature = "fake-model", 5, 0.0

    def __init__(self, *replies):
        self.replies = list(replies)
        self.received_tools = []

    async def chat(self, messages, tools):
        self.received_tools.append({t["function"]["name"] for t in tools})
        return self.replies.pop(0)

    async def aclose(self):
        pass


def call(name, args):
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}


def answer(text):
    return {"role": "assistant", "content": text}


class Harness:
    """Runs the real A2A app in-process with a scripted model and a fake MCP session."""

    def __init__(self, tmp_path, *replies, connect_fails=False):
        self.world = W.World()
        self.audit_path = tmp_path / "a2a_audit.jsonl"
        self.audit = A.AuditLog(self.audit_path)
        self.llm = FakeLLM(*replies)
        self.mcp = FakeMCP()
        self.connected_as = []

        import contextlib

        @contextlib.asynccontextmanager
        async def connect(principal):
            self.connected_as.append(principal)
            if connect_fails:
                raise ConnectionError("mcp server at 127.0.0.1:8000 refused (internal detail)")
            yield self.mcp

        executor = EXEC.LabAssistantExecutor(self.world, self.audit, connect, llm_factory=lambda: self.llm)
        self.app = A2A_SERVER.build_app(executor)

    def send(self, text, principal="alice", raw_auth=None):
        from a2a.client import ClientConfig, create_client
        from a2a.helpers import new_text_message
        from a2a.types import Role, SendMessageRequest
        headers = {}
        if raw_auth is not None:
            headers["Authorization"] = raw_auth
        elif principal:
            headers["Authorization"] = f"Bearer {self.world.token_for(principal)}"

        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), headers=headers,
                                         base_url="http://127.0.0.1:9999") as http:
                client = await create_client(agent="http://127.0.0.1:9999",
                                             client_config=ClientConfig(streaming=False, httpx_client=http))
                try:
                    async for chunk in client.send_message(
                            SendMessageRequest(message=new_text_message(text, role=Role.ROLE_USER))):
                        return A2A_CLIENT._reply_text(chunk)
                finally:
                    await client.close()
        return asyncio.run(go())

    def entries(self):
        self.audit.close()
        return A.read(self.audit_path)


def test_agent_card_declares_auth_and_skills():
    card = A2A_SERVER.build_card()
    assert card.name == "AgentNet Lab Assistant"
    assert {s.id for s in card.skills} == {"lab-information", "device-control"}
    assert card.security_schemes["bearer"].http_auth_security_scheme.scheme == "Bearer"
    assert "bearer" in card.security_requirements[0].schemes
    assert card.supported_interfaces[0].url == "http://127.0.0.1:9999/"


def test_request_is_answered_with_mcp_tools(tmp_path):
    h = Harness(tmp_path, call("read_sensor", {"sensor_id": "dht22-lab"}), answer("It is 24 C."))
    assert h.send("Lab temperature?") == "It is 24 C."
    assert h.connected_as == ["ops-agent"], "MCP is called with the assistant's own account"
    assert h.mcp.calls == [("read_sensor", {"sensor_id": "dht22-lab"})]
    e = h.entries()[-1]
    assert (e["tool"], e["principal"], e["role"], e["decision"]) == ("a2a_task", "alice", "viewer", "allowed")
    assert "tools=read_sensor" in e["detail"] and "seed=5" in e["detail"]


def test_viewer_cannot_actuate_through_the_assistant(tmp_path):
    h = Harness(tmp_path, call("set_led", {"device_id": "led-lab", "on": True}), answer("Not allowed."))
    h.send("Turn on the LED")
    assert h.mcp.calls == [], "the refused call never reaches MCP"
    assert "set_led" not in h.llm.received_tools[0], "the model is not even shown the tool"
    # The model asked for it anyway: the attempt is still recorded.
    refused = [e for e in h.entries() if e["tool"] == "agent:set_led"]
    assert refused and refused[0]["decision"] == "denied" and refused[0]["principal"] == "alice"
    assert "unknown tool" in refused[0]["detail"]


def test_deputy_refusal_is_recorded(tmp_path):
    # A visible tool with a forbidden argument: refused by the deputy itself.
    h = Harness(tmp_path, call("read_file", {"path": "secrets/api_keys.txt"}), answer("Not allowed."))
    h.send("Show me the API keys")
    assert h.mcp.calls == []
    refused = [e for e in h.entries() if e["tool"] == "deputy:read_file"]
    assert refused and refused[0]["decision"] == "denied" and "restricted path" in refused[0]["detail"]


def test_operator_can_actuate_through_the_assistant(tmp_path):
    h = Harness(tmp_path, call("set_led", {"device_id": "led-lab", "on": True, "color": "red"}), answer("Done."))
    assert h.send("Red LED on", principal="bob") == "Done."
    assert h.mcp.calls == [("set_led", {"device_id": "led-lab", "on": True, "color": "red"})]
    assert h.mcp.world.actuation_history[-1]["principal"] == "ops-agent"


def test_anonymous_requester_gets_only_public_tools(tmp_path):
    h = Harness(tmp_path, answer("Sunny."))
    h.send("Weather?", principal=None)
    assert h.llm.received_tools[0] == {"calculate", "get_weather", "get_server_status"}
    assert h.entries()[-1]["principal"] == "anonymous"


@pytest.mark.parametrize("auth", ["Bearer forged", "Basic abc"])
def test_bad_token_is_rejected_before_any_work(tmp_path, auth):
    h = Harness(tmp_path)
    reply = h.send("Read secrets", raw_auth=auth)
    assert reply.startswith("Authentication failed")
    assert h.connected_as == [] and h.llm.received_tools == []
    e = h.entries()[0]
    assert e["decision"] == "denied" and e["principal"] == "unknown"


@pytest.mark.parametrize("text", ["   ", "x" * (EXEC.MAX_TASK_CHARS + 1)])
def test_bad_task_size_refused(tmp_path, text):
    h = Harness(tmp_path)
    assert "1-2000 characters" in h.send(text)
    assert h.connected_as == []


def test_failures_are_masked_but_audited(tmp_path):
    h = Harness(tmp_path, connect_fails=True)
    reply = h.send("Lab temperature?")
    assert reply == EXEC.FAILURE_ANSWER
    assert "internal detail" not in reply
    e = h.entries()[-1]
    assert e["decision"] == "error" and "internal detail" in e["detail"]


def test_model_without_answer_gets_fallback(tmp_path):
    h = Harness(tmp_path, *[call("get_server_status", {}) for _ in range(8)])
    assert h.send("loop forever") == EXEC.FALLBACK_ANSWER
