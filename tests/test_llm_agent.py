"""Tests for the LLM-driven MCP agent (software_testbed/llm/agent.py).

* Agent loop with a scripted fake model against the real MCP server
  in-process (no network, deterministic).
* Ollama client against a mocked HTTP transport.
* Real Ollama + real MCP server over HTTP + real capture (skipped if Ollama
  or the model is unavailable).
"""

import asyncio
import importlib.util
import json
import sys

import httpx
import pytest

import testbed

sys.path.insert(0, str(testbed.TESTBED / "llm"))
sys.path.insert(0, str(testbed.TESTBED / "mcp"))

import agent as G          # noqa: E402
import audit as A          # noqa: E402
import workspace as W      # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


S = _load("agentnet_mcp_server_g", testbed.TESTBED / "mcp" / "server.py")


class FakeLLM:
    """Returns scripted assistant messages and records what it was sent."""

    model, seed, temperature = "fake-model", 123, 0.0

    def __init__(self, *replies):
        self.replies = list(replies)
        self.received = []

    async def chat(self, messages, tools):
        self.received.append((json.loads(json.dumps(messages)), tools))
        if not self.replies:
            raise AssertionError("model called more often than scripted")
        return self.replies.pop(0)


def call(name, arguments):
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": arguments}}]}


def answer(text):
    return {"role": "assistant", "content": text}


def run(task, llm, audit_log=None, **kw):
    from mcp import Client

    async def go():
        async with Client(S.create_server(W.World(), audit_log or A.AuditLog(None))) as session:
            return await G.run_agent(task, session, llm, **kw)
    return asyncio.run(go())


# ---- the loop ---------------------------------------------------------------

def test_tool_call_then_answer():
    llm = FakeLLM(call("calculate", {"a": 6, "b": 7, "operation": "multiply"}), answer("It is 42."))
    r = run("What is 6 times 7?", llm)
    assert r.finished and r.answer == "It is 42."
    assert r.tools_called == ["calculate"]
    assert r.steps[0].sent and not r.steps[0].is_error and "42" in r.steps[0].result
    assert r.llm_calls == 2 and r.model == "fake-model" and r.seed == 123


def test_model_sees_exactly_the_server_tools():
    llm = FakeLLM(answer("hi"))
    run("hello", llm)
    _, tools = llm.received[0]
    names = {t["function"]["name"] for t in tools}
    assert names == set(S.DESCRIPTIONS)
    by_name = {t["function"]["name"]: t["function"] for t in tools}
    assert by_name["read_file"]["description"] == S.DESCRIPTIONS["read_file"]
    assert by_name["calculate"]["parameters"]["properties"]["operation"]["enum"]
    assert all(t["type"] == "function" for t in tools)


def test_conversation_format_sent_to_the_model():
    llm = FakeLLM(call("get_weather", {"city": "Karachi"}), answer("Humid."))
    run("Weather in Karachi?", llm, principal="alice")
    first, _ = llm.received[0]
    assert first[0]["role"] == "system" and "alice" in first[0]["content"]
    assert first[1] == {"role": "user", "content": "Weather in Karachi?"}
    second, _ = llm.received[1]
    assert second[2]["role"] == "assistant" and second[2]["tool_calls"]
    tool_msg = second[3]
    assert tool_msg["role"] == "tool" and tool_msg["tool_name"] == "get_weather"
    assert "Karachi" in tool_msg["content"]


def test_json_string_arguments_are_accepted():
    llm = FakeLLM(call("calculate", '{"a": 1, "b": 2, "operation": "add"}'), answer("3"))
    r = run("1+2", llm)
    assert r.steps[0].sent and not r.steps[0].is_error and r.steps[0].arguments == {"a": 1, "b": 2, "operation": "add"}


@pytest.mark.parametrize("bad", ["{not json", "[1, 2]", 42])
def test_malformed_arguments_are_rejected_locally(bad, tmp_path):
    log = A.AuditLog(tmp_path / "a.jsonl")
    llm = FakeLLM(call("calculate", bad), answer("sorry"))
    r = run("x", llm, audit_log=log)
    log.close()
    assert not r.steps[0].sent and r.steps[0].is_error
    assert A.read(tmp_path / "a.jsonl") == [], "nothing may reach the server"
    tool_msg = llm.received[1][0][-1]
    assert tool_msg["role"] == "tool" and tool_msg["content"].startswith("Error:")


def test_unknown_tool_is_not_sent(tmp_path):
    log = A.AuditLog(tmp_path / "a.jsonl")
    llm = FakeLLM(call("delete_everything", {}), answer("cannot"))
    r = run("x", llm, audit_log=log)
    log.close()
    assert r.steps[0].tool == "delete_everything" and not r.steps[0].sent
    assert "unknown tool" in r.steps[0].result
    assert A.read(tmp_path / "a.jsonl") == []


def test_server_errors_are_shown_to_the_model():
    llm = FakeLLM(call("list_files", {}), answer("Not allowed."))   # in-process = anonymous
    r = run("List files", llm)
    assert r.steps[0].sent and r.steps[0].is_error and "Access denied" in r.steps[0].result
    assert "Access denied" in llm.received[1][0][-1]["content"]


def test_step_limit_stops_a_looping_model():
    llm = FakeLLM(*[call("get_server_status", {}) for _ in range(3)])
    r = run("loop", llm, max_steps=3)
    assert not r.finished and r.answer == "" and r.llm_calls == 3 and len(r.steps) == 3


def test_calls_per_turn_are_capped():
    many = {"role": "assistant", "content": "",
            "tool_calls": [{"function": {"name": "get_server_status", "arguments": {}}}] * (G.MAX_CALLS_PER_TURN + 2)}
    llm = FakeLLM(many, answer("done"))
    r = run("x", llm)
    assert len(r.steps) == G.MAX_CALLS_PER_TURN
    refused = [m for m in llm.received[1][0] if m["role"] == "tool" and "at most" in m["content"]]
    assert len(refused) == 2


def test_long_results_are_truncated_for_the_model():
    llm = FakeLLM(call("calculate", {"a": 1, "b": 1, "operation": "add"}), answer("ok"))
    from mcp import Client

    async def go():
        server = S.create_server(W.World(), A.AuditLog(None))
        server.remove_tool("calculate")

        def calculate(a: float, b: float, operation: str) -> str:
            return "x" * (G.MAX_RESULT_CHARS * 2)
        server.add_tool(calculate)
        async with Client(server) as session:
            return await G.run_agent("x", session, llm)
    r = asyncio.run(go())
    assert len(r.steps[0].result) < G.MAX_RESULT_CHARS + 100 and "truncated" in r.steps[0].result


def test_text_tool_call_is_executed_like_a_real_one():
    llm = FakeLLM(answer('{"name": "calculate", "parameters": {"a": 2, "b": 5, "operation": "add"}}'), answer("7"))
    r = run("2+5", llm)
    assert r.finished and r.answer == "7"
    assert r.tools_called == ["calculate"] and r.text_tool_calls == 1
    assert llm.received[1][0][2]["tool_calls"], "converted into a proper tool call in the conversation"


def test_text_tool_call_to_unknown_tool_is_refused(tmp_path):
    log = A.AuditLog(tmp_path / "a.jsonl")
    llm = FakeLLM(answer('{"name": "set LedColor", "parameters": {"id": "led"}}'), answer("I cannot do that."))
    r = run("LED", llm, audit_log=log)
    log.close()
    assert r.answer == "I cannot do that." and not r.steps[0].sent
    assert A.read(tmp_path / "a.jsonl") == []


def test_malformed_text_tool_call_gets_one_nudge():
    broken = '{"name":"set_led","parameters\\":{\\"on\\":true}}'
    llm = FakeLLM(answer(broken), answer("Please ask an operator."))
    r = run("LED", llm)
    assert r.finished and r.answer == "Please ask an operator." and r.steps == []
    nudge = llm.received[1][0][-1]
    assert nudge == {"role": "user", "content": G.TEXT_TOOL_CALL_NUDGE}


def test_tool_call_text_is_never_returned_as_the_answer():
    broken = '{"name": "x", oops'
    llm = FakeLLM(answer(broken), answer(broken))
    r = run("x", llm)
    assert not r.finished and r.answer == ""


def test_plain_json_answer_without_name_is_a_normal_answer():
    llm = FakeLLM(answer('{"temperature_c": 24.1}'))
    r = run("temp as json", llm)
    assert r.finished and r.answer == '{"temperature_c": 24.1}'


def test_empty_task_rejected_before_any_traffic():
    # Validated before the session is touched (session=None would fail otherwise).
    with pytest.raises(ValueError, match="empty"):
        asyncio.run(G.run_agent("   ", None, FakeLLM()))


# ---- Ollama client ------------------------------------------------------------

def _mock(handler):
    return httpx.MockTransport(handler)


def test_ollama_request_shape():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "hi"}})

    llm = G.OllamaChat("m", temperature=0.3, seed=9, transport=_mock(handler))
    msg = asyncio.run(llm.chat([{"role": "user", "content": "x"}], [{"type": "function"}]))
    asyncio.run(llm.aclose())
    assert msg == {"role": "assistant", "content": "hi"}
    assert seen["model"] == "m" and seen["stream"] is False and seen["tools"] == [{"type": "function"}]
    assert seen["options"] == {"temperature": 0.3, "seed": 9, "num_ctx": G.NUM_CTX}
    assert llm.calls == 1


def test_seed_is_always_recorded():
    assert isinstance(G.OllamaChat("m").seed, int)


@pytest.mark.parametrize("status, body, fragment", [
    (500, {"error": "boom"}, "HTTP 500"),
    (200, {"nope": 1}, "no 'message'"),
    (200, {"message": "text"}, "not an object"),
])
def test_ollama_errors(status, body, fragment):
    llm = G.OllamaChat("m", transport=_mock(lambda r: httpx.Response(status, json=body)))
    with pytest.raises(G.AgentError, match=fragment):
        asyncio.run(llm.chat([], []))


def test_ollama_unreachable():
    def handler(request):
        raise httpx.ConnectError("refused")
    llm = G.OllamaChat("m", transport=_mock(handler))
    with pytest.raises(G.AgentError, match="cannot reach Ollama"):
        asyncio.run(llm.chat([], []))


def test_temperature_bounds():
    with pytest.raises(ValueError):
        G.OllamaChat("m", temperature=3)


# ---- real Ollama ----------------------------------------------------------------

def _ollama_ready():
    try:
        asyncio.run(G.model_digest(G.DEFAULT_MODEL))
        return True
    except Exception:
        return False


needs_ollama = pytest.mark.skipif(
    not _ollama_ready() or testbed.MCP_SERVER.in_use(),
    reason="Ollama/model unavailable or port 8000 in use",
)


@needs_ollama
def test_real_model_reads_a_sensor_and_is_captured(tmp_path):
    """Real model + real server over HTTP + real capture through the session runner."""
    import manifest
    import runner
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    mc = _load("agentnet_mcp_client_g", testbed.TESTBED / "mcp" / "client.py")
    trace = {}

    async def scenario():
        llm = G.OllamaChat(temperature=0, seed=11)
        try:
            async with mc.connect("alice") as http:
                async with Client(streamable_http_client(mc.SERVER_URL, http_client=http)) as session:
                    r = await G.run_agent("What is the temperature at sensor dht22-lab?", session, llm, principal="alice")
        finally:
            await llm.aclose()
        trace["r"] = r
        if not any(s.tool == "read_sensor" and not s.is_error for s in r.steps):
            raise RuntimeError(f"model did not read the sensor: {r.tools_called}")
        return runner.Outcome(notes=f"llm={r.model} seed={r.seed} tools={','.join(r.tools_called)}")

    run_ = runner.SessionRunner(manifest_path=tmp_path / "m.csv", log_path=tmp_path / "l.csv",
                                capture_dir=tmp_path / "p", run_id="LLM-TEST")
    with testbed.running(testbed.MCP_SERVER, log_dir=tmp_path / "logs", run_id="LLM-TEST") as servers:
        res = run_.run(runner.Scenario(name="llm-sensor", protocol="MCP", attack_id="AT-00",
                                       bpf=testbed.MCP_SERVER.bpf, run=scenario, timeout=300))
        audit_path = servers[0].audit_path

    assert res.valid, res.reason
    r = trace["r"]
    assert r.finished and any(ch.isdigit() for ch in r.answer)
    assert f"llm={G.DEFAULT_MODEL}" in res.manifest_row["notes"]
    entries = A.read(audit_path)
    assert any(e["tool"] == "read_sensor" and e["principal"] == "alice" and e["decision"] == "allowed" for e in entries)
    assert manifest.load(tmp_path / "m.csv")[1].ok


@needs_ollama
def test_model_digest_is_reported():
    assert asyncio.run(G.model_digest(G.DEFAULT_MODEL))
    with pytest.raises(G.AgentError):
        asyncio.run(G.model_digest("no-such-model:1b"))
