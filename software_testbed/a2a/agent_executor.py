"""The AgentNet Lab Assistant: an LLM-driven A2A agent that uses MCP tools.

For each A2A message:

    1. identify the requester from "Authorization: Bearer <token>"
       (the same synthetic identities as the MCP server; no header = anonymous)
    2. connect to the MCP server with the assistant's own service account
    3. let the model complete the request (software_testbed/llm/agent.py),
       through the deputy check that enforces the requester's role (deputy.py)
    4. reply with the model's answer

Every request is written to the A2A audit log: requester, task, the tools
used, and every call the deputy check refused or filtered. Attack scenarios
use this log, together with the MCP audit log, as ground truth.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue

_TESTBED = Path(__file__).resolve().parent.parent
for _folder in ("mcp", "llm"):
    if str(_TESTBED / _folder) not in sys.path:
        sys.path.append(str(_TESTBED / _folder))

import agent as llm_agent                      # noqa: E402
from audit import ALLOWED, DENIED, ERROR, AuditLog  # noqa: E402
from workspace import AccessDenied, World      # noqa: E402

from deputy import DeputySession               # noqa: E402

SERVICE_PRINCIPAL = "ops-agent"   # the assistant's own MCP account (admin)
MAX_TASK_CHARS = 2000

FALLBACK_ANSWER = "Sorry, I could not complete that request."
FAILURE_ANSWER = "Sorry, the assistant failed to process the request."


def _default_llm():
    return llm_agent.OllamaChat()


class LabAssistantExecutor(AgentExecutor):
    """Answers lab requests with an LLM agent and the MCP server's tools.

    connect_mcp(principal) must return an async context manager yielding an
    entered MCP client session; llm_factory() returns an OllamaChat-like
    object. Both are injectable so the agent can be tested without a network.
    """

    def __init__(self, world: World, audit: AuditLog, connect_mcp: Callable,
                 llm_factory: Callable = _default_llm) -> None:
        self.world = world
        self.audit = audit
        self.connect_mcp = connect_mcp
        self.llm_factory = llm_factory

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        headers = (context.call_context.state or {}).get("headers") or {}
        task = (context.get_user_input() or "").strip()
        request_id = (context.call_context.state or {}).get("request_id")

        try:
            requester = self.world.caller(headers.get("authorization"))
        except AccessDenied as e:
            self.audit.record(tool="a2a_task", principal="unknown", role="unknown",
                              args={"task": task}, decision=DENIED, detail=str(e), request_id=request_id)
            await event_queue.enqueue_event(new_text_message("Authentication failed: unknown or invalid token."))
            return

        who = {"principal": requester.principal, "role": requester.role}
        if not task or len(task) > MAX_TASK_CHARS:
            self.audit.record(tool="a2a_task", **who, args={"task": task}, decision=DENIED,
                              detail=f"task must be 1-{MAX_TASK_CHARS} characters", request_id=request_id)
            await event_queue.enqueue_event(new_text_message(
                f"Please send a request of 1-{MAX_TASK_CHARS} characters."))
            return

        llm = self.llm_factory()
        try:
            async with self.connect_mcp(SERVICE_PRINCIPAL) as session:
                deputy = DeputySession(session, requester.role)
                result = await llm_agent.run_agent(
                    task, deputy, llm, principal=f"{requester.principal} (role: {requester.role})")
        except Exception as e:  # never leak internals to the requester
            self.audit.record(tool="a2a_task", **who, args={"task": task}, decision=ERROR,
                              detail=f"{type(e).__name__}: {e}", request_id=request_id)
            await event_queue.enqueue_event(new_text_message(FAILURE_ANSWER))
            return
        finally:
            aclose = getattr(llm, "aclose", None)
            if aclose:
                await aclose()

        # Calls the agent refused before the deputy saw them: tools hidden from
        # this requester (the model asked anyway), unknown tools, bad arguments.
        # Recorded because attempts matter as much as successes.
        for step in result.steps:
            if not step.sent:
                self.audit.record(tool=f"agent:{step.tool}", **who, args=step.arguments,
                                  decision=DENIED, detail=step.result, request_id=request_id)
        for d in deputy.decisions:
            if d.outcome != "forwarded":
                self.audit.record(tool=f"deputy:{d.tool}", **who, args=d.arguments,
                                  decision=DENIED if d.outcome == "refused" else ALLOWED,
                                  detail=f"{d.outcome}: {d.detail}", request_id=request_id)
        self.audit.record(
            tool="a2a_task", **who, args={"task": task}, decision=ALLOWED,
            detail=(f"tools={','.join(result.tools_called) or '-'}; finished={result.finished}; "
                    f"model={result.model}; seed={result.seed}"),
            request_id=request_id,
        )
        await event_queue.enqueue_event(new_text_message(result.answer or FALLBACK_ANSWER))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise RuntimeError("Cancellation is not supported.")
