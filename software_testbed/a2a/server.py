"""AgentNet Lab Assistant — A2A server (JSON-RPC over HTTP; address from software_testbed/addresses.py).

An LLM-driven agent that answers lab requests using the MCP server's tools
(see agent_executor.py). The Agent Card declares bearer-token
authentication; requesters use the same synthetic identities as the MCP
server.

Environment variables (set by scripts/testbed.py during collection runs):
    AGENTNET_AUDIT_LOG   path of the A2A JSON-lines audit log (default: no log)
    AGENTNET_SEED        seed for the synthetic identities (default: workspace.DEFAULT_SEED)

Run by hand (the MCP server must be running):
    python server.py
"""

from __future__ import annotations

import contextlib
import os

import httpx2
import uvicorn
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    HTTPAuthSecurityScheme,
    SecurityRequirement,
    SecurityScheme,
)
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from agent_executor import LabAssistantExecutor
from audit import AuditLog
from workspace import DEFAULT_SEED, World

import sys  # noqa: E402
from pathlib import Path  # noqa: E402

sys.path.append(str(Path(__file__).resolve().parent.parent))
import addresses  # noqa: E402

HOST = addresses.A2A_HOST
PORT = addresses.A2A_PORT
VERSION = "2.0.0"
MCP_URL = addresses.MCP_URL
MCP_TIMEOUT = 30.0


def build_card() -> AgentCard:
    card = AgentCard(
        name="AgentNet Lab Assistant",
        description=("An AI assistant for the AgentNet lab. Answers questions about lab sensors, "
                     "devices, documents and weather, and controls lab devices for authorised users."),
        version=VERSION,
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        supported_interfaces=[
            AgentInterface(protocol_binding="JSONRPC", url=f"http://{HOST}:{PORT}/", protocol_version="1.0"),
        ],
        skills=[
            AgentSkill(
                id="lab-information",
                name="Lab information",
                description="Sensor readings, device status, lab documents and weather.",
                tags=["sensors", "documents", "weather"],
                examples=["What is the temperature in the lab?", "Which documents are in the docs folder?"],
            ),
            AgentSkill(
                id="device-control",
                name="Device control",
                description="Switch lab LEDs and sound buzzers (operator role required).",
                tags=["devices", "actuators"],
                examples=["Turn on the lab LED in green."],
            ),
        ],
        security_schemes={
            "bearer": SecurityScheme(http_auth_security_scheme=HTTPAuthSecurityScheme(
                scheme="Bearer", bearer_format="opaque", description="AgentNet lab token")),
        },
    )
    card.security_requirements.append(SecurityRequirement(schemes={"bearer": {}}))
    return card


def mcp_connector(world: World, url: str = MCP_URL):
    """Returns connect(principal): an MCP session authenticated as that principal."""

    @contextlib.asynccontextmanager
    async def connect(principal: str):
        token = world.token_for(principal)
        # MCP calls leave from the assistant's own host address.
        transport = httpx2.AsyncHTTPTransport(local_address=addresses.workstation(principal))
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=MCP_TIMEOUT,
                                      transport=transport) as http:
            async with Client(streamable_http_client(url, http_client=http)) as session:
                yield session

    return connect


def build_app(executor, card: AgentCard | None = None) -> Starlette:
    card = card or build_card()
    handler = DefaultRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card)
    routes = []
    routes.extend(create_agent_card_routes(card))
    routes.extend(create_jsonrpc_routes(handler, "/"))
    return Starlette(routes=routes)


def main() -> None:
    world = World(int(os.environ.get("AGENTNET_SEED", DEFAULT_SEED)))
    audit = AuditLog(os.environ.get("AGENTNET_AUDIT_LOG"))
    app = build_app(LabAssistantExecutor(world, audit, mcp_connector(world)))
    print("Starting AgentNet Lab Assistant (A2A)...")
    print(f"Endpoint: http://{HOST}:{PORT}/")
    print(f"Agent Card: http://{HOST}:{PORT}/.well-known/agent-card.json")
    print(f"Audit log: {audit.path or 'disabled'}")
    try:
        uvicorn.run(app, host=HOST, port=PORT)
    finally:
        audit.close()


if __name__ == "__main__":
    main()
