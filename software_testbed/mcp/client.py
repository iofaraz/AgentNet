"""AgentNet MCP client.

Run directly to exercise the MCP server by hand:
    python client.py

exercise_tools() is also used by the session runner, so it returns what the
server answered instead of only printing it.

The client authenticates as a synthetic user with an
"Authorization: Bearer <token>" header, as real MCP deployments do.
"""

import asyncio
import os

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from workspace import DEFAULT_SEED, World

SERVER_URL = "http://127.0.0.1:8000/mcp"
HTTP_TIMEOUT = 30.0


def token_for(principal: str) -> str:
    """Bearer token of a synthetic user (same seed as the server)."""
    seed = int(os.environ.get("AGENTNET_SEED", DEFAULT_SEED))
    return World(seed).token_for(principal)


def connect(principal: str | None, server_url: str = SERVER_URL):
    """An HTTP client carrying the user's token, for use with mcp.Client.

    principal=None connects anonymously (no Authorization header).
    """
    headers = {"Authorization": f"Bearer {token_for(principal)}"} if principal else {}
    return httpx2.AsyncClient(headers=headers, timeout=HTTP_TIMEOUT)


def _text(result) -> str:
    """Join the text parts of a tool result."""
    return "".join(getattr(part, "text", "") for part in result.content)


def _value(result):
    """The structured value of a tool result (unwrapping {"result": ...})."""
    data = result.structured_content
    if isinstance(data, dict) and set(data) == {"result"}:
        return data["result"]
    return data


async def exercise_tools(server_url: str = SERVER_URL, principal: str = "alice") -> dict:
    """Discover the server's tools and use a typical viewer's set of them.

    Returns the tool list and every tool's answer.
    """
    async with connect(principal, server_url) as http:
        async with Client(streamable_http_client(server_url, http_client=http)) as client:
            tools = await client.list_tools()
            total = await client.call_tool("calculate", {"a": 10, "b": 20, "operation": "add"})
            weather = await client.call_tool("get_weather", {"city": "Islamabad"})
            files = await client.call_tool("list_files", {})
            faq = await client.call_tool("read_file", {"path": "public/faq.md"})
            sensor = await client.call_tool("read_sensor", {"sensor_id": "dht22-lab"})

    results = {"calculate": total, "get_weather": weather, "list_files": files,
               "read_file": faq, "read_sensor": sensor}
    errors = {name: _text(r) for name, r in results.items() if r.is_error}
    return {
        "tools": [(tool.name, tool.description) for tool in tools.tools],
        "errors": errors,
        **{name: _value(r) for name, r in results.items() if not r.is_error},
    }


async def main():
    print("Connecting to AgentNet MCP Server as 'alice' (viewer)...")
    results = await exercise_tools()
    print("\nConnected successfully!")

    print(f"\n--- Available Tools ({len(results['tools'])}) ---")
    for name, description in results["tools"]:
        print(f"- {name}: {description}")

    for name in ("calculate", "get_weather", "list_files", "read_file", "read_sensor"):
        print(f"\n--- {name} ---")
        print("Result:", results.get(name, f"ERROR: {results['errors'].get(name)}"))

    print("\nAll MCP tests completed!")


if __name__ == "__main__":
    asyncio.run(main())
