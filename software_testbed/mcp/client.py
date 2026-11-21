"""AgentNet MCP client.

Run directly to exercise the MCP server by hand:
    python client.py

exercise_tools() is also used by the session runner, so it returns what the
server answered instead of only printing it.
"""

import asyncio

from mcp import Client

SERVER_URL = "http://127.0.0.1:8000/mcp"


def _text(result) -> str:
    """Join the text parts of a tool result."""
    return "".join(getattr(part, "text", "") for part in result.content)


async def exercise_tools(server_url: str = SERVER_URL) -> dict:
    """Discover the server's tools and call each one once.

    Returns the tool list and every tool's answer.
    """
    async with Client(server_url) as client:
        tools_result = await client.list_tools()
        total = await client.call_tool("calculate_sum", {"a": 10, "b": 20})
        weather = await client.call_tool("get_weather", {"city": "Islamabad"})
        system = await client.call_tool("get_system_info", {})

    return {
        "tools": [(tool.name, tool.description) for tool in tools_result.tools],
        "calculate_sum": total.structured_content,
        "get_weather": _text(weather),
        "get_system_info": _text(system),
    }


async def main():
    print("Connecting to AgentNet MCP Server...")
    results = await exercise_tools()
    print("\nConnected successfully!")

    print("\n--- Available Tools ---")
    for name, description in results["tools"]:
        print(f"- {name}: {description}")

    print("\n--- Testing calculate_sum ---")
    print("Result:", results["calculate_sum"])

    print("\n--- Testing get_weather ---")
    print("Result:", results["get_weather"])

    print("\n--- Testing get_system_info ---")
    print("Result:", results["get_system_info"])

    print("\nAll MCP tests completed!")


if __name__ == "__main__":
    asyncio.run(main())
