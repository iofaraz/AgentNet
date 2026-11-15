
import asyncio
from mcp import Client


async def main():
    server_url = "http://127.0.0.1:8000/mcp"

    print("Connecting to AgentNet MCP Server...")

    async with Client(server_url) as client:
        print("\nConnected successfully!")

        # 1. Discover available tools
        print("\n--- Available Tools ---")

        tools_result = await client.list_tools()

        for tool in tools_result.tools:
            print(f"- {tool.name}: {tool.description}")

        # 2. Test calculate_sum
        print("\n--- Testing calculate_sum ---")

        result = await client.call_tool(
            "calculate_sum",
            {"a": 10, "b": 20}
        )
        print("Result:", result.structured_content)

        # 3. Test get_weather
        print("\n--- Testing get_weather ---")

        result = await client.call_tool(
            "get_weather",
            {"city": "Islamabad"}
        )
        print("Result:", result.content)

        # 4. Test get_system_info
        print("\n--- Testing get_system_info ---")

        result = await client.call_tool(
            "get_system_info",
            {}
        )
        print("Result:", result.content)

        print("\nAll MCP tests completed!")


if __name__ == "__main__":
    asyncio.run(main())
