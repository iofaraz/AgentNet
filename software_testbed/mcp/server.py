from mcp.server.mcpserver import MCPServer
import platform
import sys

# Initialize MCP server
mcp = MCPServer(
    "AgentNet MCP Server",
    instructions="A local MCP server for AgentNet network experiments.",
    version="1.0.0"
)


# Tool 1: Calculate sum
@mcp.tool()
def calculate_sum(a: float, b: float) -> float:
    """Calculate the sum of two numbers."""
    return a + b


# Tool 2: Get sample weather
@mcp.tool()
def get_weather(city: str) -> str:
    """Return sample weather information for a city."""
    return (
        f"Sample weather for {city}: "
        "Temperature: 25°C, Condition: Sunny"
    )


# Tool 3: Get system information
@mcp.tool()
def get_system_info() -> str:
    """Return basic information about the server environment."""
    return (
        f"Operating System: {platform.system()}\n"
        f"Python Version: {sys.version.split()[0]}\n"
        f"Machine: {platform.machine()}"
    )


if __name__ == "__main__":
    print("Starting AgentNet MCP Server...")
    print("Endpoint: http://127.0.0.1:8000/mcp")

    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8000
    )