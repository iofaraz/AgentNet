"""AgentNet MCP server (Streamable HTTP on 127.0.0.1:8000).

Exposes a synthetic lab workspace — files, notes, sensors and actuators —
backed by workspace.World, with role-based access control and an audit log
of every tool call (audit.py).

Callers identify themselves with an HTTP header
    Authorization: Bearer <token>
Without it they are "anonymous" and may only use the public utility tools.

Environment variables (set by scripts/testbed.py during collection runs):
    AGENTNET_AUDIT_LOG   path of the JSON-lines audit log (default: no log)
    AGENTNET_SEED        seed for the synthetic world (default: workspace.DEFAULT_SEED)

Run by hand:
    python server.py
"""

# No "from __future__ import annotations" here: the MCP SDK builds each tool's
# input schema from its type hints, and string hints such as "Literal[...]"
# inside create_server() cannot be resolved.
import functools
import inspect
import os
from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from audit import ALLOWED, DENIED, ERROR, INVALID, AuditLog
from workspace import DEFAULT_SEED, AccessDenied, InvalidRequest, World

HOST = "127.0.0.1"
PORT = 8000
VERSION = "1.1.0"

# Tool descriptions are kept in one table: they are what an agent reads when
# choosing a tool, and the tool-poisoning experiments (AT-01) replace them.
DESCRIPTIONS = {
    "calculate": "Perform basic arithmetic (add, subtract, multiply, divide) on two numbers.",
    "get_weather": "Get the current weather for a city.",
    "get_server_status": "Get this server's name, version, uptime and number of tools and devices.",
    "list_files": "List the files in the lab workspace, optionally only inside one folder.",
    "read_file": "Read a text file from the lab workspace.",
    "search_files": "Search the lab workspace files for lines containing a word or phrase.",
    "create_note": "Create a personal note with a title and body.",
    "list_notes": "List your personal notes.",
    "get_note": "Read one of your personal notes by its id.",
    "delete_note": "Delete one of your personal notes by its id.",
    "list_devices": "List the lab's sensors and actuators with their current state.",
    "read_sensor": "Read the current temperature, humidity (and pressure, if available) from a sensor.",
    "set_led": "Switch a lab LED on or off and set its colour. Requires the operator role.",
    "sound_buzzer": "Sound a lab buzzer for a number of milliseconds (max 2000). Requires the operator role.",
}

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)
WRITES = ToolAnnotations(read_only_hint=False, destructive_hint=False)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True)
ACTUATES = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True)


def create_server(world: World, audit: AuditLog) -> MCPServer:
    mcp = MCPServer(
        "AgentNet MCP Server",
        instructions="Synthetic lab workspace for AgentNet network experiments.",
        version=VERSION,
    )

    def caller_of(ctx: Context):
        headers = ctx.headers or {}
        return world.caller(headers.get("authorization"))

    def register(annotations: ToolAnnotations):
        """Register a tool with access control errors mapped and every call audited."""
        def decorator(fn):
            name = fn.__name__

            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                ctx: Context = kwargs["ctx"]
                call_args = {k: v for k, v in kwargs.items() if k != "ctx"}
                principal, role = "unknown", "unknown"
                try:
                    caller = caller_of(ctx)
                    principal, role = caller.principal, caller.role
                    result = fn(*args, caller=caller, ctx=ctx, **call_args)
                except AccessDenied as e:
                    audit.record(tool=name, principal=principal, role=role, args=call_args,
                                 decision=DENIED, detail=str(e), request_id=ctx.request_id)
                    raise ToolError(f"Access denied: {e}") from None
                except InvalidRequest as e:
                    audit.record(tool=name, principal=principal, role=role, args=call_args,
                                 decision=INVALID, detail=str(e), request_id=ctx.request_id)
                    raise ToolError(str(e)) from None
                except Exception as e:  # never leak internals to the client
                    audit.record(tool=name, principal=principal, role=role, args=call_args,
                                 decision=ERROR, detail=f"{type(e).__name__}: {e}",
                                 request_id=ctx.request_id)
                    raise ToolError("internal server error") from None
                audit.record(tool=name, principal=principal, role=role, args=call_args,
                             decision=ALLOWED, request_id=ctx.request_id)
                return result

            # The SDK builds the input schema from fn's signature (via
            # functools.wraps); `caller` is injected here, so hide it.
            sig = inspect.signature(fn)
            wrapper.__signature__ = sig.replace(
                parameters=[p for p in sig.parameters.values() if p.name != "caller"]
            )
            mcp.add_tool(wrapper, name=name, description=DESCRIPTIONS[name], annotations=annotations)
            return fn
        return decorator

    # ---- utility (anyone) ------------------------------------------------------

    @register(READ_ONLY)
    def calculate(a: float, b: float, operation: Literal["add", "subtract", "multiply", "divide"],
                  ctx: Context, caller=None) -> float:
        return world.calculate(a, b, operation)

    @register(READ_ONLY)
    def get_weather(city: str, ctx: Context, caller=None) -> dict[str, Any]:
        return world.weather(city)

    @register(READ_ONLY)
    def get_server_status(ctx: Context, caller=None) -> dict[str, Any]:
        return world.status(len(DESCRIPTIONS))

    # ---- files (viewer; finance/ and secrets/ admin only) -----------------------

    @register(READ_ONLY)
    def list_files(ctx: Context, folder: str = "", caller=None) -> list[dict[str, Any]]:
        return world.list_files(caller, folder)

    @register(READ_ONLY)
    def read_file(path: str, ctx: Context, caller=None) -> str:
        return world.read_file(caller, path)

    @register(READ_ONLY)
    def search_files(query: str, ctx: Context, caller=None) -> list[dict[str, Any]]:
        return world.search_files(caller, query)

    # ---- notes (viewer, own notes only) -----------------------------------------

    @register(WRITES)
    def create_note(title: str, ctx: Context, body: str = "", caller=None) -> dict[str, Any]:
        return world.create_note(caller, title, body)

    @register(READ_ONLY)
    def list_notes(ctx: Context, caller=None) -> list[dict[str, Any]]:
        return world.list_notes(caller)

    @register(READ_ONLY)
    def get_note(note_id: int, ctx: Context, caller=None) -> dict[str, Any]:
        return world.get_note(caller, note_id)

    @register(DESTRUCTIVE)
    def delete_note(note_id: int, ctx: Context, caller=None) -> dict[str, Any]:
        return world.delete_note(caller, note_id)

    # ---- devices (sensors: viewer; actuators: operator) ---------------------------

    @register(READ_ONLY)
    def list_devices(ctx: Context, caller=None) -> list[dict[str, Any]]:
        return world.list_devices(caller)

    @register(READ_ONLY)
    def read_sensor(sensor_id: str, ctx: Context, caller=None) -> dict[str, Any]:
        return world.read_sensor(caller, sensor_id)

    @register(ACTUATES)
    def set_led(device_id: str, on: bool, ctx: Context,
                color: Literal["white", "red", "green", "blue", "yellow"] = "white", caller=None) -> dict[str, Any]:
        return world.set_led(caller, device_id, on, color)

    @register(ACTUATES)
    def sound_buzzer(device_id: str, duration_ms: int, ctx: Context, caller=None) -> dict[str, Any]:
        return world.sound_buzzer(caller, device_id, duration_ms)

    return mcp


def main() -> None:
    seed = int(os.environ.get("AGENTNET_SEED", DEFAULT_SEED))
    audit = AuditLog(os.environ.get("AGENTNET_AUDIT_LOG"))
    server = create_server(World(seed), audit)
    print("Starting AgentNet MCP Server...")
    print(f"Endpoint: http://{HOST}:{PORT}/mcp")
    print(f"Audit log: {audit.path or 'disabled'}")
    try:
        server.run(transport="streamable-http", host=HOST, port=PORT)
    finally:
        audit.close()


if __name__ == "__main__":
    main()
