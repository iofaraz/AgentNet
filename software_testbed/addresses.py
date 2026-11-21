"""Network address plan of the software testbed.

Every testbed component has its own address inside 127.77.0.0/16, so a
capture looks like traffic between separate hosts (users' workstations, the
A2A assistant, the MCP server, and — in attack scenarios — attacker hosts)
rather than one machine talking to itself.

The whole 127.0.0.0/8 range is the loopback network: these addresses never
leave the computer. They are kept out of 127.0.0.1, where other local
programs (Ollama, editors, Docker) run, so one capture filter selects all
testbed traffic and nothing else.

All components read their addresses from here; no address is written
anywhere else.
"""

TESTBED_NET = "127.77.0.0/16"
CAPTURE_FILTER = f"net {TESTBED_NET}"

# Servers
MCP_HOST, MCP_PORT = "127.77.1.10", 8000        # MCP tool server
A2A_HOST, A2A_PORT = "127.77.2.10", 9999        # A2A Lab Assistant (also the source of its MCP calls)

MCP_URL = f"http://{MCP_HOST}:{MCP_PORT}/mcp"
A2A_URL = f"http://{A2A_HOST}:{A2A_PORT}"

# Workstations: the address each identity's requests come from.
WORKSTATIONS = {
    "alice": "127.77.3.11",
    "bob": "127.77.3.12",
    "dana": "127.77.3.13",
    "reporter-agent": "127.77.3.14",
    "anonymous": "127.77.3.20",
    "ops-agent": A2A_HOST,       # the assistant's service account is used from the assistant's host
}

# Reserved for attacker infrastructure in attack scenarios (Part 4).
ATTACKER_NET = "127.77.9.0/24"


def workstation(principal: str | None) -> str:
    """Source address for requests made as `principal` (None = anonymous)."""
    try:
        return WORKSTATIONS[principal or "anonymous"]
    except KeyError:
        raise KeyError(f"no workstation address for {principal!r}") from None
