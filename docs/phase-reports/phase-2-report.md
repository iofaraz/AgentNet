# AgentNet — Phase 2 Report

## Phase Name
MCP Software Testbed

## 1. Objective

Develop a functional MCP client-server environment using HTTP-based Streamable HTTP transport and generate benign network traffic for intrusion detection research.

## 2. Completed Tasks

- Installed and verified MCP Python SDK version 2.3.0.
- Implemented an MCP server using the installed SDK.
- Implemented three harmless MCP tools:
  - calculate_sum
  - get_weather
  - get_system_info
- Configured the server to listen locally on port 8000.
- Implemented an MCP client.
- Established successful client-server communication.
- Tested MCP tool discovery.
- Successfully invoked all three tools.
- Captured network traffic using Wireshark.
- Inspected HTTP and JSON-RPC communication.
- Saved an initial PCAP capture.
- Generated 10 repeated benign client runs.
- Saved a batch PCAP capture.
- Created an initial benign traffic manifest.

## 3. Implementation Details

**Programming Language:** Python

**MCP SDK:** 2.3.0

**Transport:** Streamable HTTP

**Server Endpoint:** http://127.0.0.1:8000/mcp

**Traffic Capture:** Wireshark with Npcap loopback capture.

## 4. Generated Files

| File | Description |
|---|---|
| `software_testbed/mcp/server.py` | MCP server implementation |
| `software_testbed/mcp/client.py` | MCP client implementation |
| `traffic/pcaps/mcp_benign_sample.pcapng` | Initial network capture |
| `traffic/pcaps/mcp_benign_batch_01.pcapng` | Batch capture of repeated client runs |
| `traffic/samples/mcp_benign_manifest.csv` | Initial traffic manifest |

## 5. Testing Results

- Server startup: Successful.
- Local port connectivity: Successful.
- Client-server connection: Successful.
- Tool discovery: Successful.
- Tool invocation: Successful.
- Network traffic capture: Successful.
- Batch traffic generation: Successful.

## 6. Outcome

A functional MCP software testbed has been established. It successfully generates normal MCP communication over Streamable HTTP, and its network traffic can be captured using Wireshark.

The generated captures and manifest provide initial material for subsequent dataset development.

## 7. Limitations

- Only the MCP software environment has been implemented in this phase.
- The current traffic manifest is capture-level rather than a fully extracted session-level dataset.
- A2A communication and controlled attack scenarios are planned for later phases.
- TLS traffic experiments have not yet been completed.

## 8. Next Phase

**Phase 3 — A2A Software Testbed and Benign Traffic Generation**

The next phase will implement A2A agents, test normal agent-to-agent communication, and expand benign traffic generation to include both MCP and A2A protocols.