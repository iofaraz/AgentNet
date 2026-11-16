# AgentNet — Phase 3 Report

## Phase Name
A2A Software Testbed and Benign Traffic Generation

## 1. Objective
Develop a functional A2A software testbed using the official Python A2A SDK and generate benign agent-to-agent network traffic over HTTP.

## 2. Completed Tasks
- Installed and verified A2A Python SDK version 1.3.0.
- Implemented a deterministic Echo Agent.
- Configured an A2A server using the SDK's HTTP and JSON-RPC routes.
- Published an Agent Card for agent discovery.
- Implemented an A2A client using the SDK's client API.
- Successfully discovered the Echo Agent.
- Tested message sending and response handling.
- Generated 10 repeated benign A2A requests.
- Captured A2A network traffic using Wireshark.
- Saved an A2A batch PCAP capture.
- Added an A2A record to the benign traffic manifest.

## 3. Implementation Details
- **Programming Language:** Python
- **A2A SDK:** 1.3.0
- **Transport:** HTTP with JSON-RPC
- **Server Address:** http://127.0.0.1:9999
- **Agent:** AgentNet Echo Agent
- **Traffic Capture:** Wireshark with Npcap loopback adapter

## 4. Generated Files
| File | Description |
|---|---|
| `software_testbed/a2a/agent_executor.py` | Echo Agent execution logic |
| `software_testbed/a2a/server.py` | A2A server and Agent Card configuration |
| `software_testbed/a2a/client.py` | A2A client and repeated request generation |
| `traffic/pcaps/a2a_benign_batch_01.pcapng` | Captured benign A2A traffic |
| `traffic/samples/mcp_benign_manifest.csv` | Updated benign traffic manifest |

## 5. Testing Results
- A2A server startup: Successful.
- Agent Card discovery: Successful.
- Client-server communication: Successful.
- Message sending: Successful.
- Response handling: Successful.
- Repeated benign requests: 10 successful requests.
- Wireshark traffic capture: Successful.

## 6. Outcome
A functional A2A software testbed has been established. The Echo Agent successfully receives and responds to client messages over HTTP using the A2A protocol.

The generated PCAP capture and manifest entry provide initial benign A2A traffic for the AgentNet dataset.

## 7. Limitations
- The current agent uses deterministic responses rather than an LLM.
- Only benign A2A communication has been tested.
- HTTP traffic has been captured; TLS experiments are planned for later phases.
- The manifest currently contains capture-level records rather than individually extracted sessions.

## 8. Next Phase
**Phase 4 — Controlled Attack Scenario Implementation**

The next phase will introduce controlled, isolated attack scenarios against the MCP and A2A testbeds to generate labeled attack traffic for defensive intrusion-detection research.
