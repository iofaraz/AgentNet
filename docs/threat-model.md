# AgentNet — Threat Model

## 1. Introduction

AgentNet focuses on identifying malicious and suspicious activities in AI agent networks that use the Model Context Protocol (MCP) and Agent2Agent (A2A) protocols.

This threat model defines the system's assets, potential attackers, attack surfaces, security threats, and detection objectives.

## 2. System Assets

The following assets require protection:

- **Agent Communication:** Messages exchanged between MCP clients, MCP servers, and A2A agents.
- **Tools and Services:** Tools exposed by MCP servers and services accessed by agents.
- **Agent Identity:** Agent names, capabilities, and A2A agent-card information.
- **Sensitive Data:** Information processed or exchanged during agent interactions.
- **Device Operations:** Actions performed by connected hardware devices.
- **Network Traffic:** Communication patterns and session metadata.
- **Dataset Integrity:** Correct labels and reliable traffic records used for model training and evaluation.

## 3. Potential Attackers

AgentNet considers the following potential attacker categories:

1. **Malicious Tool Provider:** A tool provider that exposes deceptive or modified tools.
2. **Compromised Agent:** An agent whose behavior has been manipulated or whose credentials have been compromised.
3. **Malicious External Agent:** An unauthorized agent attempting to interact with legitimate agents.
4. **Malicious User or Input Source:** An entity supplying harmful or misleading instructions through otherwise valid interactions.
5. **Network-Level Attacker:** An entity attempting to observe, manipulate, or exploit agent communication.

These categories describe the threat scenarios considered in the controlled testbed.

## 4. Attack Surfaces

The main attack surfaces include:

- MCP tool discovery and invocation.
- MCP client-server communication.
- A2A agent communication.
- Tool descriptions and tool outputs.
- Agent identity and capability information.
- HTTP-based network endpoints.
- TLS-encrypted communication metadata.
- Connections between agents and physical devices.

## 5. Threat Scenarios

AgentNet considers the following security threats:

### 5.1 Tool Poisoning

A tool description or its advertised behavior is manipulated to mislead an agent into selecting or using a tool in an unintended way.

### 5.2 Tool Rug Pull

A tool's behavior changes after it has initially been discovered or trusted by an agent.

### 5.3 Prompt Injection Through Tool Output

Untrusted content returned by a tool attempts to influence an agent's subsequent instructions or decisions.

### 5.4 Confused Deputy

An agent is manipulated into using its legitimate permissions to perform an action that the requesting party should not be authorized to perform.

### 5.5 Data Exfiltration

Sensitive information is transferred to an unauthorized destination through agent interactions.

### 5.6 Agent-Card Spoofing

An unauthorized agent presents misleading identity or capability information to appear as a legitimate A2A agent.

### 5.7 Unauthorized Physical Actuation

An agent attempts to trigger a physical device operation without the required authorization.

## 6. Trust Boundaries

The system contains several trust boundaries:

- **Agent-to-Agent Boundary:** Communication between independent A2A agents.
- **Client-to-Server Boundary:** Communication between MCP clients and MCP servers.
- **Tool-to-Agent Boundary:** Information returned by external or connected tools.
- **Network Boundary:** Traffic passing between different network components.
- **Software-to-Hardware Boundary:** Communication between software agents and physical devices.

AgentNet monitors relevant network communication across these boundaries.

## 7. Security Assumptions

The project uses the following assumptions:

- The software testbed operates in a controlled environment.
- Attack scenarios are simulated using authorized test components.
- Benign and attack traffic can be generated and labeled separately.
- Some communication may be encrypted using TLS.
- Plaintext protocol information is available only where encryption does not prevent inspection.
- Network-level metadata remains available for analysis in encrypted sessions.
- The initial project scope focuses on HTTP-based MCP and A2A transports.

## 8. Detection Objectives

AgentNet aims to:

1. Identify suspicious MCP and A2A communication patterns.
2. Detect malicious sessions using protocol-aware features when traffic is readable.
3. Detect suspicious encrypted sessions using packet sizes, directions, and timing patterns.
4. Reduce false positives during normal agent communication.
5. Evaluate detection performance against unseen agents, servers, and attack variations.
6. Test whether a detector trained on software-generated traffic can generalize to hardware-based traffic.

## 9. Scope and Limitations

This project focuses on network-level intrusion detection rather than complete protection of AI agents or their internal reasoning processes.

The system does not guarantee prevention of every attack. Its effectiveness depends on the quality and diversity of the dataset, available network features, and evaluation conditions.

MCP stdio transport is excluded because it does not produce network traffic for the intended network-level analysis.