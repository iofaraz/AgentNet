# AgentNet — System Architecture

## 1. Project Overview

AgentNet is a network intrusion detection system designed for AI agent networks using the **Model Context Protocol (MCP)** and **Agent2Agent (A2A)** protocols.

The system aims to detect suspicious and malicious agent-network activities by analyzing network traffic. It uses protocol-aware features for plaintext traffic and packet-level features for encrypted TLS traffic.

The project also develops a labeled network traffic dataset containing both benign and attack sessions.

## 2. High-Level Architecture

AgentNet consists of the following major components:

1. **Agent Environment:** MCP servers and A2A agents that communicate through HTTP-based transports.
2. **Traffic Generation:** Generates benign and controlled attack sessions.
3. **Traffic Capture:** Captures network packets using tools such as Wireshark and tcpdump.
4. **Dataset Preparation:** Processes captured traffic and assigns labels to each session.
5. **Feature Extraction:** Extracts protocol-aware and network-level features.
6. **Intrusion Detection System:** Uses machine learning and deep learning models to classify network sessions.
7. **Evaluation:** Measures detection performance and tests generalization.

## 3. System Components

### 3.1 Agent Environment

The software testbed contains:

- MCP servers providing tools to AI agents.
- A2A agents communicating with other agents.
- Local LLMs used to support agent interactions.
- Benign and controlled attack scenarios.

The initial implementation uses HTTP-based communication so that network traffic can be captured and analyzed.

### 3.2 Traffic Generation

Traffic is generated through two categories:

- **Benign Traffic:** Normal agent communication, tool requests, responses, and agent-to-agent interactions.
- **Attack Traffic:** Controlled scenarios representing the attack categories defined in the project threat model.

Each generated session receives an appropriate label.

### 3.3 Traffic Capture

Network traffic is captured using Wireshark, tcpdump, and packet-analysis tools.

The system collects:

- Source and destination information.
- Packet sizes and directions.
- Timestamps and timing information.
- Transport and application protocol information.
- Available plaintext protocol information.

Both plaintext and TLS-encrypted traffic are considered.

### 3.4 Dataset Preparation

Captured traffic is organized into a labeled dataset.

The dataset contains:

- Raw packet captures.
- Processed network sessions.
- Extracted features.
- Session labels.
- Attack category information.

The initial dataset target is at least 5,000 labeled sessions, with approximately half representing benign activity.

### 3.5 Feature Extraction

AgentNet uses two feature categories:

**Protocol-Aware Features (Plaintext Traffic)**

- JSON-RPC method sequences.
- Tool-list changes across sessions.
- Message sizes.
- Request and response timing.

**Network-Level Features (TLS Traffic)**

- Packet sizes.
- Packet directions.
- Inter-arrival times.
- Traffic sequences.

### 3.6 Intrusion Detection System

The detection system contains two main approaches:

**Baseline Models**

- Random Forest
- XGBoost
- Small Multi-Layer Perceptron (MLP)

**Proposed Detection Models**

- Protocol-aware feature-based detection.
- 1D-CNN or GRU models for network traffic sequences.

The proposed system is compared against the baseline to evaluate whether additional protocol-aware and sequence-based features improve detection performance.

## 4. Hardware Architecture

The hardware testbed will extend the software environment using:

- ESP32 boards running MCP tool servers.
- Raspberry Pi boards hosting agents and controlled test scenarios.
- Sensors and output devices for validating device-state changes.
- A managed network switch with port mirroring for traffic capture.

This environment will help evaluate whether the detection system can generalize from software-generated traffic to real-device network traffic.

## 5. Technology Stack

| Area | Technologies |
|---|---|
| Programming | Python |
| Agent Protocols | MCP SDK, A2A SDK |
| Agent Framework | LangGraph |
| Local LLMs | Ollama |
| Backend | FastAPI |
| Traffic Capture | Wireshark, tcpdump |
| Packet Analysis | Scapy, PyShark |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn, XGBoost |
| Deep Learning | PyTorch |
| Explainability | SHAP |
| Hardware | ESP32, Raspberry Pi |

## 6. Overall Data Flow

1. MCP servers and A2A agents communicate.
2. Benign or controlled attack sessions are generated.
3. Network packets are captured.
4. Captures are processed into sessions.
5. Sessions are labeled and organized into the dataset.
6. Features are extracted from plaintext or TLS traffic.
7. Baseline and proposed detection models analyze the features.
8. Model performance is evaluated using classification and generalization metrics.

## 7. Project Scope

AgentNet focuses on MCP and A2A communication over HTTP-based transports.

MCP stdio transport is excluded because it does not generate network traffic for this project's network-level analysis.

The project covers software-based experiments first, followed by hardware-based validation.