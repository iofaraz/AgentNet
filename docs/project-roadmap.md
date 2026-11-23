# AgentNet — Project Roadmap

## Project Title

**Protocol-Aware, Encryption-Robust Intrusion Detection for MCP and A2A Agent Networks, with a Labeled Attack Traffic Dataset**

## 1. Project Overview

AgentNet aims to develop a labeled network traffic dataset for AI agent protocols (MCP and A2A) and use it to develop and evaluate an improved network-level Intrusion Detection System (IDS).

The project combines software-based agent environments with a physical hardware testbed to generate both benign and controlled attack traffic.

The collected traffic will be captured, analyzed, labeled, and converted into a structured dataset. Machine learning and deep learning models will then be developed and evaluated using this dataset.

## 2. Project Objectives

- Establish software-based MCP and A2A communication environments.
- Build a physical network testbed using ESP32, Raspberry Pi, sensors, and network equipment.
- Generate realistic benign network traffic.
- Simulate seven controlled security attack categories.
- Capture and label network traffic from software and hardware environments.
- Develop a labeled dataset for MCP and A2A network security research.
- Implement traditional machine learning baseline IDS models.
- Propose an improved protocol-aware and encryption-robust IDS.
- Evaluate detection performance and generalization across different environments.

## 3. Technology Stack

| Area | Technologies |
|---|---|
| Programming | Python |
| Agent Protocols | MCP, A2A |
| Agent Frameworks | MCP Python SDK, A2A Python SDK |
| Backend | FastAPI, Starlette |
| Hardware | ESP32, Raspberry Pi |
| Devices | ESP32 built-in LED, optional buzzer; readings simulated or Wi-Fi RSSI (DHT22/BME280 optional) |
| Network Analysis | Wireshark, tcpdump, Scapy |
| Network Equipment | Wi-Fi Access Point, Managed Switch |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn, XGBoost |
| Deep Learning | PyTorch |
| Explainability | SHAP |
| Version Control | Git, GitHub |

## 4. Project Phases

### Phase 1 — Research, Project Foundation, and Environment Setup

**Status: Completed**

**Tasks:**
- Research MCP and A2A protocols.
- Review existing intrusion detection approaches.
- Finalize project scope and proposal.
- Set up Python, Git, VS Code, Docker, Wireshark, and Ollama.
- Initialize the GitHub repository.
- Prepare project architecture documentation.
- Prepare threat model and attack taxonomy.
- Create the project roadmap.

**Deliverables:**
- GitHub repository.
- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/attack-taxonomy.md`
- `docs/project-roadmap.md`
- `docs/phase-reports/phase-1-report.md`

### Phase 2 — MCP Software Testbed

**Status: Completed**

**Tasks:**
- Install and configure the MCP Python SDK.
- Develop a Python MCP server.
- Implement sample MCP tools.
- Develop an MCP client.
- Establish communication using Streamable HTTP.
- Test tool discovery and invocation.
- Capture benign MCP traffic using Wireshark.
- Generate repeated benign MCP requests.
- Create an initial traffic manifest.

**Deliverables:**
- `software_testbed/mcp/server.py`
- `software_testbed/mcp/client.py`
- `traffic/pcaps/mcp_benign_sample.pcapng`
- `traffic/pcaps/mcp_benign_batch_01.pcapng`
- Initial benign traffic manifest.
- `docs/phase-reports/phase-2-report.md`

### Phase 3 — A2A Software Testbed

**Status: Implementation and benign traffic generation completed; documentation and GitHub synchronization to be verified.**

**Tasks:**
- Install and configure A2A Python SDK.
- Develop a deterministic A2A Echo Agent.
- Configure the A2A server and Agent Card.
- Develop an A2A client.
- Test agent discovery and message communication.
- Generate repeated benign A2A requests.
- Capture A2A traffic using Wireshark.
- Update the benign traffic manifest.

**Deliverables:**
- `software_testbed/a2a/agent_executor.py`
- `software_testbed/a2a/server.py`
- `software_testbed/a2a/client.py`
- `traffic/pcaps/a2a_benign_batch_01.pcapng`
- Updated benign traffic manifest.
- `docs/phase-reports/phase-3-report.md`

### Phase 4 — Physical Hardware Network Testbed

**Status: Pending**

**Objective:** Establish a physical network environment in which real devices communicate using the MCP and A2A protocols.

**Tasks:**
- Prepare ESP32 development boards.
- Configure the Raspberry Pi as the **gateway** (agreed design, D11): it runs the software testbed's Python MCP server, whose device tools forward commands to the ESP32.
- ESP32 firmware: switch the built-in LED (optional buzzer) and return readings (simulated or Wi-Fi RSSI; DHT22/BME280 optional).
- Keep the software tool names: `list_devices`, `read_sensor`, `set_led`, `sound_buzzer`.
- Establish communication between the Raspberry Pi and ESP32 (HTTP or MQTT over Wi-Fi preferred; Serial allowed but not capturable).
- Integrate software agents with the physical network.
- Configure network equipment and packet capture.
- Verify communication between physical devices.
- Test packet visibility through Wireshark or a mirrored switch port.

**Deliverables:**
- Functional physical network testbed.
- ESP32 device firmware (LED, readings).
- Raspberry Pi gateway (MCP server forwarding to the ESP32).
- Hardware network architecture documentation.
- Successful physical-device communication.
- Initial hardware network captures.
- `docs/phase-reports/phase-4-report.md`

### Phase 5 — Benign Traffic Generation

**Status: Pending**

**Objective:** Generate a diverse collection of normal MCP and A2A network traffic from both software and physical hardware environments.

**Tasks:**
- Generate normal MCP communication.
- Generate normal A2A communication.
- Generate sensor-data communication.
- Generate normal tool discovery and invocation patterns.
- Generate different agent-to-agent message patterns.
- Vary request frequency, message sizes, and communication patterns.
- Capture software-based benign traffic.
- Capture hardware-based benign traffic.
- Record session metadata and environment information.

**Deliverables:**
- Benign software traffic captures.
- Benign hardware traffic captures.
- Initial benign session records.
- Updated traffic manifest.
- `docs/phase-reports/phase-5-report.md`

### Phase 6 — Controlled Attack Scenario Implementation

**Status: Pending**

**Objective:** Implement and validate seven controlled security attack categories in isolated AgentNet test environments.

**Planned attack categories:**

| ID | Attack Category |
|---|---|
| AT-01 | Tool Poisoning |
| AT-02 | Rug Pull |
| AT-03 | Prompt Injection via Tool Output |
| AT-04 | Confused Deputy |
| AT-05 | Data Exfiltration |
| AT-06 | Agent Card Spoofing |
| AT-07 | Unauthorized Physical Actuation |

**Tasks:**
- Develop a reusable attack simulation framework.
- Implement controlled MCP-related scenarios.
- Implement controlled A2A-related scenarios.
- Use synthetic data and mock tools for security experiments.
- Use safe physical output simulations where relevant.
- Validate each scenario independently.
- Record attack success and failure.
- Record attack category and affected protocol.
- Ensure all experiments remain within the isolated test environment.

**Deliverables:**
- Attack simulation framework.
- Seven validated attack scenarios.
- Attack execution logs.
- Scenario validation results.
- Updated attack taxonomy.
- `docs/phase-reports/phase-6-report.md`

### Phase 7 — Network Traffic Collection and Dataset Creation

**Status: Pending**

**Objective:** Build a structured, labeled dataset from benign and attack traffic collected in software and hardware environments.

**Tasks:**
- Capture traffic for all seven attack categories.
- Capture corresponding benign traffic.
- Collect software and hardware PCAP files.
- Organize and validate packet captures.
- Extract communication sessions and network flows.
- Extract network-level features:
  - Packet sizes.
  - Packet directions.
  - Inter-arrival times.
  - Flow duration.
  - Packet counts.
  - Protocol and transport information.
- Extract protocol-aware features where available:
  - JSON-RPC methods.
  - Tool invocation sequences.
  - Agent communication patterns.
  - Tool-list changes.
- Assign benign and attack labels.
- Record attack categories and outcomes.
- Remove duplicates and validate dataset quality.
- Prepare training, validation, and testing splits.
- Keep raw captures and processed dataset versions organized.

**Dataset target:** At least 5,000 labeled sessions, subject to successful collection and validation.

**Deliverables:**
- Organized raw PCAP collection.
- Structured labeled dataset.
- Dataset metadata and feature definitions.
- Dataset statistics and validation report.
- Reproducible preprocessing scripts.
- `docs/phase-reports/phase-7-report.md`

### Phase 8 — Baseline Intrusion Detection System

**Status: Pending**

**Objective:** Establish baseline intrusion detection performance using conventional machine learning models.

**Tasks:**
- Load and preprocess the labeled dataset.
- Perform feature selection and analysis.
- Define training, validation, and testing datasets.
- Train baseline models:
  - Random Forest.
  - XGBoost.
  - Multilayer Perceptron (MLP).
- Evaluate binary and multiclass classification.
- Compare model performance.
- Analyze false positives and false negatives.
- Save trained models and evaluation results.

**Deliverables:**
- Baseline IDS implementation.
- Trained machine learning models.
- Performance comparison.
- Baseline evaluation report.
- `docs/phase-reports/phase-8-report.md`

### Phase 9 — Proposed Protocol-Aware and Encryption-Robust IDS

**Status: Pending**

**Objective:** Develop an improved detection approach that uses agent-protocol information when available and network-level traffic patterns when payloads are encrypted.

**Tasks:**

**Protocol-aware detection:**
- Extract MCP and A2A communication features.
- Analyze JSON-RPC methods and message sequences.
- Incorporate tool and agent behavior features.
- Combine protocol-aware features with network-flow features.

**Encryption-robust detection:**
- Generate and capture TLS-protected traffic.
- Extract packet size, direction, timing, and sequence features.
- Develop a 1D-CNN or GRU-based model.
- Evaluate detection without relying on readable application payloads.

**Model development:**
- Combine appropriate feature extraction and classification components.
- Compare the proposed approach with baseline models.
- Tune model parameters.
- Analyze feature importance and model behavior.

**Deliverables:**
- Proposed IDS implementation.
- Protocol-aware detection model.
- Encrypted-traffic detection model.
- Trained model files.
- Comparison with baseline models.
- `docs/phase-reports/phase-9-report.md`

### Phase 10 — Final Evaluation, Validation, and Project Deliverables

**Status: Pending**

**Objective:** Perform comprehensive evaluation and prepare the final research contributions.

**Tasks:**
- Evaluate binary and multiclass detection performance.
- Measure precision, recall, macro-F1, and per-class F1.
- Measure false-positive rate, ROC-AUC, and PR-AUC.
- Compare baseline and proposed IDS models.
- Evaluate plaintext versus TLS detection.
- Test unseen attack variations.
- Evaluate generalization across different agents and servers.
- Evaluate software-to-hardware generalization.
- Perform dataset validity checks.
- Conduct feature-importance analysis using SHAP.
- Prepare visualizations and experimental results.
- Document limitations and future improvements.
- Prepare the final report, presentation, and project demonstration.

**Deliverables:**
- Final dataset.
- Final IDS models.
- Experimental evaluation results.
- Performance graphs and comparison tables.
- Final project report.
- Project presentation and demonstration.
- `docs/phase-reports/phase-10-report.md`

## 5. Dataset Design

All formats and rules are binding as written in [`attack-dataset-contract.md`](attack-dataset-contract.md) v1.2; the must-follow summary is in the README.

The dataset will contain both benign and attack communication sessions.

**Primary labels:**
- Benign: `0`
- Attack: `1`

**Additional metadata:**
- Session ID.
- Protocol (MCP/A2A).
- Attack category (AT-01 to AT-07).
- Transport (`HTTP`, `HTTPS`, `MQTT`, `Serial`).
- Environment (Software/Hardware).
- Attack outcome (`Success`/`Failed`; `N/A` for benign).
- Capture file reference.
- Session and experiment metadata.

The dataset will support both binary classification and attack-category classification.

## 6. Evaluation Metrics

The proposed IDS will be evaluated using:

- Accuracy.
- Precision.
- Recall.
- Macro-F1.
- Per-class F1.
- False-positive rate.
- ROC-AUC.
- PR-AUC.
- Generalization performance.
- Software-to-hardware performance comparison.
- Plaintext versus encrypted traffic performance.

Additional validation will examine dataset balance, labeling consistency, reproducibility, and the possibility of data leakage.

## 7. Documentation Structure

```text
docs/
├── architecture.md
├── threat-model.md
├── attack-taxonomy.md
├── project-roadmap.md
└── phase-reports/
    ├── phase-1-report.md
    ├── phase-2-report.md
    ├── phase-3-report.md
    ├── phase-4-report.md
    ├── phase-5-report.md
    ├── phase-6-report.md
    ├── phase-7-report.md
    ├── phase-8-report.md
    ├── phase-9-report.md
    └── phase-10-report.md
```

## 8. Project Completion Criteria

The project will be considered complete when:

- MCP and A2A software testbeds are functional.
- The physical hardware testbed is operational.
- Benign and controlled attack traffic has been collected.
- All seven attack categories have been implemented and validated.
- The labeled dataset has been prepared and documented.
- Baseline IDS models have been trained and evaluated.
- The proposed IDS has been implemented and compared against baselines.
- Encrypted-traffic detection has been evaluated.
- Software-to-hardware generalization has been investigated.
- Final documentation, results, and demonstration are ready.

## 9. Current Project Status

**Completed Phases:**
- Phase 1 — Research, Project Foundation, and Environment Setup.
- Phase 2 — MCP Software Testbed.
- Phase 3 — A2A Software Testbed implementation and benign traffic generation (documentation and GitHub synchronization to be verified).

**Current Phase:**
Phase 4 — Physical Hardware Network Testbed.

**Next Milestone:**
Establish communication between the ESP32, Raspberry Pi (gateway MCP server), and software agents over the physical network.

**Overall Status:** Software testbed foundation established; physical hardware integration is the next major milestone.