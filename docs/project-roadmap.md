# AgentNet — Complete Project Roadmap

## Project Overview

**Project Title:** Protocol-Aware, Encryption-Robust Intrusion Detection for MCP and A2A Agent Networks, with a Labeled Attack Traffic Dataset

**Project Name:** AgentNet

**Objective:** Develop a network intrusion detection system for MCP and A2A agent networks, create a labeled traffic dataset, and evaluate detection performance on both plaintext and TLS-encrypted traffic.

The project is divided into 10 phases, progressing from project setup and software testbed development to dataset creation, model development, hardware validation, and final evaluation.

---

# Phase 1 — Research, Project Foundation, and Environment Setup

**Objective:** Establish the project foundation, prepare the development environment, and define the system architecture and security scope.

### Tasks

- Review the project proposal and relevant research.
- Finalize project scope and objectives.
- Install Python, Git, VS Code, Docker, Wireshark, and Ollama.
- Create the AgentNet project repository.
- Initialize Git and configure the Python virtual environment.
- Create the project directory structure.
- Prepare `architecture.md`.
- Prepare `threat-model.md`.
- Prepare `attack-taxonomy.md`.
- Create `docs/phase-reports/`.
- Create the Phase 1 report.
- Commit and push the completed work to GitHub.

### Deliverables

- Configured development environment.
- GitHub repository.
- Initial project structure.
- System architecture documentation.
- Threat model.
- Attack taxonomy.
- Phase 1 report.

### Completion Criteria

All required tools are installed, documentation is prepared, the project structure is verified, and the work is committed to GitHub.

**Status:** Complete

---

# Phase 2 — MCP Software Testbed

**Objective:** Build a working MCP environment that generates normal network traffic for experimentation.

### Tasks

- Understand MCP client-server architecture.
- Set up the Python MCP SDK.
- Implement a basic MCP server.
- Create harmless example tools.
- Implement an MCP client.
- Connect the client and server using HTTP-based Streamable HTTP transport.
- Test tool discovery and invocation.
- Generate benign MCP communication sessions.
- Capture traffic using Wireshark.
- Inspect HTTP and JSON-RPC communication.
- Save sample PCAP files.
- Write and run basic tests.

### Deliverables

- Working MCP server.
- Working MCP client.
- Functional example tools.
- Benign MCP traffic samples.
- Initial PCAP captures.
- Phase 2 report.

### Completion Criteria

The MCP client successfully communicates with the server, invokes tools, and produces capturable network traffic.

**Status:** Complete

---

# Phase 3 — A2A Software Testbed and Benign Traffic Generation

**Objective:** Build an A2A environment and generate normal communication traffic across both supported agent protocols.

### Tasks

- Set up the A2A SDK.
- Implement basic A2A agents.
- Configure agent identity and capability information.
- Implement normal agent-to-agent communication.
- Integrate MCP and A2A components where appropriate.
- Introduce local LLM integration if feasible.
- Generate normal agent interactions.
- Capture MCP and A2A traffic.
- Record session metadata.
- Validate that generated traffic represents legitimate activity.
- Create a reusable benign traffic-generation pipeline.

### Deliverables

- Working A2A agents.
- Functional agent communication.
- Integrated software testbed.
- Benign traffic-generation scripts.
- Initial benign traffic samples.
- Phase 3 report.

### Completion Criteria

Both MCP and A2A environments generate repeatable benign sessions, and their traffic can be captured and identified.

**Status:** Complete

---

# Phase 4 — Controlled Attack Scenario Implementation

**Objective:** Implement controlled, reproducible attack scenarios based on the approved attack taxonomy.

### Tasks

Implement the seven proposed attack categories:

1. Tool Poisoning.
2. Tool Rug Pull.
3. Prompt Injection Through Tool Output.
4. Confused Deputy.
5. Data Exfiltration.
6. Agent-Card Spoofing.
7. Unauthorized Physical Actuation.

Additional tasks:

- Define a controlled test scenario for each category.
- Define expected attack behavior.
- Define success and failure conditions.
- Implement scenario-generation scripts.
- Record scenario metadata.
- Validate outcomes through application logs or testbed state.
- Ensure benign sessions remain distinguishable from attack sessions.

### Deliverables

- Seven controlled attack scenarios.
- Attack-generation scripts.
- Outcome-validation logic.
- Attack session metadata.
- Phase 4 report.

### Completion Criteria

Each attack category has a reproducible test scenario, documented success criteria, and validated session labels.

**Status:** Pending

---

# Phase 5 — Traffic Capture and Dataset Creation

**Objective:** Create a labeled dataset containing benign and attack traffic from MCP and A2A environments.

### Tasks

- Capture benign and attack sessions.
- Collect plaintext traffic.
- Configure TLS-based experiments.
- Capture encrypted traffic.
- Organize raw PCAP files.
- Extract network sessions and flow information.
- Assign session IDs.
- Apply traffic-class and attack-category labels.
- Record attack success and failure.
- Extract initial network metadata.
- Check missing and inconsistent labels.
- Remove duplicate or invalid records where appropriate.
- Create training, validation, and testing splits.
- Prevent session leakage across dataset splits.
- Perform dataset statistics and quality checks.

### Dataset Target

At least **5,000 labeled sessions**, with approximately half representing benign activity, subject to the feasibility and quality of generated data.

### Deliverables

- Raw traffic captures.
- Processed traffic sessions.
- Labeled dataset.
- Dataset metadata.
- Dataset statistics and validation report.
- Phase 5 report.

### Completion Criteria

The dataset contains validated benign and attack sessions with consistent labels, documented collection procedures, and reproducible splits.

---

# Phase 6 — Baseline Intrusion Detection System

**Objective:** Develop baseline machine learning models using conventional network-level features.

### Tasks

- Select relevant network-level features.
- Build the feature extraction pipeline.
- Prepare model training datasets.
- Handle class imbalance where necessary.
- Train Random Forest.
- Train XGBoost.
- Train a small Multi-Layer Perceptron (MLP).
- Evaluate models using held-out data.
- Record per-class performance.
- Analyze false positives and false negatives.
- Save trained models and experiment results.

### Evaluation Metrics

- Accuracy.
- Precision.
- Recall.
- Macro-F1.
- Per-class F1.
- False Positive Rate.
- ROC-AUC.
- PR-AUC.

### Deliverables

- Baseline feature pipeline.
- Trained baseline models.
- Evaluation results.
- Comparison tables and visualizations.
- Phase 6 report.

### Completion Criteria

Baseline models are trained, evaluated, and documented using a reproducible experimental setup.

---

# Phase 7 — Proposed Protocol-Aware Intrusion Detection System

**Objective:** Improve detection by incorporating MCP and A2A protocol-aware information alongside conventional network features.

### Tasks

- Identify protocol-specific features.
- Extract JSON-RPC method sequences where traffic is readable.
- Track tool-list changes across sessions.
- Extract message sizes and timing information.
- Combine protocol-aware features with network-level features.
- Train and evaluate the proposed detector.
- Experiment with suitable model architectures.
- Compare proposed models against baseline models.
- Analyze improvements and limitations.
- Perform feature-importance analysis using SHAP where appropriate.

### Proposed Models

- Protocol-aware machine learning model.
- 1D-CNN for traffic sequences.
- GRU for traffic sequences.

### Deliverables

- Protocol-aware feature extraction pipeline.
- Proposed detection models.
- Trained model checkpoints.
- Baseline-versus-proposed comparison.
- Feature-importance analysis.
- Phase 7 report.

### Completion Criteria

The proposed detector is evaluated against the baseline using the same data splits and evaluation metrics.

---

# Phase 8 — TLS Detection and Generalization Testing

**Objective:** Evaluate detection when payloads are encrypted and test whether models generalize to previously unseen environments.

### Tasks

- Prepare TLS-based traffic experiments.
- Extract packet sizes and directions.
- Calculate packet inter-arrival times.
- Construct traffic sequences.
- Train and evaluate sequence-based detection models.
- Compare plaintext and TLS detection performance.
- Test on unseen LLMs.
- Test on unseen MCP servers and A2A agents.
- Evaluate unseen attack variations.
- Analyze false positives and generalization performance.

### Deliverables

- TLS traffic feature pipeline.
- TLS detection models.
- Plaintext-versus-TLS comparison.
- Generalization test results.
- Phase 8 report.

### Completion Criteria

The detector is evaluated on encrypted traffic and previously unseen test scenarios, with results documented.

---

# Phase 9 — Hardware Testbed and Software-to-Hardware Validation

**Objective:** Extend the software testbed to physical devices and evaluate whether detection models generalize to real-device traffic.

### Hardware Components

- ESP32 development boards.
- Raspberry Pi 4 or 5 boards.
- DHT22 or BME280 sensor.
- Relay module.
- LED, buzzer, or servo.
- Managed network switch with port mirroring.
- Wi-Fi access point.
- Required cables and power supplies.

### Tasks

- Prepare ESP32 development environment.
- Configure ESP32-based MCP tool servers.
- Configure Raspberry Pi agent hosts.
- Connect sensors and output devices.
- Integrate physical devices with the software testbed.
- Generate normal device communication.
- Execute controlled hardware test scenarios.
- Capture hardware network traffic.
- Validate device states and session outcomes.
- Extract hardware traffic features.
- Evaluate software-trained models on hardware traffic.
- Analyze software-to-hardware performance differences.

### Deliverables

- Working hardware testbed.
- ESP32 MCP servers.
- Raspberry Pi agent environment.
- Hardware traffic captures.
- Hardware dataset samples.
- Software-to-hardware evaluation results.
- Phase 9 report.

### Completion Criteria

The hardware testbed produces validated traffic, and the trained detection models are evaluated on hardware-generated sessions.

---

# Phase 10 — Final Evaluation, Analysis, and Project Deliverables

**Objective:** Complete the experimental evaluation, analyze findings, and prepare the final project submission.

### Tasks

- Consolidate all experiment results.
- Compare baseline and proposed detectors.
- Compare plaintext and TLS performance.
- Evaluate unseen-agent and unseen-server performance.
- Evaluate software-to-hardware generalization.
- Perform dataset validity checks.
- Conduct negative-control experiments.
- Analyze model explainability using SHAP.
- Calculate confidence intervals where appropriate.
- Prepare final performance tables and graphs.
- Document limitations and future improvements.
- Finalize source code and README.
- Prepare the final technical report.
- Prepare presentation slides.
- Verify reproducibility and repository organization.

### Deliverables

- Final labeled dataset.
- Complete source code.
- Trained models.
- Experiment results.
- Evaluation graphs and tables.
- Final technical report.
- Presentation slides.
- Updated GitHub repository.
- Phase 10 report.

### Completion Criteria

All experiments are documented, project objectives are evaluated against the results, and final submission materials are ready.

---

# Overall Project Completion Checklist

- [ ] Phase 1 — Research, Project Foundation, and Environment Setup
- [ ] Phase 2 — MCP Software Testbed
- [ ] Phase 3 — A2A Software Testbed and Benign Traffic Generation
- [ ] Phase 4 — Controlled Attack Scenario Implementation
- [ ] Phase 5 — Traffic Capture and Dataset Creation
- [ ] Phase 6 — Baseline Intrusion Detection System
- [ ] Phase 7 — Proposed Protocol-Aware Intrusion Detection System
- [ ] Phase 8 — TLS Detection and Generalization Testing
- [ ] Phase 9 — Hardware Testbed and Software-to-Hardware Validation
- [ ] Phase 10 — Final Evaluation, Analysis, and Project Deliverables

## Project Management Rules

1. Complete phases sequentially unless a dependency requires parallel work.
2. Test each major component before moving forward.
3. Maintain clean and organized source code.
4. Keep raw traffic captures separate from processed datasets.
5. Record dataset-generation settings and experiment configurations.
6. Use Git commits to track meaningful project milestones.
7. **After completing every phase, prepare its report in `docs/phase-reports/`.**
8. Update this roadmap when phase status changes.
9. Do not mark a phase complete until its implementation, testing, documentation, and GitHub commit are finished.

## Current Project Status

**Current Phase:** Phase 1 — Research, Project Foundation, and Environment Setup

**Next Phase:** Phase 2 — MCP Software Testbed

**Overall Status:** Foundation and documentation preparation.