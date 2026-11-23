# Attack and Dataset Contract

## 1. Purpose

This document defines the common standards for attack simulation, network traffic capture, session metadata, feature extraction, and dataset preparation in the AgentNet project.

Both team members must follow these standards so independently developed components can work together without major integration changes.

## 2. Attack Taxonomy and Labels

Every traffic session must be assigned one of the following labels:

| Attack ID | Attack Name | Label | Protocol |
|---|---|---|---|
| AT-00 | Benign Traffic | Benign | MCP / A2A |
| AT-01 | Tool Poisoning | Attack | MCP |
| AT-02 | Rug Pull | Attack | MCP |
| AT-03 | Prompt Injection via Tool Output | Attack | MCP |
| AT-04 | Confused Deputy | Attack | MCP |
| AT-05 | Data Exfiltration | Attack | MCP / A2A |
| AT-06 | Agent Card Spoofing | Attack | A2A |
| AT-07 | Unauthorized Physical Actuation | Attack | MCP / A2A |

**Important:**
- Use only the listed IDs and names.
- AT-00 represents benign traffic, not an attack.
- Failed attack attempts must also be recorded.
- AT-07 will use harmless simulated outputs during software testing. Physical validation will be limited to safe outputs such as LEDs and buzzers.

## 3. Common Session Metadata

Every captured session must have a corresponding record in the common manifest.

### Required CSV Columns

| Field | Description | Example |
|---|---|---|
| session_id | Unique session identifier | MCP-S-AT01-0001 |
| label | Benign or Attack | Attack |
| attack_id | Attack category; `AT-00` for benign | AT-01 |
| protocol | MCP or A2A | MCP |
| transport | `HTTP`, `HTTPS`, `MQTT` or `Serial` | HTTP |
| environment | Software or Hardware | Software |
| capture_file | Associated PCAP filename | mcp_at01_software_001.pcapng |
| outcome | `Success` or `Failed` (exactly this spelling); `N/A` for benign | Success |
| start_time | Session start timestamp | 2026-11-20T10:30:00.000+05:00 |
| end_time | Session end timestamp | 2026-11-20T10:30:15.000+05:00 |

### Additional Recommended Columns

| Field | Description |
|---|---|
| run_id | Identifier for the overall experiment run |
| attack_variant | Variant identifier, or N/A for benign |
| source_device | Device generating the traffic |
| destination_device | Device receiving the traffic |
| notes | Relevant experimental observations |

Use ISO 8601 timestamps in local time with the UTC offset and milliseconds, e.g. `2026-11-21T15:46:00.123+05:00`, throughout the project.

## 4. Session ID Convention

Use unique IDs following these formats:

`<PROTOCOL>-<ENV>-B<number>` for benign sessions and `<PROTOCOL>-<ENV>-AT<nn>-<number>` for attack sessions, where `<ENV>` is `S` (Software) or `H` (Hardware) and `<number>` has at least 4 digits.

| Session | Software | Hardware |
|---|---|---|
| MCP benign | `MCP-S-B0001` | `MCP-H-B0001` |
| A2A benign | `A2A-S-B0001` | `A2A-H-B0001` |
| MCP attack | `MCP-S-AT01-0001` | `MCP-H-AT01-0001` |
| A2A attack | `A2A-S-AT06-0001` | `A2A-H-AT06-0001` |

The environment letter keeps software and hardware IDs distinct when the two datasets are merged, and must match the `environment` column. Four digits allow up to 9,999 sessions per protocol, environment and attack category.

**Session IDs must never be reused.**

## 5. PCAP Naming Convention

Use the following naming pattern:

`<protocol>_<attack-id>_<environment>_<run-number>.pcapng`

Examples:

- `mcp_benign_software_001.pcapng`
- `a2a_benign_software_001.pcapng`
- `mcp_at01_software_001.pcapng`
- `a2a_at06_software_001.pcapng`
- `mcp_at01_hardware_001.pcapng`

Keep original PCAP files unchanged. Store extracted and processed data separately.

## 6. Traffic Capture Requirements

Each experiment must:

1. Start a packet capture before the experiment.
2. Record the session start time.
3. Execute one clearly defined benign or attack scenario.
4. Record whether the intended scenario succeeded or failed.
5. Record the session end time.
6. Stop and save the capture.
7. Add the session metadata to the manifest.

Where practical, capture one experiment per PCAP file to simplify labeling and analysis.

If multiple experiments are captured in one file, each session must have clearly recorded boundaries and timestamps.

All captures must be generated within the isolated project testbed.

## 7. Feature Extraction Contract

The dataset pipeline should extract features from two categories.

### A. Network-Level Features

- Packet count
- Total bytes sent and received
- Average packet size
- Minimum and maximum packet size
- Packet size standard deviation
- Average inter-arrival time
- Flow duration
- Packets per second
- Bytes per second
- Traffic direction
- TCP flags, where applicable

### B. Protocol-Level Features

For observable plaintext MCP/A2A HTTP traffic:

- JSON-RPC method
- Request and response counts
- Tool discovery frequency
- Tool invocation frequency
- Method sequence
- Request and response sizes
- Agent Card request frequency
- HTTP status codes
- Tool-list change indicators, where observable

For TLS-encrypted traffic:

- Packet sizes
- Traffic direction
- Timing and inter-arrival patterns
- Flow duration
- Packet and byte counts
- Other observable transport metadata

Do not assume that encrypted application-layer fields can be extracted directly from TLS traffic.

## 8. Dataset Output Format

The extraction pipeline must produce a structured CSV or Parquet dataset.

Each row should represent one clearly defined session or flow, according to the finalized extraction method.

The output should contain:

- Session identifier
- Extracted network features
- Extracted protocol features, when available
- Target label
- Attack ID
- Protocol
- Environment

Keep metadata and model features logically separated.

**Never use the following as model input features:**

- `session_id`
- `run_id`
- `capture_file`
- `label`
- `attack_id`
- `outcome`
- `environment`

These fields are useful for labeling, grouping, and evaluation, but can cause data leakage if used as predictive features.

## 9. Data Quality and Validation

Before adding records to the final dataset, verify:

- Every session has a unique ID.
- Every PCAP has a corresponding manifest record.
- Labels and attack IDs are valid.
- Timestamps are present and correctly ordered.
- Captures are readable and not corrupted.
- Features contain valid values.
- Missing values are documented.
- Duplicate sessions are identified.
- Benign and attack records are distinguishable.
- Failed attacks are retained and correctly labeled.

Do not silently discard failed experiments or malformed captures. Record their status and document exclusions from the final dataset.

## 10. Dataset Splitting and Evaluation

To avoid misleading evaluation results:

- Split data by independent experiment runs or attack variants.
- Do not randomly distribute packets from the same session across training and testing.
- Keep related sessions from the same run together.
- Reserve unseen attack variants for generalization testing.
- Preserve software and hardware environment information for cross-environment evaluation.

The final evaluation should include:

1. Train on software, test on software.
2. Train on hardware, test on hardware.
3. Train on software, test on hardware.
4. Train on hardware, test on software.
5. Train on combined environments, test on unseen variants.

## 11. Reproducibility

For every experiment, record:

- Experiment/run ID
- Attack category and variant
- Protocol and transport
- Environment
- Software and SDK versions
- Testbed configuration
- Capture filename
- Start and end timestamps
- Outcome
- Relevant notes

Keep experiment configurations and scripts version-controlled. Never commit passwords, API keys, Wi-Fi credentials, or other secrets.

## 11a. Hardware Design and Shared Tool Names (agreed, v1.2)

- The Raspberry Pi is the **gateway**: it runs the same Python MCP server as the software testbed, and its device tools forward commands to the ESP32.
- The ESP32 is the physical device: built-in LED (optional buzzer) and readings (simulated or Wi-Fi RSSI; external sensors optional).
- Device tools keep the software names and arguments: `list_devices`, `read_sensor(sensor_id)`, `set_led(device_id, on, color)`, `sound_buzzer(device_id, duration_ms)`. A tool that has no device behind it is left out, not renamed.

## 11b. Rules Against Label Shortcuts (agreed, v1.2)

A model must learn attack *behaviour*, not side effects of how the data was made:

1. Attack sessions use the same identities (users, tokens) as benign sessions. There is no special "attacker" user.
2. Attack sessions use the same mix as benign sessions: scripted vs. LLM-driven, MCP handshake types and timing profiles.
3. Benign traffic includes honest mistakes and legitimate sensitive actions, so "error" or "secret read" alone never means attack.
4. Raw IP addresses, port numbers, tokens, user names, session IDs, outcome and environment are never model features.
5. Tools and outputs never reveal real host details (OS, host name, user name) or real data. Everything is synthetic.

## 12. Repository Responsibilities

### Attack Simulation

The attack simulation component is responsible for:

- Implementing controlled attack scenarios.
- Using the approved attack IDs.
- Recording experiment outcomes.
- Producing captures compatible with this contract.
- Supplying session metadata.

### Dataset Pipeline

The dataset component is responsible for:

- Reading original PCAP files.
- Extracting session-level traffic information.
- Extracting agreed network and protocol features.
- Associating extracted records with manifest metadata.
- Validating labels and data quality.
- Producing processed datasets.

### Shared Responsibilities

Both team members must:

- Follow this contract.
- Agree on changes before modifying shared schemas.
- Test integration using the same sample captures.
- Document changes to feature definitions or metadata.
- Review the final dataset before model training.

## 13. Initial Integration Test

Before implementing all attack scenarios, both components must work with the existing benign captures:

- `mcp_benign_sample.pcapng`
- `mcp_benign_batch_01.pcapng`
- `a2a_benign_batch_01.pcapng`

The attack simulation component must demonstrate that it can produce a capture and matching metadata record.

The dataset pipeline must demonstrate that it can read an existing capture, extract features, and associate the output with its manifest record.

**Completion condition:** Both components successfully follow the same metadata schema and can be integrated without manually changing their output formats.

---

**Contract Status:** Version 1.2 (agreed by both team members)

| Version | Change |
|---|---|
| 1.0 | Initial version |
| 1.1 | Session IDs include an environment letter (`S`/`H`) and at least 4 digits, so software and hardware IDs cannot clash when merged (§4). §3 examples corrected to follow §4 and §5. |
| 1.2 | Agreed by both team members. Benign `attack_id` is `AT-00`; outcome spelling is `Failed`; transport values `HTTP`, `HTTPS`, `MQTT`, `Serial`; timestamp format fixed (§3); hardware design and shared tool names (§11a); rules against label shortcuts (§11b). |

Any changes to field names, labels, IDs, or output formats must be discussed and agreed upon by both team members before implementation.