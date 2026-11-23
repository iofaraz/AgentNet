# AgentNet

**Protocol-Aware, Encryption-Robust Intrusion Detection for MCP and A2A Agent Networks**

## Overview

AgentNet is a Computer Networks research project focused on detecting malicious activities in Model Context Protocol (MCP) and Agent-to-Agent (A2A) network communication.

The project aims to develop a labeled network traffic dataset and an improved intrusion detection system capable of identifying attacks in both plaintext and encrypted traffic.

## Main Objectives

- Build a labeled MCP/A2A network traffic dataset.
- Generate benign and malicious network sessions.
- Develop a flow-based baseline intrusion detection system.
- Improve detection using protocol-aware features.
- Investigate encrypted traffic detection using packet size, direction, and timing.
- Evaluate detection performance on software and hardware testbeds.

## Technology Stack

- **Languages:** Python
- **Agent Protocols:** MCP, A2A
- **LLM Runtime:** Ollama
- **Containerization:** Docker
- **Network Analysis:** Wireshark, TShark, Scapy
- **Machine Learning:** Scikit-learn, XGBoost, PyTorch
- **Data Processing:** Pandas, NumPy
- **Explainability:** SHAP

## Rules — Must Follow (both team members)

These rules were agreed by both team members on 2026-11-23. The full standard is [`docs/attack-dataset-contract.md`](docs/attack-dataset-contract.md) **v1.2**. If anything here seems unclear, the contract wins. **No rule, column, value or format may change without agreement from both of us.**

### 1. Labels and formats

| Item | Rule | Example |
|---|---|---|
| Session ID | `<PROTOCOL>-<ENV>-B<number>` (benign) or `<PROTOCOL>-<ENV>-AT<nn>-<number>` (attack). ENV is `S` (software) or `H` (hardware); at least 4 digits. **Never reuse an ID.** | `MCP-H-B0001`, `MCP-H-AT07-0001` |
| PCAP name | `<protocol>_<attack-id>_<environment>_<run>.pcapng` | `mcp_benign_hardware_001.pcapng`, `mcp_at07_hardware_001.pcapng` |
| `label` | `Benign` or `Attack` | `Benign` |
| `attack_id` | `AT-00` for benign; `AT-01` … `AT-07` for attacks | `AT-00` |
| `outcome` | Attacks: `Success` or `Failed` (exactly this spelling). Benign: `N/A` | `Failed` |
| `protocol` | `MCP` or `A2A` | `MCP` |
| `transport` | `HTTP`, `HTTPS`, `MQTT` or `Serial` | `HTTP` |
| `environment` | `Software` or `Hardware` | `Hardware` |
| Timestamps | Local time with UTC offset and milliseconds | `2026-11-21T15:46:00.123+05:00` |

### 2. Recording sessions

1. Start the capture **before** the session and stop it **after**. Keep one session per PCAP where practical.
2. Every session gets a row in the shared manifest (`dataset/labels/manifest.csv`, columns in contract §3).
3. **Validate before sharing:** `python scripts/manifest.py validate dataset/labels/manifest.csv`. It must report no errors.
4. A failed attack is still real attack traffic. Record it with outcome `Failed`; never delete it.
5. A broken capture (crash, Wi-Fi drop, wrong setup) is **excluded, not deleted**. Write it in the capture log with `status = excluded` and the reason (see [Hardware Capture Log](#hardware-capture-log)).
6. Never mark an attack `Success` by assumption. Check it against logs or the device state (e.g. the LED actually turned on).
7. If a label is unclear, discuss it. **Never guess a label.**
8. Never edit original PCAPs. Processed data goes in `dataset/processed/`.

### 3. Hardware testbed design (agreed)

```
Agent (laptop or Pi) ──MCP over HTTP──> MCP server on Raspberry Pi ──HTTP / MQTT / Serial──> ESP32
                                         (gateway)                                         (LED, buzzer, readings)
```

1. **The Raspberry Pi is the gateway.** It runs the same Python MCP server as the software testbed (`software_testbed/mcp/server.py`), and its device tools forward commands to the ESP32.
2. **The ESP32 is the device.** It switches its built-in LED (optional buzzer) and returns readings: simulated temperature/humidity or Wi-Fi signal strength. An external DHT22/BME280 is optional.
3. **Use the same tool names and arguments as the software side:**
   - `list_devices()`
   - `read_sensor(sensor_id)`
   - `set_led(device_id, on, color)`
   - `sound_buzzer(device_id, duration_ms)`

   If a device does not exist (e.g. no buzzer), leave its tool out. Do not rename it.
4. Run the agent from a separate machine if possible, so the MCP traffic crosses the real network.
5. Prefer HTTP or MQTT over Wi-Fi for the Pi ↔ ESP32 link. Serial is allowed, but Wireshark cannot capture it.

### 4. Rules against shortcuts (so the model learns real attack behaviour)

1. Attacks use the **same users and tokens** as benign traffic (e.g. a "compromised bob"). There is no special attacker user.
2. Attacks use the **same mix** as benign traffic: scripted vs. AI-driven sessions, handshake types and timing.
3. Benign traffic includes **honest mistakes** and **legitimate sensitive actions** (e.g. an admin reading a secret file), so "error" or "secret read" alone never means attack.
4. **Never use as model features:** IP addresses, port numbers, tokens, user names, session IDs, outcome or environment.
5. Tools never return real host details (OS, host name, user name) or real personal data. Everything is synthetic.

### 5. Safety and security

1. All experiments run **only inside our isolated testbed**. Never attack real networks, devices or services.
2. Physical outputs are **harmless only**: LEDs and buzzers. Nothing that moves, heats or switches mains power.
3. **Never commit secrets:** Wi-Fi passwords, API keys or real tokens. Keep them in local files that git ignores.

### 6. Storing captures

1. PCAPs and processed data are **not** stored in git (`.gitignore` excludes them), so pushing does not back them up.
2. Upload every capture to the **shared cloud folder** (Google Drive / OneDrive) after each collection run.
3. Record each file's SHA-256 in your capture log. Use it to check that the uploaded copy is identical.

### 7. Git workflow

1. Never push directly to `main`. Work on your own branch (software: `software-dataset`; hardware: e.g. `hardware-testbed`) and merge through a pull request.
2. Commit and push after each finished piece of work. Write in the commit message what changed and why.
3. Do not change the repository folder structure without agreement.

## Hardware Capture Log

Besides the shared manifest, the hardware side keeps one row per capture in `dataset/labels/hardware_capture_log.csv`. It is simpler than the software side's `capture_log.csv`, as agreed. It **includes captures that went wrong**: mark them `excluded` with a reason, and never delete them silently.

| Column | Meaning | Example |
|---|---|---|
| `session_id` | Same ID as in the manifest | `MCP-H-B0001` |
| `capture_file` | PCAP file name | `mcp_benign_hardware_001.pcapng` |
| `sha256` | Hash of the PCAP, to verify backup copies | `3f9a…` |
| `status` | `valid` or `excluded` | `valid` |
| `reason` | Why it was excluded; empty when valid | `ESP32 lost Wi-Fi mid-session` |
| `capture_start` | When capture started (same timestamp format) | `2026-11-25T14:02:10.000+05:00` |
| `capture_stop` | When capture stopped | `2026-11-25T14:02:31.500+05:00` |
| `notes` | Anything useful: devices, firmware version, setup | `Pi 4 ↔ ESP32 over Wi-Fi AP` |

Header row:

```csv
session_id,capture_file,sha256,status,reason,capture_start,capture_stop,notes
```

Getting the SHA-256 of a capture:

```powershell
certutil -hashfile mcp_benign_hardware_001.pcapng SHA256   # Windows
sha256sum mcp_benign_hardware_001.pcapng                    # Raspberry Pi / Linux
```

## Project Status

Software testbed and benign scenario catalogue complete (see [`docs/software-worklog.md`](docs/software-worklog.md)). Next: benign traffic collection (software) and the Raspberry Pi gateway + ESP32 testbed (hardware).