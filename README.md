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
9. If a whole run must be left out of the final dataset (e.g. a pilot made with an older setup), list its `run_id` with the reason in `dataset/labels/excluded_runs.csv`. Keep its captures and records; never delete them.

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

---

# Umar Hayat Ali

> **Software side of AgentNet: the complete guide.**
> This section explains the whole project in plain words, what has been built, how it was built step by step, and how anyone can repeat it from scratch. You do not need to be an expert. Technical words are explained in the [Glossary](#glossary) at the end.

## A. The project in simple words

### What is AgentNet?
Today, AI assistants don't just chat. They also **do things**: read files, check sensors, switch on devices, or ask other AI assistants for help. They do this by sending messages over a network using two new "languages" (protocols):

- **MCP (Model Context Protocol):** how an AI assistant talks to a **tool server** (for example "read the temperature sensor" or "list the files").
- **A2A (Agent-to-Agent):** how one AI assistant talks to **another AI assistant**.

Like any network, these can be **attacked**: a tool can lie to the assistant, hidden instructions can trick it, data can be stolen, or a device can be switched on without permission.

**AgentNet builds a "security camera" for these AI networks**: an **Intrusion Detection System (IDS)** that watches the network traffic and raises an alarm when something looks like an attack.

### What will the project deliver?
1. **A labelled dataset:** thousands of recorded network conversations ("sessions"), each marked *normal* or *attack*. Such data is rare and valuable, because almost none exists for MCP/A2A yet.
2. **A detector (IDS):** machine-learning models trained on that dataset, including one that still works when the traffic is **encrypted** (when it can't read the messages, only see their size and timing).

### Who does what?
| Side | Person | Work |
|---|---|---|
| Software | Umar Hayat Ali | Software testbed, normal traffic, the 7 attacks, recordings, the software dataset, tests |
| Hardware | Project partner | Physical testbed: Raspberry Pi + ESP32 (see the agreed design in [Rules — Must Follow](#rules--must-follow-both-team-members)) |

### How it works, in one picture
```
 1. A fake "lab" runs on one computer:
      users' apps / AI agents ──MCP──> tool server (files, notes, sensors, LED)
      users ──A2A──> Lab Assistant (an AI agent) ──MCP──> tool server

 2. Every conversation is RECORDED (like a voice recorder, but for network packets)
 3. Each recording gets a LABEL: normal or attack (and which attack)
 4. Thousands of labelled recordings = the DATASET
 5. A machine-learning model LEARNS from the dataset to spot attacks
```

---

## B. Tools used (and what each one is for)

| Tool | What it is | What we use it for |
|---|---|---|
| **Python 3.13** | Programming language | All project code |
| **VS Code** | Code editor | Writing and running the code |
| **Git + GitHub** | Version history + online storage for code | Saving every change; sharing with the partner |
| **MCP Python SDK 2.3.0** | Ready-made MCP library | Building the tool server and clients |
| **A2A Python SDK 1.3.1** | Ready-made A2A library | Building the Lab Assistant agent |
| **Ollama 0.40.17** | Runs AI language models on your own computer (free, offline) | The "brain" of the AI agents |
| **llama3.1 (8B)** | The AI model itself | Decides which tools to call for a task |
| **Wireshark / dumpcap / TShark** | Network recording and inspection tools | Recording every packet of a session into a `.pcapng` file |
| **Npcap** (Windows only) | Driver that lets Wireshark record local traffic | Recording traffic between programs on the same PC |
| **pytest** | Testing tool | Hundreds of automatic checks that the code works |
| **pandas, NumPy, scikit-learn, XGBoost, PyTorch, SHAP** | Data and machine-learning libraries | Later parts: features, training and explaining the detector |
| **Google Drive for Desktop** | Syncs a folder to Google Drive | Backing up the recordings (too big for GitHub) |
| **Docker** | Container tool | Installed for later experiments; not needed for the current steps |

Exact library versions are fixed in [`requirements.txt`](requirements.txt), so everyone gets the same versions.

---

## C. Map of the project folders

| Folder / file | What is inside |
|---|---|
| `software_testbed/mcp/` | The MCP tool server (fake workspace: files, notes, synthetic secrets, sensors, LED, buzzer) and a client |
| `software_testbed/a2a/` | The A2A "Lab Assistant" agent and a client |
| `software_testbed/llm/` | The AI agent that uses tools through MCP |
| `software_testbed/addresses.py` | The fake network addresses of every "machine" in the lab |
| `scripts/manifest.py` | Checks that every label row follows the rules |
| `scripts/capture.py` | Starts and stops packet recording |
| `scripts/runner.py` | Runs **one** session: record → run → stop → check → label |
| `scripts/benign_scenarios.py` | The catalogue of **normal** sessions (who does what, and when) |
| `scripts/collect.py` | Runs **thousands** of sessions in batches, checks them and backs them up |
| `scripts/testbed.py`, `scripts/e2e_check.py` | Start the servers; full end-to-end check |
| `tests/` | Automatic tests for everything above |
| `dataset/labels/` | The label files (manifest, capture log, schedules, excluded runs) |
| `traffic/pcaps/` | The recordings (not on GitHub; backed up to Google Drive) |
| `docs/` | Plans, rules and reports, especially [`docs/software-worklog.md`](docs/software-worklog.md), a detailed diary of every step |

---

## D. Set up your computer (do this once)

These steps are for **Windows 11**, which the software side uses.

1. **Install Python 3.13** from python.org. During setup, tick **"Add Python to PATH"**.
2. **Install Git** from git-scm.com (keep the default options).
3. **Install Wireshark** from wireshark.org. When asked, also install **Npcap** and tick **"Support loopback traffic"**. This is essential: without it, local traffic can't be recorded.
4. **Add Wireshark to PATH:** Windows search → "Edit the system environment variables" → *Environment Variables* → *Path* → *New* → `C:\Program Files\Wireshark`.
5. **Install Ollama** from ollama.com, then open a terminal and download the model:
   ```powershell
   ollama pull llama3.1
   ```
6. **Get the code:**
   ```powershell
   git clone https://github.com/iofaraz/AgentNet.git
   cd AgentNet
   git checkout software-dataset
   ```
7. **Create the project's private Python environment and install the libraries:**
   ```powershell
   python -m venv .venv
   .venv\Scripts\python -m pip install torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu
   .venv\Scripts\python -m pip install -r requirements.txt
   ```
8. **Check that everything works** (takes a few minutes; Ollama must be running):
   ```powershell
   .venv\Scripts\python -m pytest -q
   ```
   All tests should pass, with none failed.

---

## E. What was built, step by step

Each step below says **what** was done, **why**, and **how to repeat or check it**. Full details, numbers and reasons are in [`docs/software-worklog.md`](docs/software-worklog.md).

### Phases 1–3: foundation (done before the software work plan)
- **Phase 1 — Research and planning:** studied MCP/A2A and existing detectors; wrote the architecture, the threat model, the list of 7 attacks and the roadmap (see `docs/`).
- **Phase 2 — First MCP testbed:** a simple MCP server and client that could talk to each other.
- **Phase 3 — First A2A testbed:** a simple "echo" agent and client.

### Step 0 — Tools and environment
- **What:** installed everything in section D and fixed exact library versions.
- **Why:** so the work runs the same way on any computer, today and later.
- **Check:** `.venv\Scripts\python -m pytest -q`

### Step 1 — The recording and labelling system (the foundation)
| Sub-step | What it does, in plain words |
|---|---|
| **1.1 Label checker** (`scripts/manifest.py`) | Every recorded session gets one row in a spreadsheet called the **manifest** (who, what, when, normal or attack). The checker refuses any row that breaks the rules (wrong spelling, impossible combinations, a reused ID). Wrong labels would silently ruin the detector. |
| **1.1b Session names** | Every session gets a unique name such as `MCP-S-B0001` (MCP, Software, Benign, number 1). Hardware uses `H`, so the two teams' names never clash. |
| **1.2 Automatic recording** (`scripts/capture.py`) | Starts the packet recorder, waits until it is really recording, stops it, and stores a **fingerprint (SHA-256)** of the file, so any later change to the file can be detected. |
| **1.3 Session runner** (`scripts/runner.py`) | Does one whole session in one go: name it → start recording → run the conversation → stop → check → write the label. If something goes wrong, the session is kept but marked **excluded** with the reason. Nothing is silently lost. |
| **1.4 End-to-end check** (`scripts/e2e_check.py`) | Proves that all of the above works together on the real servers and that the recordings can be read back correctly. |

Try it: `.venv\Scripts\python scripts\e2e_check.py --sessions 2`

### Step 2 — A realistic fake lab
| Sub-step | What it does, in plain words |
|---|---|
| **2.1 Rich tool server** (`software_testbed/mcp/server.py`) | A pretend company workspace: files (meeting notes, reports, a payroll file, a fake API-keys file), notes, a weather tool, a calculator, and simulated sensors, an LED and a buzzer. Different users have different permissions (viewer, operator, admin). Everything is **fake data**; nothing real is ever exposed. Every tool call is written to an **audit log**, which will later prove whether an attack really succeeded. |
| **2.2 AI agent over MCP** (`software_testbed/llm/agent.py`) | An AI model (running in Ollama) receives a task in normal language ("what is the lab temperature?") and decides by itself which tools to call. |
| **2.3 AI Lab Assistant over A2A** (`software_testbed/a2a/`) | Users chat with an assistant agent, which uses the tool server on their behalf, just like real multi-agent systems. |
| **2.4 Separate "machines"** (`software_testbed/addresses.py`) | Every role gets its own address (e.g. the tool server `127.77.1.10`, the assistant `127.77.2.10`, each user's computer its own address), so the recordings look like traffic between real, separate computers. Attackers will get their own address range. All of this stays inside the PC; nothing reaches the real network. |

Try it yourself (start the tool server in one terminal, then run the agent in another):
```powershell
.venv\Scripts\python software_testbed\mcp\server.py
.venv\Scripts\python software_testbed\llm\agent.py "What is the temperature in the lab?" --principal alice
```

### Step 3 — Recording normal (benign) traffic
**3.1 Catalogue of normal behaviour** (`scripts/benign_scenarios.py`)
- Describes what "normal" looks like. There are three kinds of sessions:
  - **scripted:** an app calls 1–8 tools in a realistic order,
  - **AI over MCP:** the AI agent completes one task,
  - **A2A:** a user sends 1–4 requests to the Lab Assistant.
- Every session is generated from a number (a **seed**), so it can be recreated exactly later.
- Realism rules: all users appear; admins sometimes legitimately read secret files; about 5% of steps are honest mistakes; about 40% of AI tasks are multi-step (e.g. "find the file, read it, summarise it"). These rules stop the detector from learning lazy shortcuts like "an error means attack".
- See some example plans: `.venv\Scripts\python scripts\benign_scenarios.py plans --kind mcp-llm --count 5`

**3.2 The big collection run** (`scripts/collect.py`)
- **Plan:** 2,500 normal sessions in 10 **batches** of 250. Each batch has exactly 100 scripted, 75 AI-over-MCP and 75 A2A sessions. Batches can be run at different times and **resume automatically** if interrupted.
- **What has happened so far:**
  1. **Pilot batch** (`S-BENIGN-01`): all 250 sessions were valid, but it showed that the small AI model almost never did multi-step work. It is **kept on record but left out of the final dataset** (listed in `dataset/labels/excluded_runs.csv`).
  2. **Fix:** switched to the larger **llama3.1 8B** model and added multi-step tasks. Now about 37% of AI sessions chain several tool calls.
  3. **Batch `S-BENIGN2-01`:** 250/250 valid, checked and backed up.
  4. **Paused:** deciding whether to run the AI model on a lab computer with a powerful graphics card (much faster). If so, `S-BENIGN2-01` will be redone there, so all data comes from the same setup.
- **Commands:**
  ```powershell
  .venv\Scripts\python scripts\collect.py plan        # show the full schedule
  .venv\Scripts\python scripts\collect.py run --next  # run the next unfinished batch (backs up at the end)
  .venv\Scripts\python scripts\collect.py status      # how many sessions are done
  .venv\Scripts\python scripts\collect.py verify      # full check of labels, recordings and fingerprints
  .venv\Scripts\python scripts\collect.py backup --to "<your Google Drive folder>"
  ```
- **Before a long run:** keep the PC plugged in, turn sleep off (Settings → System → Power), make sure Ollama is running, and close heavy programs.

---

## F. What comes next

| Step | What it means in plain words | Roadmap phase |
|---|---|---|
| **3.2 (finish)** | Record the remaining normal batches | 5 |
| **4. Attacks** | Build a safe "attack simulator", then record each of the 7 attacks: tool poisoning, rug pull, prompt injection via tool output, confused deputy, data exfiltration, agent card spoofing, and unauthorized device control. Attacks use the **same users, mix and timing** as normal traffic, so the detector must learn the attack itself, not side effects. Failed attacks are recorded too. | 6 |
| **5. Encrypted traffic** | Repeat sessions over HTTPS (encrypted), where the content can't be read, only sizes and timing | 9 |
| **6. Dataset pipeline** | Turn recordings into a table of numbers (packet sizes, timing, tool-call sequences); merge the labels; run quality checks; split into training and test parts **by batch** | 7 |
| **7. Compare and deliver** | Charts comparing normal and attack traffic, phase reports, dataset documentation, pull request to `main` | 7 |
| **Later** | Train baseline detectors (Random Forest, XGBoost, neural network), then the improved protocol-aware and encryption-robust detector; final evaluation, including software → hardware | 8–10 |

---

## G. Important rules (short version)

- **Never guess a label.** Never delete a recording; mark it excluded with a reason instead.
- **Everything is fake/synthetic:** no real passwords, people or data.
- **Attacks only inside the testbed**, never against real systems. Physical outputs are harmless (LED, buzzer).
- **All data in one dataset must come from the same setup** (same AI model, same kind of machine). Otherwise the detector learns the setup instead of the attack.
- **Recordings go to Google Drive, not GitHub.** Check copies with the SHA-256 fingerprints.
- The full rules are in [Rules — Must Follow](#rules--must-follow-both-team-members) above and in [`docs/attack-dataset-contract.md`](docs/attack-dataset-contract.md).

---

## H. If something goes wrong

| Problem | What to do |
|---|---|
| `Ollama is not ready` | Open Ollama (or run `ollama serve`) and check that `ollama list` shows `llama3.1` |
| `no loopback interface found` | Reinstall Npcap with **"Support loopback traffic"** ticked |
| `dumpcap` / `tshark` not found | Add `C:\Program Files\Wireshark` to PATH (section D, step 4) and open a new terminal |
| `another session runner is already active` | Another collection is still running; wait or close it |
| `5 sessions in a row were excluded` | Something is broken (often Ollama has stopped). Fix it, then run the same command again; it resumes |
| Port already in use | A server from an earlier run is still open; close that terminal or restart the PC |

---

## Glossary

| Word | Meaning |
|---|---|
| **Agent** | An AI program that can take actions (call tools), not just chat |
| **MCP** | The protocol an AI agent uses to call tools on a tool server |
| **A2A** | The protocol AI agents use to talk to each other |
| **IDS** | Intrusion Detection System, a "security camera" for network traffic |
| **Packet** | A small piece of data sent over a network; every conversation is many packets |
| **Capture / PCAP / `.pcapng`** | A recording of network packets, saved as a file |
| **Session** | One recorded conversation (e.g. a user asking the assistant 2 questions) |
| **Benign** | Normal, harmless traffic (label `AT-00`) |
| **Dataset** | The collection of all labelled sessions |
| **Manifest** | The spreadsheet with one label row per session |
| **Seed** | A number that makes a "random" session repeatable |
| **Batch / run** | A group of 250 sessions collected together |
| **SHA-256 / fingerprint** | A code computed from a file; if the file changes even slightly, the code changes |
| **LLM** | Large Language Model, the AI "brain" (here llama3.1, run by Ollama) |
| **Testbed** | The safe, isolated fake lab where everything runs |
| **Shortcut / data leakage** | When a model learns an accidental difference (e.g. "slow = normal") instead of the real pattern |
| **Excluded run** | A batch kept on record but deliberately left out of the final dataset |
