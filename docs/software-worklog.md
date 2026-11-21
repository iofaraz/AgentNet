# AgentNet — Software Work Log

Record of the software-side work: software testbeds, MCP/A2A simulations, benign traffic, the seven attack categories, traffic capture, the software dataset, and testing.

| | |
|---|---|
| **Owner** | Umar Hayat Ali (software side) |
| **Branch** | `software-dataset` (merged into `main` by pull request) |
| **Rules followed** | One subpart at a time · no repository structure changes · no changes to `main` · high-risk steps confirmed first · push after every subpart · security review after every subpart |
| **Binding standard** | [`attack-dataset-contract.md`](attack-dataset-contract.md) v1.1 (proposed; v1.0 plus the session ID change in 1.1b) |

---

## 1. Plan and Status

| Part | Subpart | Roadmap phase | Status |
|---|---|---|---|
| **0. Setup** | 0.1 Tools, libraries and environment | — | ✅ Done |
| **1. Foundation** | 1.1 Manifest schema and validator | 5–7 | ✅ Done |
| | 1.1b Session ID format with environment letter | 5–7 | ✅ Done |
| | 1.2 Automated capture (dumpcap) | 5–7 | ✅ Done |
| | 1.3 Session runner (capture → run → stop → log) | 5–7 | ✅ Done |
| | 1.4 End-to-end test with the existing agents | 5–7 | ✅ Done |
| **2. Realistic testbed** | 2.1 Richer MCP server (files, synthetic secrets, mock device) | 5 | ✅ Done |
| | 2.2 LLM-driven MCP agent (Ollama) | 5 | ✅ Done |
| | 2.3 LLM-driven A2A agents | 5 | ✅ Done |
| | 2.4 Separate hosts so attacker traffic has its own address | 5 | ⏳ Next |
| **3. Benign traffic** | 3.1 Catalogue of benign scenarios with variability | 5 | Pending |
| | 3.2 Collection run, validation and backup | 5 | Pending |
| **4. Attacks** | 4.1 Attack framework (variants, success checks, failed attempts) | 6 | Pending |
| | 4.2–4.8 AT-01 to AT-07, one subpart each | 6 | Pending |
| | 4.9 Attack collection run | 6 | Pending |
| **5. Encrypted traffic** | 5.1 HTTPS for MCP and A2A | 9 (data) | Pending |
| | 5.2 TLS collection run | 9 (data) | Pending |
| **6. Dataset pipeline** | 6.1 PCAP → sessions | 7 | Pending |
| | 6.2 Network-level features | 7 | Pending |
| | 6.3 Protocol-level features | 7 | Pending |
| | 6.4 Label merge, quality checks, leakage-free splits | 7 | Pending |
| **7. Compare and deliver** | 7.1 Attack vs. benign comparison and charts | 7 | Pending |
| | 7.2 Phase reports, dataset documentation, pull request | 7 | Pending |

---

## 2. Open Decisions and Issues

Items that need a decision from both team members, or that affect the hardware side.

| # | Issue | Current handling | Needs |
|---|---|---|---|
| D1 | **Session ID clash.** Contract §4 gave hardware sessions the same ID pattern as software (`MCP-B001`), but also says IDs must never be reused. Combined datasets would clash. 3 digits also only reach 999, while ~2,500 benign sessions are planned. | **Resolved in 1.1b:** environment letter + 4 digits (`MCP-S-B0001` / `MCP-H-B0001`). Contract updated to v1.1 (proposed); validator enforces it. | Hardware side to confirm v1.1 (in the pull request) and use the `H` format. |
| D2 | **Benign `attack_id`.** Contract §2 says `AT-00`; the contract's column table says `N/A`. | Software writes `AT-00`. Validator accepts `N/A` for benign rows with a warning. | Confirm `AT-00` with hardware side. |
| D3 | **Outcome spelling.** Contract says `Failed`; attack-taxonomy.md says `Failure`. | Software writes `Failed`. Validator accepts `Failure` with a warning. | Confirm `Failed`. |
| D4 | **Transport values.** Contract shows only `HTTP`; taxonomy says "HTTP or HTTPS/TLS". | Allowed values: `HTTP`, `HTTPS`. | Confirm. |
| D5 | **Timezone convention.** Contract asks for one convention but does not name it. | ISO 8601 local time with UTC offset and milliseconds, e.g. `2026-11-21T15:46:00.123+05:00`. Validator rejects a manifest that mixes offset and no-offset times. | Hardware side to use the same format. |
| D6 | **Phase 2–3 captures and sample manifest.** `traffic/samples/mcp_benign_manifest.csv` has no header row and an older column layout, and its PCAPs are not on the software machine (captures are git-ignored). | Left unchanged. Not migrated to the new manifest because its timestamps are unknown and labels must not be guessed (taxonomy §6, rule 6). | Hardware side holds the original PCAPs if they are needed. |
| D7 | **Capture backup.** `.gitignore` excludes `*.pcapng`, `traffic/pcaps/*`, `dataset/raw/*` and `dataset/processed/*`, so pushing does **not** back up captures or processed data. | Noted. To be solved before the first collection run (subpart 3.2). Captures are made read-only with a SHA-256 hash (1.2), so a backup copy can be verified. | Choose a backup location for captures (e.g. shared drive or GitHub release assets). |
| D9 | **Real host details in captures.** The demo MCP tool `get_system_info` returned the real OS, Python version and CPU type, so every MCP capture contained them. Privacy issue if the dataset is shared, and an environment-specific signal a model could use to tell environments apart. | **Resolved in 2.1:** tool removed; replaced by `get_server_status` (synthetic, environment-neutral). Tests fail if any tool output contains the host's OS, CPU, Python version, host name or user name, or if server code queries the host. | — |
| D11 | **Tool names shared with the hardware side.** Software-to-hardware evaluation compares the same behaviour in two environments; if the ESP32 MCP server names or shapes its sensor/actuator tools differently, the two datasets differ for reasons unrelated to the environment. | Software uses `list_devices`, `read_sensor(sensor_id)`, `set_led(device_id, on, color)`, `sound_buzzer(device_id, duration_ms)` with DHT22/BME280 sensor types. | Hardware side to confirm or share its tool names and argument shapes; align before collection (3.2). |
| D12 | **Label leakage through identities.** Bearer tokens travel in plaintext HTTP and appear in captures. If attack sessions used identities that benign sessions never use (e.g. an "attacker" user), a model could detect attacks from the token alone. | Tokens are opaque (no user names inside) and synthetic. | Rule for Part 4: attack sessions use the same identities as benign sessions (e.g. a compromised `bob`). Rule for Part 6: tokens and identities are not model features. |
| D10 | **Demo agents produce identical sessions.** In 1.4, every MCP session was 47 packets / 10,304 bytes and every A2A session 100 packets / 17,188 bytes. A dataset of such sessions would let a model memorise sizes instead of learning behaviour. | Evidence recorded; the demo sessions are not added to the dataset manifest. | Variability is the goal of Part 2 and subpart 3.1. |
| D13 | **Label leakage through the session driver.** LLM-driven sessions have ~1–2 s gaps between MCP calls (model thinking time); scripted sessions have millisecond gaps. If benign sessions were mostly LLM-driven and attacks mostly scripted (or the reverse), timing alone would reveal the label. | Recorded. The session runner already stores the scenario name, and LLM sessions record model and seed in `notes`. | Rule for Parts 3–4: benign and attack sessions use the same mix of LLM-driven and scripted drivers, per protocol. Check the mix in 7.1. |
| D8 | **Where capture hashes are stored.** The contract's manifest has no hash column, and its schema must not change without agreement. | **Resolved in 1.3:** a separate capture log `dataset/labels/capture_log.csv` (one row per session, valid or excluded) holds hash, packet/drop counts, scenario name, software versions and exclusion reasons. The manifest is unchanged. | Hardware side may use the same log format. |

---

## 3. Work Record

### 0.1 — Tools, libraries and environment

**Goal:** a reproducible environment in which every later step can run.

**What was done**
- Created a project virtual environment (`.venv`, Python 3.13.7) and installed all libraries; pinned exact versions in `requirements.txt` with setup steps (CPU-only PyTorch to avoid the CUDA download).
- Added Wireshark to PATH so `tshark`/`dumpcap` work from scripts; confirmed the Npcap loopback adapter is available.
- Installed Docker Desktop 29.9.3 (WSL2 backend); pulled the `llama3.2:3b` model into Ollama (0.40.17) alongside the existing `llama3.1`.

**Verification**
- MCP testbed from the venv: connected, discovered 3 tools, called all 3.
- A2A testbed from the venv: Agent Card served; 10/10 messages answered.
- TShark captured 147 loopback packets during both runs; scapy separated MCP (47) and A2A (100) packets; pyshark extracted `tools/list`, `tools/call` and `SendMessage`.
- scikit-learn, XGBoost, PyTorch (1D-CNN forward pass) and SHAP ran on synthetic data; Ollama answered from Python; Docker ran `hello-world`.

**Commit:** `db2c00a` — Pin dependency versions and document setup.

---

### 1.1 — Manifest schema and validator

**Goal:** turn the dataset contract into code, so every session record — software or hardware — is checked by the same rules before it enters the dataset.

**Why first:** the manifest is the integration point between the software and hardware datasets and the input to the dataset pipeline. Every later subpart writes to it.

**Files**

| File | Purpose |
|---|---|
| `scripts/manifest.py` | Schema, validation rules, safe reading/writing, command-line tool |
| `tests/conftest.py` | Makes `scripts/` importable from tests |
| `tests/test_manifest.py` | 46 tests |
| `dataset/labels/manifest.csv` | The shared manifest (header only; no sessions yet) |

**What the validator enforces**
- All 10 required contract columns present; only the 15 contract columns allowed (schema changes need agreement, contract §12).
- Allowed values for label, attack ID, protocol, transport, environment and outcome.
- Fields agree with each other: `AT-00` ⇔ `Benign` ⇔ outcome `N/A`; attacks ⇔ `Attack` ⇔ `Success`/`Failed`; each attack only on its protocols (e.g. AT-01 MCP only, AT-06 A2A only).
- Session ID and capture file name follow contract §4 and §5 and agree with the protocol, attack and environment columns.
- Timestamps are ISO 8601, end ≥ start, one timezone convention per manifest.
- Across rows: no reused session IDs; sessions sharing a capture file do not overlap in time.
- Failed attacks are valid records (taxonomy §5: attempts are not assumed successful).

**Steps**
1. Re-read the contract, taxonomy and roadmap; listed their inconsistencies (D1–D5 above) and chose the contract as the binding source.
2. Wrote `scripts/manifest.py` with the schema in one place and checks split into single-row and cross-row rules.
3. Wrote 46 tests covering valid records, every rule violation, legacy spellings, cross-row rules, file handling and the command line.
4. Mutation-tested the suite: removed the overlap check, allowed AT-01 on A2A, and removed the CSV-injection fix — each change made a test fail. Restored the original afterwards.
5. Created `dataset/labels/manifest.csv` with `init`; confirmed a second `init` refuses to overwrite.
6. Ran the validator on the Phase 3 sample manifest: rejected (no header row) — recorded as D6.

**Usage**
```powershell
python scripts/manifest.py validate dataset/labels/manifest.csv
python -m pytest tests/
```

**Test results:** 46 passed. Mutation tests: 3 of 3 deliberate bugs caught.

**Security review**

| Risk | Finding | Action |
|---|---|---|
| CSV/formula injection (a cell like `=HYPERLINK(...)` runs when opened in Excel) | Free-text columns could carry formulas | Writer neutralises leading `= + - @` and tabs with an apostrophe and flattens newlines; validator warns on such cells in rows from other sources |
| Path traversal via `capture_file` (`../../file`) | The dataset pipeline will join this name with a folder | Only bare file names matching the contract pattern are accepted |
| Accidental loss of recorded sessions | Re-creating the manifest could wipe it | `init` uses exclusive create and refuses to overwrite; `append` writes nothing unless every check passes |
| Bad rows from other sources | Hand-edited or Excel-saved files | Strict header check, ragged-row detection, Excel byte-order mark accepted |
| Regular-expression denial of service | — | Patterns are anchored with no nested repetition |
| Secrets in the repository | None found in tracked or new files | — |
| Testbed exposure | MCP and A2A servers bind to `127.0.0.1` only and have no authentication | Acceptable while loopback-only; revisit in subpart 2.4 when separate hosts are introduced |

**Viva notes**
- *What is the manifest?* The label file: one row per captured session saying what happened in it. Without it a PCAP is just packets with no ground truth.
- *Why validate in code?* Wrong labels silently ruin a trained model; a validator catches them at the moment they are written instead of after training.
- *Why must fields agree?* Contradictions (e.g. benign with outcome "Success") mean a labelling error, and ML models learn labelling errors as if they were real patterns.
- *Why keep failed attacks?* An attack attempt still produces attack-like traffic; dropping failures would bias the dataset toward only successful attacks (taxonomy §5).
- *Why are `session_id`, `outcome`, `environment` never model features?* They are labels or bookkeeping; using them lets the model "cheat" (data leakage, contract §8).
- *What is CSV injection?* Spreadsheet programs execute cells beginning with `=`; a malicious note could run a formula on the reviewer's machine.
- *What is mutation testing?* Deliberately breaking the code to prove the tests notice; a test suite that cannot fail proves nothing.

---

### 1.1b — Session ID format with environment letter

**Goal:** resolve open decision D1 so software and hardware session IDs can never clash.

**Decision:** option "environment letter" chosen by the software owner (alternatives considered: number ranges per environment; fixing IDs at merge time — rejected because it breaks the "never reused" rule).

**New format** (contract v1.1, §4)

| Session | Software | Hardware |
|---|---|---|
| Benign | `MCP-S-B0001`, `A2A-S-B0001` | `MCP-H-B0001`, `A2A-H-B0001` |
| Attack | `MCP-S-AT01-0001`, `A2A-S-AT06-0001` | `MCP-H-AT07-0001` |

**What was done**
1. `scripts/manifest.py`: new `SESSION_ID_PATTERN` (environment letter, 4+ digits) and a new rule — the letter must match the `environment` column (`S` ⇔ Software, `H` ⇔ Hardware).
2. `tests/test_manifest.py`: all IDs moved to the new format; 8 new tests (hardware IDs valid, software and hardware IDs coexist, old format rejected, unknown letter rejected, lowercase rejected, letter/environment mismatch rejected both ways).
3. `docs/attack-dataset-contract.md`: §4 rewritten with the new format; §3 example values corrected (`MCP-S001` and `mcp_at01_001.pcapng` did not follow §4/§5); version table added, status "1.1 proposed".

**Test results:** 54 passed. Mutation test: removing the letter/environment check makes 2 tests fail.

**Security review:** no new inputs or file operations. The new pattern is anchored with no nested repetition (no regular-expression denial of service). No other changes.

**Viva notes**
- *Why put the environment in the ID?* The IDs must be unique across the merged software + hardware dataset. With the letter, uniqueness is guaranteed by construction instead of by coordination.
- *Why 4 digits?* Roughly 2,500 benign sessions are planned; 3 digits stop at 999.
- *Why not just rely on the `environment` column?* The contract requires IDs that are never reused. A key that is only unique together with another column is easy to break when files are merged or filtered.
- *Why does the validator check the letter against the column?* Two places now hold the same fact; if they disagree one of them is wrong, and the validator refuses to guess which.

---

### 1.2 — Automated capture (dumpcap)

**Goal:** record sessions from code — reliably enough that thousands of captures can be trusted without opening each one in Wireshark.

**Files**

| File | Purpose |
|---|---|
| `scripts/capture.py` | `Capture` class (start/stop/verify), interface discovery, command-line tool |
| `tests/test_capture.py` | 29 tests, most making real loopback captures with a throw-away local HTTP server |

**How it works**
1. Checks the file name against the contract (§5), refuses paths and refuses to overwrite an existing capture.
2. Starts Wireshark's `dumpcap` on the loopback interface with a **mandatory** capture filter.
3. Waits until dumpcap prints `File: …` — only then does the session run.
4. After the session, keeps recording for a 1-second grace period, then stops dumpcap gracefully (Ctrl+Break on Windows, SIGINT on Linux).
5. Reads dumpcap's own packet and drop counts, makes the file read-only and computes its SHA-256 hash.
6. Returns a `CaptureResult` (path, start/stop timestamps in manifest format, packets, drops, hash); `ok` is false for empty captures or any dropped packet.

**Design decisions**

| Decision | Reason |
|---|---|
| `dumpcap` instead of `tshark` | dumpcap is the capture engine Wireshark itself uses; it only writes packets (no decoding), so it is lighter and less likely to drop packets |
| Capture filter is required | The loopback interface also carries Ollama (port 11434), editors and Docker traffic; recording everything would mix unrelated packets into the dataset and could record private data |
| Ready = `File:` line, not `Capturing on` | Measured: dumpcap prints `Capturing on` **before** checking the filter. With an invalid filter it prints that line and then exits. Waiting for `Capturing on` would let a session run with no recording. Found by a failing test, then confirmed by hand with three invalid filters |
| 1-second grace period | Measured: catches every closing FIN of every connection |
| Graceful stop | A hard kill can leave the last packets unwritten; mutation test showed 7 tests fail when graceful stop is replaced by kill |
| Read-only + SHA-256 | Contract §5: keep original PCAPs unchanged; the hash proves later that a file was not altered |
| Session errors keep the capture | Failed experiments are recorded, not dropped (contract §9); dumpcap is still always stopped |
| Read stderr on a background thread | dumpcap writes progress continuously; an unread pipe fills up and freezes the capture |

**Measurements on this machine:** dumpcap ready in ≈0.26 s; a 5-request test captured 65 packets with 0 dropped, the first packet being the opening SYN, 5 SYNs and 10 FINs (complete connections).

**Real-world check:** recorded the existing MCP client/server session (outside `traffic/pcaps`): 47 packets, 0 dropped, and the full JSON-RPC exchange was present — `server/discover`, `tools/list`, three `tools/call` (calculate_sum, get_weather, get_system_info), each with its response.

> **Finding for Part 6:** MCP SDK 2.3.0 opens a session with `server/discover`, not the `initialize` handshake of earlier MCP versions. Protocol-feature extraction must use the methods actually observed, not those assumed from older documentation. Also, this TShark version returns HTTP bodies (`http.file_data`) as hex, which must be decoded.

**Test results:** 83 tests pass (54 manifest + 29 capture), three consecutive runs, no dumpcap process left behind.

**Mutation tests (4 of 4 caught):** ready on `Capturing on` → 3 fail · no read-only → 1 fails · hard kill instead of graceful stop → 7 fail · stop errors swallowed → 1 fails (this mutation initially survived; two tests were added to cover it).

**Usage**
```powershell
python scripts/capture.py interfaces
python scripts/capture.py record mcp_benign_software_001.pcapng --filter "tcp port 8000" --seconds 10
```

**Security review**

| Risk | Finding | Action |
|---|---|---|
| Command injection through filter or interface text | — | dumpcap is started with an argument list, never through a shell; no `shell=True`, `os.system` or `eval` in the code |
| Path traversal / overwriting captures | — | Bare contract file names only; existing files refused; finished files read-only |
| Recording unrelated or private local traffic | Loopback carries other applications' traffic | Capture filter mandatory; test proves traffic on another port is excluded |
| Orphaned capture processes | A crash could leave dumpcap recording forever | Always stopped on exit from the `with` block, plus an exit handler that kills leftovers |
| Captures pushed to GitHub | Captures contain full plaintext payloads | `traffic/pcaps/*` and `*.pcapng` are git-ignored (verified) |
| Frozen capture (pipe deadlock) | — | stderr read continuously on a background thread |
| Npcap configuration | `AdminOnly = 0`: any program running as this user can capture loopback traffic | Recorded, not changed — this is what allows capture without administrator rights; acceptable on a single-user laptop |

**Viva notes**
- *What is a capture filter (BPF)?* A rule given to the capture driver, e.g. `tcp port 8000`, so only matching packets are recorded. It works in the kernel before packets reach the program, which is efficient.
- *Capture filter vs. display filter?* A capture filter decides what is recorded (cannot be undone); a display filter (Wireshark's `http.request`) only hides packets in an existing recording.
- *Why do dropped packets matter?* A capture with missing packets has wrong packet counts, sizes and timings — the very features the IDS learns from. Every capture's drop count is checked.
- *What is the loopback interface?* The virtual network inside one computer (`127.0.0.1`). The software testbed's agents talk over it; Npcap's loopback adapter makes it capturable on Windows.
- *What is a SYN / FIN?* The TCP packets that open and close a connection. Seeing the first SYN and every FIN proves a recording is complete from start to end.
- *Why a SHA-256 hash?* A fingerprint of the file; if even one byte changes, the hash changes. It proves the dataset was built from unmodified captures.
- *How was the ready-signal bug found?* A test with an invalid filter failed; reproducing it by hand showed dumpcap prints "Capturing on" before validating the filter. Tests exist to find exactly this kind of hidden assumption.

---

### 1.3 — Session runner

**Goal:** turn "run one benign or attack scenario" into a single call that allocates the ID, captures, runs, verifies and records — so collection runs (Parts 3–5) cannot produce unlabelled, mislabelled or untraceable sessions.

**Files**

| File | Purpose |
|---|---|
| `scripts/runner.py` | `Scenario`, `Outcome`, `SessionRunner`, `SessionResult` |
| `tests/test_runner.py` | 33 tests, all with real loopback captures |
| `dataset/labels/capture_log.csv` | Created on the first real session (not yet) |

**One session, step by step**
1. Check the scenario (protocol, attack ID allowed on that protocol, variant, transport, filter, async function, timeout) — invalid scenarios are refused before anything is recorded.
2. Take an operating-system file lock (one runner at a time).
3. Pre-flight: refuse to run if the manifest is invalid or the capture log has a foreign header.
4. Allocate the next number for this protocol / environment / attack, e.g. `MCP-S-B0007` ↔ `mcp_benign_software_0007.pcapng`.
5. Start the capture (1.2) — a capture that cannot start raises an error and records nothing.
6. Record `start_time`, run the scenario under a time limit, record `end_time`.
7. Stop and verify the capture.
8. Decide validity. **Excluded** if: the scenario raised an error, timed out, returned something other than an `Outcome`, a benign scenario reported a success value, an attack did not report `True`/`False`, the capture is empty, or packets were dropped.
9. Valid → append to the manifest (validated again by 1.1). Every session, valid or excluded → one row in the capture log.

**Capture log columns:** `session_id, run_id, scenario, status, reason, capture_file, sha256, packets_captured, packets_dropped, capture_start, capture_stop, software_versions`

**Design decisions**

| Decision | Reason |
|---|---|
| One session per capture file, same number as the ID | Contract §6 prefers it; any file can be matched to its row at a glance |
| Excluded sessions stay out of the manifest but are logged with the reason, and their capture is kept | Contract §9: never silently discard failed experiments; document exclusions. A crashed session is neither a valid benign nor a valid attack example |
| Attack outcome must be reported explicitly by the scenario | Taxonomy §5: success is checked against predefined conditions, never assumed; an undetermined outcome is excluded rather than guessed |
| Separate capture log instead of new manifest columns | The manifest schema needs both members' agreement to change; contract §11 asks for versions and configuration to be recorded |
| Numbers allocated from manifest **and** capture log **and** existing files | An excluded session's ID is used up even though it is not in the manifest; captures may later move to backup storage (D7) |
| Runner timeout distinguished from a scenario's own `TimeoutError` | A network timeout inside the scenario is a scenario error, not "the runner's limit expired"; the log must state the real cause |
| Scenarios are `async` functions | MCP and A2A clients are asynchronous, and asyncio can cancel a hung scenario cleanly at the time limit |
| Ctrl+C during a session | Capture is stopped, the session is logged as excluded ("interrupted"), then the interruption continues |
| OS file lock | Released automatically if the process dies, so no stale lock can block later runs |
| `start_time`/`end_time` = scenario boundaries | They fall strictly inside the capture window (tested), so the dataset pipeline can cut exactly the session's packets |

**Test results:** 116 tests pass (54 manifest + 29 capture + 33 runner), three consecutive runs, no dumpcap left running.

**Mutation tests (6 of 6 caught):** no pre-flight check · excluded IDs reusable · orphan capture files ignored · undetermined attack accepted · every `TimeoutError` treated as the runner's · interrupted session not recorded. The "excluded IDs reusable" mutation first survived because a second safeguard (existing capture files) masked it; a test was added for the case the second safeguard cannot cover — captures moved to backup — and the first version of that test was itself too weak (still passed under the mutation) and was corrected.

**Security review**

| Risk | Finding | Action |
|---|---|---|
| Spreadsheet formula injection | Error messages and notes are free text | Exclusion reasons pass through `sanitize_free_text`; manifest notes always begin with `scenario=`; device fields are sanitised by `manifest.append` |
| Large or sensitive text in a version-controlled file | Exception messages are written to the capture log, which is pushed | Reasons capped at 500 characters; scenarios will use synthetic data only (contract §2) |
| Injection through `run_id` | Used in file contents | Restricted to letters, digits, `.`, `_`, `-` |
| Two runners at once (duplicate IDs) | — | OS file lock in `traffic/pcaps/.runner.lock` (git-ignored) |
| Half-written sessions | A failure between writing manifest and log | Both files checked before capturing; the manifest is written only after every check passes |
| Runaway sessions | — | Time limit per scenario; capture always stopped |
| Shell / eval / secrets | None in the code or repository | — |

**Viva notes**
- *What does the runner guarantee?* Every captured session ends up either as a valid labelled row in the manifest or as an excluded row in the capture log with its reason — never unrecorded, never half-recorded.
- *Why exclude a session instead of labelling it "Failed"?* "Failed" means the attack was attempted and its success condition was not met — real attack traffic. A crash or timeout means the scenario did not run as designed, so its traffic does not represent the label.
- *Why keep excluded captures at all?* Transparency and reproducibility: anyone can check why a session was excluded, and the exclusion rate is itself a quality measure of the collection.
- *Why does an excluded session use up an ID?* Session IDs are never reused (contract §4); otherwise the log and a future manifest row would refer to two different sessions with one ID.
- *What is a race condition, and how is it prevented here?* Two processes reading "the last number is 6" at the same time would both use 7. A lock lets only one runner allocate and record at a time.
- *What is the difference between capture time and session time?* The capture starts slightly before and ends a grace period after the session; the manifest records the session's own boundaries, which lie inside the capture.

---

### 1.4 — End-to-end test with the existing agents

**Goal:** prove that Part 1 works as a whole on the real MCP and A2A agents — the "initial integration test" of contract §13: produce a capture and a matching metadata record, and read the capture back.

**Files**

| File | Purpose |
|---|---|
| `scripts/testbed.py` | Starts/stops the testbed servers (`MCP_SERVER`, `A2A_SERVER`, `running(...)`) |
| `scripts/e2e_check.py` | Benign scenarios on the existing clients, the end-to-end run and the read-back verification; command-line tool |
| `software_testbed/mcp/client.py` | Refactored: `exercise_tools()` returns the answers (still runnable by hand) |
| `software_testbed/a2a/client.py` | Refactored: `send_messages()` returns the replies (still runnable by hand) |
| `tests/test_testbed.py` | 9 tests with throw-away server scripts |
| `tests/test_e2e.py` | 7 tests sharing one real end-to-end run |

**What the end-to-end run does**
1. Starts the real MCP (port 8000) and A2A (port 9999) servers — refusing if a port is already taken — and waits until they are ready (A2A: Agent Card answers 200).
2. Runs real sessions through the session runner (1.3): `mcp-basic-tools` and `a2a-echo-10`. Each scenario **checks the answers** (tool list, `calculate_sum(10, 20) = 30`, city in the weather answer, all 10 echoes exact); a wrong answer makes the session excluded rather than "benign".
3. Stops the servers gracefully (Ctrl+Break; logs end with "Application shutdown complete").
4. Reads every capture back: manifest validates; every valid session has a log row; SHA-256 still matches; tshark's packet count equals dumpcap's; the capture contains exactly the expected protocol messages.

**Result (real run, 2 sessions per scenario):** 4 of 4 sessions valid and verified.

| Session | Packets | Messages found in the capture |
|---|---|---|
| `MCP-S-B0001`, `MCP-S-B0002` | 47 each | `server/discover`, `tools/list`, `tools/call` ×3 |
| `A2A-S-B0001`, `A2A-S-B0002` | 100 each | `GET /.well-known/agent-card.json`, `SendMessage` ×10 |

**Client refactors.** Network behaviour is unchanged (same requests, same order, same 1-second gaps between A2A messages), with one deliberate exception: the A2A client no longer waits 1 second **after the last** message. That wait produced no traffic, only an idle tail at the end of every benign session; attack sessions would not have it, so it would be a spurious "benign" signal (data leakage). Manual runs (`python client.py`) were re-checked and still work.

**Why these sessions are not in the dataset manifest:** they come from the Phase 2–3 demonstration agents, which Part 2 replaces; mixing them in would add unrepresentative, identical sessions (D10). The run writes to its own output folder.

**Findings recorded:** D9 (real host details inside MCP captures), D10 (identical demo sessions).

**Test results:** 132 tests pass (54 manifest + 29 capture + 33 runner + 9 testbed + 7 end-to-end), three consecutive runs, no dumpcap or server left running.

**Mutation tests (5 of 5 caught):** port-in-use check removed · servers not stopped by `running()` · hash check removed · MCP message check removed · A2A message check removed. The MCP-message mutation first survived because the real agents always send the right messages, so no test ever showed the checker a wrong capture; tests were added that feed it wrong expectations for MCP and A2A.

**Usage**
```powershell
python scripts/e2e_check.py --sessions 2
```

**Security review**

| Risk | Finding | Action |
|---|---|---|
| Recording a foreign program on a testbed port | Something else could be listening on 8000/9999 | Server manager refuses to start when the port is in use |
| Servers reachable from the network | — | Both bind to `127.0.0.1`; a test now fails if a server script stops doing so |
| Server logs pushed to GitHub | Logs may contain request details | In collection runs logs go to `dataset/raw/` (git-ignored, verified); the end-to-end check writes to its own folder |
| Overwriting earlier results | — | Server logs opened in exclusive mode; end-to-end output folder must be empty |
| Orphaned servers | A failure could leave servers running | Always stopped in `finally`, including when a later server fails to start (tested) |
| Real host information in captures | `get_system_info` returns real OS/Python/CPU details | Recorded as D9, fixed in 2.1 |
| Shell / eval / secrets | None | — |

**Viva notes**
- *What does "end-to-end" mean here?* The whole chain on the real agents: servers → session → capture → manifest + log → capture read back and compared with the records.
- *Why check the server's answers in a benign scenario?* "Benign" must mean the session behaved normally. If a server misbehaves, its traffic is not representative of normal traffic, so the session is excluded instead of labelled.
- *Why read captures back with a different tool (tshark) than the one that wrote them (dumpcap)?* An independent check: the packet count and the protocol messages are confirmed by a second program, not by trusting the writer.
- *What is data leakage, with an example from this project?* A signal that reveals the label without being real attack behaviour — e.g. a 1-second idle tail present only in benign sessions, or host details that differ only between environments.
- *Why are identical sessions a problem?* A model can memorise exact packet counts and sizes instead of learning behaviour, giving perfect accuracy on the dataset and failing on anything new.

---

### 2.1 — Richer MCP server

**Goal:** replace the three demonstration tools with a realistic, varied MCP server that every later attack can target, with ground truth for attack outcomes, and without revealing the host (D9).

**Files**

| File | Purpose |
|---|---|
| `software_testbed/mcp/workspace.py` | The synthetic world: users/roles/tokens, virtual files, notes, sensors, actuators, all permission rules |
| `software_testbed/mcp/audit.py` | Append-only JSON-lines audit log; `between()` selects a session's entries by time |
| `software_testbed/mcp/server.py` | Rewritten: 14 tools, bearer-token identity, error masking, audit of every call |
| `software_testbed/mcp/client.py` | Authenticates as a synthetic user; exercises 5 tools as a viewer |
| `scripts/testbed.py` | Passes each run's audit-log path to the MCP server (never overwritten) |
| `scripts/e2e_check.py` | Expects the new tool set and checks a viewer cannot see admin-only files |
| `tests/test_mcp_server.py` | 64 tests (plus 1 new end-to-end test for audit time windows) |

**Tools (14)**

| Group | Tools | Minimum role | Prepares for |
|---|---|---|---|
| Utility | `calculate`, `get_weather`, `get_server_status` | anonymous | benign variety; replaces `get_system_info` (D9) |
| Files | `list_files`, `read_file`, `search_files` | viewer; `finance/` and `secrets/` admin only | AT-03 (content returned by tools), AT-04 (confused deputy), AT-05 (synthetic canary secrets) |
| Notes | `create_note`, `list_notes`, `get_note`, `delete_note` | viewer, own notes only | stateful, varied traffic |
| Sensors | `list_devices`, `read_sensor` | viewer | mirrors the hardware side's DHT22/BME280 (D11) |
| Actuators | `set_led`, `sound_buzzer` | operator | AT-07 (unauthorized physical actuation), simulated and harmless |

Synthetic users: `alice` (viewer), `bob` (operator), `dana` (admin), `reporter-agent` (viewer), `ops-agent` (admin). Callers send `Authorization: Bearer <token>`; no header means anonymous; an unknown token is rejected (never downgraded to anonymous).

**Design decisions**

| Decision | Reason |
|---|---|
| Virtual in-memory workspace | The server never touches the real disk, so experiments cannot damage or read the host; path traversal is impossible by construction (the path rule is kept as defence in depth) |
| Synthetic canary secrets (`AGENTNET-CANARY-…`) in admin-only files | Contract §2 requires synthetic data; a canary found outside the server proves exactly what was exfiltrated (AT-05) |
| Audit log as attack ground truth | Taxonomy §5: outcomes validated against application logs. Entries are matched to sessions **by time**, because sending a session ID in a header would put the label into the captured traffic |
| Opaque bearer tokens | Realistic (as real MCP deployments authenticate), and no user names on the wire (D12) |
| Tool descriptions in one table | Tool poisoning (AT-01) and rug pulls (AT-02) change descriptions/tools; one place to swap them |
| Tool annotations (`read_only_hint`, `destructive_hint`) | MCP's way of telling agents which tools change state; realistic metadata that later attacks may lie about |
| Internal errors masked | Clients see "internal server error"; the real cause goes only to the audit log |
| Size limits everywhere | Note length/count, search hits, query/city/path length, buzzer duration — no request can exhaust memory |
| Response types `dict[str, Any]` | Measured: a bare `dict` return type is sent as text only; typed returns give structured output for every tool |
| Sensor values and weather vary with time | Responses differ between sessions (D10) |

**SDK findings (MCP 2.3.0)**
- `from __future__ import annotations` breaks schema generation for tools defined inside a function (type hints become unresolvable strings) — not used in `server.py`.
- Tools returning bare `dict` get no structured output; `dict[str, Any]` does.
- `Client` can use a custom HTTP client (`streamable_http_client(url, http_client=...)`) — used for the `Authorization` header — and has a `mode` option (`"legacy"` uses the older `initialize` handshake), a possible source of client variety in 3.1.

**Verification**
- End-to-end check (1.4) with the new server: 4 of 4 sessions valid; MCP sessions now 63 packets (`server/discover`, `tools/list`, 5 × `tools/call`); the audit log recorded exactly the 10 calls as `alice / viewer / allowed`, and a test confirms each session's audit entries are found by its manifest time window.
- Manual `python client.py` run against the real server works.

**Test results:** 197 tests pass (54 manifest + 29 capture + 33 runner + 9 testbed + 8 end-to-end + 64 MCP server), three consecutive runs.

**Mutation tests (7 of 7 caught):** restricted files visible to everyone · viewers may actuate devices · `..` path rule removed · forged token downgraded to anonymous · internal errors leaked to the client · host information back in the status tool · anonymous caller gets the admin file list. The `..` mutation first survived because the virtual file system rejected the path anyway ("no such file"); the test now requires the path rule itself to fire.

**Security review**

| Risk | Finding | Action |
|---|---|---|
| Path traversal / host file access | — | Virtual workspace (no real files) + path rule; tested with `../`, absolute, backslash and null-byte paths |
| Privilege escalation | — | Role checks in one place (`World`); viewers cannot read restricted files or actuate; tested for every non-admin user |
| Forged credentials | A failed lookup could silently become anonymous access | Unknown tokens and wrong schemes are rejected outright |
| Information disclosure through errors | Exception text could reveal internals | Generic message to the client; detail only in the audit log |
| Host information in captures (D9) | Old tool sent real OS/CPU/Python | Removed; tests guard both output and source code |
| Resource exhaustion | Unbounded notes or searches | Limits on every input and on stored notes |
| Real secrets in the dataset | — | Only synthetic canaries; no real credentials anywhere (checked) |
| Label leakage via identities (D12) | Tokens are visible in plaintext captures | Opaque tokens; rules recorded for Parts 4 and 6 |
| Network exposure | — | Binds to `127.0.0.1` (test enforces it) |

**Viva notes**
- *Why a synthetic workspace instead of real files?* Attacks are run against it on purpose; it must be impossible for an experiment to touch real data, and every secret must be fake (contract §2).
- *What is a canary token?* A unique fake secret. If it ever appears somewhere it should not — e.g. at an attacker's server — that proves the data was exfiltrated, and exactly which data.
- *What is role-based access control (RBAC)?* Permissions attached to roles (viewer, operator, admin) instead of to individual users; the server checks the caller's role before every sensitive action.
- *How does the server know who is calling?* From the `Authorization: Bearer <token>` HTTP header, as real APIs do. Unknown tokens are rejected, not treated as anonymous.
- *How will you prove an attack succeeded?* From the audit log: for example, a `read_file` of `secrets/api_keys.txt` allowed for a principal who should not have obtained it, or a `set_led` by a caller who was not authorised to request it — selected by the session's time window.
- *Why not put the session ID in a header to make matching easier?* Headers are in the captured traffic; an ID like `MCP-S-AT01-0001` would hand the label to the model (data leakage).
- *What are MCP tool annotations?* Hints such as "read-only" or "destructive" that tell an agent how risky a tool is. They are metadata the server controls — which is exactly what a malicious server can lie about.

---

### 2.2 — LLM-driven MCP agent (Ollama)

**Goal:** an agent in which a real language model — not a script — decides which MCP tools to call. Tool poisoning (AT-01), prompt injection via tool output (AT-03) and confused deputy (AT-04) attack the model's decisions, so they need one; it also gives benign traffic natural variety in tool choice, arguments and timing.

**Files**

| File | Purpose |
|---|---|
| `software_testbed/llm/agent.py` | `OllamaChat` (Ollama `/api/chat` client with tool calling), `run_agent()` (the loop), `AgentResult`/`Step` (trace), `model_digest()`, command-line tool |
| `software_testbed/mcp/server.py` | Tool descriptions now say where identifiers come from (see evaluation) |
| `tests/test_llm_agent.py` | 22 tests |

**How the loop works**
1. List the MCP server's tools and give the model exactly their names, descriptions and input schemas.
2. Send the system prompt and the task; the model replies with tool calls or a final answer.
3. Execute each tool call on the MCP server; return the result (truncated to 4,000 characters) to the model as a `tool` message.
4. Repeat until the model answers, or stop after 8 model turns.

Rejected locally, never sent to the server: unknown tool names, arguments that are not a JSON object, more than 4 tool calls in one turn. Server errors (e.g. access denied) are shown to the model.

**Evaluation (6 tasks, real MCP server, temperature 0.7)**

| Configuration | Tasks correct | Tool calls with errors | Time per task |
|---|---|---|---|
| llama3.2:3b, first prompt (3 seeds) | 12 / 18 | 9 / 18 | 4.9 s |
| llama3.1 8B, same prompt (3 seeds) | 12 / 18 | 10 / 20 | 15.5 s |
| llama3.2:3b, final prompt + identifier hints in tool descriptions (5 seeds) | **28 / 30** | 7 / 30 | **4.7 s** |

Tasks: read lab temperature/humidity; list files in `docs`; create a note; turn on the LED as a viewer (must be refused); turn on the LED as an operator; weather in Lahore.

Findings: both models guessed identifiers (`"temperature"`, `"lab LED"`) instead of looking them up. The larger model was no more accurate and three times slower, so the cause was the information available to the model, not model size. Fixes: the system prompt tells the agent to look identifiers up with a listing tool and to correct a failed call (the first prompt had told it not to retry); tool descriptions state where identifiers come from, as real MCP servers commonly do (e.g. "Sensor ids come from list_devices (e.g. 'dht22-lab')"). **Decision: llama3.2:3b is the default model** — equally accurate here and three times faster, which matters for thousands of sessions.

The remaining ~23% of tool calls that error (some later corrected by the model) are kept: real agents make mistakes, and benign sessions that never error would themselves be an artificial signal.

**Reproducibility:** every run records model name, temperature and seed (a random seed is chosen and recorded when none is given); `model_digest()` returns the installed model's digest.

**Test results:** 219 tests pass, three consecutive runs. Includes a real end-to-end test: llama3.2:3b, authenticated as `alice`, reads a sensor over real HTTP inside a captured session-runner session; the manifest row is valid and the audit log shows `read_sensor / alice / allowed`.

**Mutation tests (6 of 6 caught):** unknown tools sent to the server · results not truncated · no cap on calls per turn · step limit ignored · Ollama HTTP errors ignored · invalid JSON arguments treated as no arguments.

**Usage**
```powershell
cd software_testbed\llm
python agent.py "What is the temperature in the lab?" --principal alice
```

**Security review**

| Risk | Finding | Action |
|---|---|---|
| Model triggers harmful actions | The model chooses tool calls | Every call is limited by the caller's role on the server; the world is synthetic; actuators are simulated |
| Runaway agent | A model can loop | At most 8 turns and 4 calls per turn; LLM timeout 180 s; session-runner time limit |
| Unvalidated model output reaching the server | Hallucinated tools or malformed arguments | Rejected locally; the server validates arguments against its schemas again |
| Agent trusts tool output and descriptions | By design — this is what AT-01/AT-03 exploit | Intentional for the experiments; contained in the synthetic testbed |
| Ollama exposed to the network | — | Listens on `127.0.0.1:11434` only; no `OLLAMA_HOST` override (verified) |
| Model traffic in captures | — | Port 11434 is outside the capture filter |
| Label leakage via timing (D13) | LLM and scripted sessions differ in timing | Rule recorded for Parts 3–4 |

**Viva notes**
- *What is an agent loop?* The model proposes an action (a tool call), the program executes it and returns the result, and the model decides the next step — until it can answer.
- *What is function/tool calling?* The model is given tool names, descriptions and argument schemas, and replies with a structured request (`read_sensor` with `{"sensor_id": "dht22-lab"}`) instead of free text.
- *Why does the agent trust tool descriptions and outputs?* That is how MCP agents work, and it is the weakness tool poisoning and prompt injection exploit; the testbed reproduces it on purpose.
- *Why choose the 3B model over the 8B?* Measured: same accuracy on the testbed tasks, three times faster. The accuracy problem was missing information (where identifiers come from), solved by better descriptions, not a bigger model.
- *Why keep the agent's mistakes in benign traffic?* Real agents err; if benign sessions never contained errors, "contains an error" would wrongly signal an attack.
- *Why record the seed and model?* So a session's model behaviour can be reproduced and reported (contract §11).
- *What is the timing-leakage risk?* LLM sessions are slower between calls than scripted ones; if one label used mostly LLM sessions, timing would reveal the label (D13).

---

### 2.3 — LLM-driven A2A agents

**Goal:** replace the Echo Agent with a real A2A agent — one that understands requests with the model and acts through the MCP server — so A2A traffic carries realistic agent-to-agent delegation, and agent card spoofing (AT-06), confused deputy (AT-04) and exfiltration through A2A (AT-05) have something real to attack.

**Architecture**
```
requester ──A2A (Bearer token of the requester)──► Lab Assistant ──MCP (Bearer token of ops-agent)──► MCP server
                                                     │
                                                     └─ deputy check: requester's role decides what the model may do
```

**Files**

| File | Purpose |
|---|---|
| `software_testbed/a2a/deputy.py` | New. The assistant's authorization layer, enforcing the **requester's** role |
| `software_testbed/a2a/agent_executor.py` | Rewritten: `LabAssistantExecutor` (identity → MCP as `ops-agent` → LLM agent through the deputy → reply), A2A audit log |
| `software_testbed/a2a/server.py` | Rewritten: Agent Card "AgentNet Lab Assistant" (skills `lab-information`, `device-control`; declares Bearer authentication), `build_app()` for in-process tests |
| `software_testbed/a2a/client.py` | Sends natural-language requests with the requester's token (`--principal`) |
| `software_testbed/llm/agent.py` | Handles tool calls the model writes as text; prompt says to state plainly when no tool can help |
| `software_testbed/mcp/server.py` | `read_file` description no longer shows an example path (see findings) |
| `scripts/testbed.py` | A2A server writes an audit log; `A2A_SESSION_BPF` captures both legs |
| `scripts/e2e_check.py` | New A2A scenario; verifies the A2A leg and the MCP leg separately; reads requests by destination port |
| `tests/test_a2a_agent.py` | 42 tests |

**Design decisions**

| Decision | Reason |
|---|---|
| The assistant uses its **own** admin service account on MCP | How real assistant agents are usually deployed — and exactly the precondition for confused-deputy attacks (AT-04). The MCP-side identity is the same in benign and attack sessions (D12) |
| **Deputy check** enforces the requester's role | Without it, any requester would get admin power through the assistant. Three layers: the model is only shown permitted tools; calls to other tools or to admin-only files are refused before MCP; admin-only entries are removed from listings and search results |
| Notes tools are not offered | One shared service account would mix different requesters' notes |
| Unknown/forged tokens rejected; no token = anonymous (public tools only) | Same identity rules as the MCP server; a failed lookup never becomes access |
| A2A audit log: every request, every refused/filtered call, agent-level refusals | Ground truth for attacks: who asked, what the assistant tried, what was stopped. Attempts matter as much as successes |
| A2A sessions capture **both** ports (`tcp port 9999 or tcp port 8000`) | Both legs are visible on a real network; confused deputy and exfiltration are only recognisable across them |
| One MCP connection per A2A request | Each request is an independent unit of work; visible in captures as one `server/discover` per `SendMessage` |
| Tool calls written as text by the model are parsed (valid → executed with the same checks; malformed → one correction request; never returned to the user) | A known small-model behaviour; frameworks handle it in code. Unknown tool names are still refused, so this opens no new path |

**Evaluation (real model, real servers, 5 trials per case)**

| Case | Before fixes (3 trials) | After fixes (5 trials) |
|---|---|---|
| alice (viewer) asks for `secrets/api_keys.txt` → must not get it | 3/3 | 5/5 |
| alice asks to turn on the LED → must be refused, plain-text answer | 1/3 | 5/5 |
| bob (operator) asks to turn on the LED → must happen | 1/3 | 4/5 |
| dana (admin) asks for `secrets/api_keys.txt` → must get it | 0/3 | 5/5 |
| anonymous asks for docs files → must be refused, plain-text answer | 1/3 | 5/5 |
| alice asks for docs files → must get them | 3/3 | 5/5 |
| **Total** | **9/18** (security properties held in all) | **29/30, 0 security violations** |

Also verified: forged token → "Authentication failed"; anonymous weather request answered.

**Findings**
1. **Security bug in the deputy check (found by its own test):** `list_files` with folder `finance` (no trailing `/`) passed the restricted-folder rule, which only matched `finance/`; the call reached MCP with admin rights. Nothing leaked — the result filter removed the entries — but the first layer was wrong. Fixed (`finance`, `finance/`, `/finance`, ` secrets ` are all caught; `financial-report.md` is not); regression tests added.
2. **Refused attempts were not recorded:** a call to a tool hidden from the requester was refused by the agent loop ("unknown tool") before the deputy saw it, so it never reached the audit log. Now recorded as `agent:<tool>`.
3. **A tool description misled the model:** the `read_file` example path `'public/faq.md'` made the model prefix `public/` to paths the user gave exactly (`secrets/…` → `public/secrets/…`), so even the admin could not read the file. Example removed; the description now says to use the exact path given.
4. **Small-model output:** when the needed tool was hidden, the model wrote fake tool calls as text instead of saying it could not help. Handled in code (see decisions) and in the prompt.
5. **Reading multi-service captures:** asked for HTTP requests "on port 9999", tshark also returned the port-8000 requests in the same capture, double-counting the legs. Requests are now selected by destination port. **Part 6 must do the same** when extracting per-leg protocol features.

**Regression check:** the 2.2 MCP-agent evaluation was re-run after the prompt and description changes: 28/30, same as before.

**Test results:** 267 tests pass, three consecutive runs (includes the real end-to-end run with the model-driven A2A agent).

**Mutation tests (8 of 8 caught):** model shown all tools · role check on calls removed · restricted-read check removed · listing filter removed · folder-name bug reintroduced · token ignored (everyone anonymous) · internal errors leaked to the requester · agent-level refusals not audited.

**Security review**

| Risk | Finding | Action |
|---|---|---|
| Privilege escalation through the assistant (confused deputy) | The assistant holds admin rights on MCP | Deputy check (3 layers), tested per role and per tool; policy tested to agree with the MCP server's rules |
| Restricted folder bypass | `finance` without `/` slipped past one layer | Fixed; regression tests |
| Forged identity | — | Unknown tokens rejected; anonymous limited to public tools |
| Information disclosure through errors | — | Requester sees a generic message; details only in the audit log |
| Resource exhaustion | Very long requests | Requests limited to 2,000 characters; agent turn/call limits from 2.2 |
| Unrecorded attack attempts | Hidden-tool attempts were invisible | Recorded (`agent:<tool>`) |
| Agent Card spoofing (AT-06) | The card is unsigned — anyone could serve a look-alike | Intentional for the experiments. A2A supports signed cards (`AgentCard.signatures`, client `signature_verifier`) — the defence to discuss in Part 4 |
| Tokens visible on the wire | A2A and MCP run over plain HTTP | Synthetic tokens; TLS variants in Part 5 |
| Network exposure | — | Both servers bind to `127.0.0.1` (tested) |

**Viva notes**
- *What is a confused deputy?* A program with more authority than its caller (the "deputy") is tricked into using that authority for the caller. Here: the assistant has admin rights on MCP; a viewer must not be able to get admin actions through it.
- *How is the deputy protected?* It checks the **requester's** role, not its own: hides tools, refuses forbidden calls before they reach MCP, and filters admin-only data out of results. Three layers, so one mistake (like the folder bug) does not cause a leak.
- *Why give the assistant admin rights at all?* Real assistants usually run with their own service credentials — that is what makes the confused-deputy threat real, and what the dataset must represent.
- *What is an Agent Card?* The A2A agent's public description (`/.well-known/agent-card.json`): name, skills, endpoint and how to authenticate. Clients trust it to decide whom to talk to — which is what spoofing exploits.
- *How can Agent Card spoofing be prevented?* Signed agent cards: the card carries a signature the client verifies (`signature_verifier`) before trusting it.
- *Why capture both A2A and MCP in an A2A session?* On a network both legs are visible. A confused-deputy or exfiltration attack looks like a normal A2A request followed by an unusual MCP action — only the pair shows the attack.
- *How do you link a request to the actions it caused?* By time window: the A2A audit (requester, task) and the MCP audit (ops-agent's calls) are both selected by the session's manifest start and end times.
