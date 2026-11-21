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
| **2. Realistic testbed** | 2.1 Richer MCP server (files, synthetic secrets, mock device) | 5 | ⏳ Next |
| | 2.2 LLM-driven MCP agent (Ollama) | 5 | Pending |
| | 2.3 LLM-driven A2A agents | 5 | Pending |
| | 2.4 Separate hosts so attacker traffic has its own address | 5 | Pending |
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
| D9 | **Real host details in captures.** The demo MCP tool `get_system_info` returns the real OS, Python version and CPU type, so every MCP capture contains them. Privacy issue if the dataset is shared, and an environment-specific signal (software and hardware hosts answer differently) that a model could use to tell environments apart instead of learning behaviour. | Not changed in 1.4 (changing testbed tools is subpart 2.1). | Replace with synthetic, environment-neutral answers in 2.1. |
| D10 | **Demo agents produce identical sessions.** In 1.4, every MCP session was 47 packets / 10,304 bytes and every A2A session 100 packets / 17,188 bytes. A dataset of such sessions would let a model memorise sizes instead of learning behaviour. | Evidence recorded; the demo sessions are not added to the dataset manifest. | Variability is the goal of Part 2 and subpart 3.1. |
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
