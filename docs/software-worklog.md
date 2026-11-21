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
| | 1.2 Automated TShark capture | 5–7 | ⏳ Next |
| | 1.3 Session runner (capture → run → stop → log) | 5–7 | Pending |
| | 1.4 End-to-end test with the existing agents | 5–7 | Pending |
| **2. Realistic testbed** | 2.1 Richer MCP server (files, synthetic secrets, mock device) | 5 | Pending |
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
| D7 | **Capture backup.** `.gitignore` excludes `*.pcapng`, `traffic/pcaps/*`, `dataset/raw/*` and `dataset/processed/*`, so pushing does **not** back up captures or processed data. | Noted. To be solved before the first collection run (subpart 3.2). | Choose a backup location for captures (e.g. shared drive or GitHub release assets). |

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
