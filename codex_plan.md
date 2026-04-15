# codex_plan.md

# Goal

Refactor this repository into a **strict vanilla Signal benchmark**.

Vanilla Signal here means:

- **Pairwise only**
- **X3DH** for initial session establishment
- **Double Ratchet** for ongoing secure messaging
- **No Sender Keys**
- **No MLS semantics**
- **No shared group protocol state**
- **No group epoch**
- **No commit / welcome / tree / ratchet-tree semantics**
- **No fake “Signal group protocol” hidden under renamed MLS structures**

A benchmark with `k` recipients is allowed, but it must be modeled as **`k` independent pairwise Signal sessions/messages**. There must be **no protocol-level shared group object**.

---

# Global execution rules

Codex must follow these rules for every phase:

1. Inspect before editing.
2. Explain findings before changing code.
3. Make only the edits required for the current phase.
4. Keep the code compiling after each phase whenever reasonably possible.
5. After each phase:
    - show changed files
    - summarize design decisions
    - run `cargo fmt`
    - run `cargo build`
    - run phase-relevant tests
6. If a full implementation in one phase is too risky, do a staged migration with a compileable intermediate state.
7. Do not introduce Sender Keys under any circumstances.
8. Do not preserve MLS semantics under neutral names unless the plan explicitly marks something as **harness metadata only**.
9. If a concept is benchmark orchestration rather than protocol state, keep it out of protocol structs and out of protocol byte accounting.
10. Be explicit about remaining approximations.

---

# Non-negotiable protocol invariants

The refactored benchmark must satisfy these invariants:

## A. Protocol model
- No shared Signal “group state”
- No protocol-level `epoch`
- No protocol-level `commit`
- No protocol-level `welcome`
- No protocol-level tree, ratchet tree, or tree size
- No “group convergence” checks based on synthetic shared state

## B. Pairwise session semantics
- Initial session setup must follow X3DH semantics
- One-time prekeys must be consumed correctly
- Ongoing messages must use Double Ratchet session semantics
- Out-of-order delivery must not be rejected merely due to message counter mismatch if the protocol/library supports skipped keys

## C. Benchmark semantics
- “Fanout to N recipients” means N independent pairwise Signal messages
- Sender total cost must reflect the total fanout cost
- Receiver cost must be measured per recipient
- Session setup must be measured separately from steady-state messaging
- Protocol bytes must be separated from harness metadata bytes

## D. Reporting semantics
- No MLS-shaped Signal CSV schema
- No `group_epoch`
- No `tree_size`
- No `encrypted_group_info_bytes`
- No `encrypted_secrets_count`
- No fake compatibility fields that imply Signal has MLS-like state

---

# Target architecture

Implement or migrate toward the following architecture.

## 1. key_repository
Responsibility:
- only prekey-bundle storage and retrieval

Allowed responsibilities:
- store identity key metadata if needed
- store signed prekeys
- store one-time prekeys
- serve prekey bundles
- consume/delete one-time prekeys when handed out

Forbidden responsibilities:
- group membership
- group convergence
- message fanout
- delivery-service-style orchestration
- group commits
- shared protocol version/epoch

## 2. relay
Responsibility:
- dumb message transport only

Allowed responsibilities:
- accept messages
- deliver messages
- optionally simulate delay/reordering if the benchmark needs it

Forbidden responsibilities:
- group state
- membership
- epoch/version authority
- cryptographic decisions
- delivery-service semantics

## 3. worker/client
Responsibility:
- protocol state and cryptographic operations only

Allowed responsibilities:
- local identity
- local prekey state
- session setup
- encrypt/decrypt
- per-peer ratchet state
- protocol-native metrics

Forbidden responsibilities:
- global group protocol state
- global group epoch
- commit-like orchestration state
- synthetic convergence logic

## 4. runner
Responsibility:
- benchmark orchestration only

Allowed responsibilities:
- choose active participants
- choose sender/recipient sets
- define plateau sizes
- define workload schedule
- define payload sizes
- define fanout patterns
- validate decryptability and scenario success

Forbidden responsibilities:
- pretending orchestration state is protocol state
- storing fake protocol epochs
- judging correctness by shared epoch equality

## 5. profiling/export
Responsibility:
- emit honest benchmark metrics

Rules:
- protocol fields only for protocol facts
- orchestration metadata must be clearly separate
- sender totals must not hide O(k) fanout cost
- receiver cost must be explicit
- setup cost must be separate from steady-state cost

---

# Phase plan

## Phase 1 — Full audit and migration map

### Objective
Inspect the repository and produce a file-by-file migration plan.

### Tasks
1. Inspect:
    - `Cargo.toml`
    - `src/`
    - `src/bin/`
    - `scripts/`
    - Docker-related files
    - vendored `libsignal-main/`
2. Identify all MLS-shaped leftovers, including:
    - `group_epoch`
    - `tree_size`
    - `commit`
    - `welcome`
    - synthetic group state
    - group convergence checks
    - delivery-service-like behavior
3. Identify all Signal fidelity gaps:
    - custom ratchet logic
    - lack of full protocol library use
    - OPK lifecycle bugs
    - out-of-order rejection
    - mixed byte accounting
4. Produce a file-by-file migration plan ordered by dependency.

### Deliverables
- audit report
- dependency-ordered refactor plan
- proposed target architecture confirmation

### Constraints
- No code changes unless a tiny helper is necessary for inspection.

---

## Phase 2 — Introduce protocol-neutral and Signal-specific vocabulary

### Objective
Stop using MLS vocabulary in the Signal benchmark wherever it implies protocol semantics.

### Tasks
1. Search for and catalog all stale concepts:
    - epoch
    - commit
    - welcome
    - group state
    - convergence
    - tree
    - delivery service
2. Decide case-by-case:
    - delete entirely
    - move to harness metadata
    - rename into honest orchestration terminology
3. Introduce explicit naming boundaries:
    - protocol state
    - session state
    - orchestration metadata
    - reporting metadata

### Deliverables
- naming map
- initial renames or removals
- brief rationale for each renamed/deleted concept

### Constraints
- No semantic drift: renames must clarify, not obscure.

---

## Phase 3 — Replace MLS-shaped profiling/event schema

### Objective
Make the Signal benchmark export schema truthful.

### Tasks
1. Inspect profiling/event structs and CSV aggregation.
2. Remove MLS-specific Signal fields, including:
    - `group_epoch`
    - `tree_size`
    - `encrypted_group_info_bytes`
    - `encrypted_secrets_count`
    - any welcome/commit/tree-specific artifact fields
3. Create a Signal-specific schema.

### Minimum required exported fields
- `ts_unix_ns`
- `op`
- `implementation`
- `run_id`
- `scenario`
- `worker_id` and/or sender/receiver identifiers
- `wall_ns`
- `cpu_thread_ns`
- `alloc_bytes`
- `alloc_count`
- `success`
- `protocol_bytes`
- `wire_bytes`
- `harness_metadata_bytes`
- `ciphertext_count`
- `recipient_count`
- `fanout_recipients`
- `session_setup_count`
- `app_msg_plaintext_bytes`
- `app_msg_ciphertext_bytes`
- `aad_bytes`
- `payload_class` or equivalent if useful

### Deliverables
- updated event structs
- updated JSONL emission
- updated CSV aggregation
- printed final CSV column list

### Constraints
- No compatibility shim that silently preserves MLS semantics.

---

## Phase 4 — Remove synthetic protocol-level group state

### Objective
Eliminate fake shared Signal group state from the codebase.

### Tasks
1. Find and remove or redesign:
    - `current_epoch_u64`
    - protocol-level `group_id`
    - protocol-level `epoch`
    - `show_group_state`
    - `ensure_converged`
    - any `GroupState` pretending to be Signal protocol state
2. If active participant sets are needed for orchestration:
    - move them into runner-only metadata
    - clearly mark them as benchmark metadata, not protocol state
3. Replace correctness validation with:
    - expected session existence
    - intended-recipient decrypt success
    - non-recipient decrypt failure where relevant
    - honest fanout success checks

### Deliverables
- removed synthetic protocol structures
- new orchestration-only structures
- updated runner validation logic

### Constraints
- No replacement with a renamed fake epoch.
- If an orchestration version counter is needed, call it something like `scenario_step` and keep it out of protocol state.

---

## Phase 5 — Migrate to a protocol-faithful Signal implementation path

### Objective
Use the vendored libsignal implementation where possible instead of a custom simplified ratchet.

### Tasks
1. Inspect the vendored crates under `libsignal-main/rust/`.
2. Identify the correct crate(s) and APIs for:
    - identity keys
    - signed prekeys
    - one-time prekeys
    - session creation
    - message encryption/decryption
    - session storage
3. Update `Cargo.toml` if needed to use the proper protocol crate(s).
4. Replace homegrown session/message logic with a wrapper over the vendored protocol implementation.
5. Keep the benchmark-facing API clean.

### Preferred benchmark-facing API
- `generate_prekey_bundle()`
- `fetch_prekey_bundle(peer)`
- `init_session_to(peer)`
- `encrypt_to(peer, plaintext, aad)`
- `decrypt_from(peer, message)`
- `session_exists(peer)`
- `session_stats(peer)`

### Deliverables
- protocol wrapper
- replaced custom pairwise session logic
- explanation of what is now protocol-native vs harness-native

### Constraints
- No Sender Keys.
- Do not leave the old custom ratchet active in parallel unless strictly necessary for staged migration.

---

## Phase 6 — Fix X3DH one-time prekey lifecycle

### Objective
Match X3DH semantics for OPKs.

### Tasks
1. Ensure the server returns one OPK if present, then deletes it from its store.
2. Ensure the responder deletes the corresponding private OPK after successful use.
3. Support the no-OPK path correctly.
4. Track:
    - whether an OPK was present
    - whether it was consumed
    - prekey bundle fetch size

### Required tests
- setup succeeds with OPK
- setup succeeds without OPK
- OPK is consumed once
- same OPK is not reused on the next fetch/setup
- failed decryption does not incorrectly mark success

### Deliverables
- corrected OPK lifecycle
- tests
- metrics/logging fields

### Constraints
- No `.get()`-style reuse where `.remove()` is protocol-correct.
- Handle rollback carefully if a staged update path is needed.

---

## Phase 7 — Add Double Ratchet-native observability

### Objective
Track ratchet-native session progression instead of fake epoch progression.

### Tasks
1. Determine what the library exposes directly.
2. Capture truthful per-session observability such as:
    - whether the message is an initial/prekey message
    - message number in sending/receiving chain where available
    - whether a DH ratchet step occurred, if observable
    - skipped-message-key stats, if observable
3. Export these metrics only if they are truthful and available.

### Deliverables
- extended Signal event schema
- send-side and receive-side ratchet metrics
- sample JSONL and CSV rows

### Constraints
- Do not invent values for metrics the library does not expose.
- Prefer “not available” over false precision.

---

## Phase 8 — Support out-of-order delivery correctly

### Objective
Stop rejecting valid out-of-order messages in a way that contradicts Double Ratchet behavior.

### Tasks
1. Inspect current decrypt path.
2. Remove local logic that rejects out-of-order messages if the protocol/library already supports skipped keys.
3. Add tests:
    - send 1, 2, 3
    - deliver 2 before 1
    - confirm proper decrypt behavior
    - confirm duplicates are handled safely
    - confirm excessive skip behavior is bounded if applicable
4. Add counters for:
    - `out_of_order_messages_seen`
    - `duplicate_messages_seen`
    - `skipped_keys_buffered` if observable

### Deliverables
- corrected receive path
- tests for out-of-order and duplicate handling
- updated metrics

### Constraints
- Do not reimplement Double Ratchet if the vendored library already provides the right behavior.

---

## Phase 9 — Redesign benchmark operations around vanilla Signal

### Objective
Replace MLS-shaped operation names and meanings with honest vanilla-Signal operations.

### Final operation set
Use these or a closely equivalent naming scheme:

- `generate_prekey_bundle`
- `fetch_prekey_bundle`
- `init_session_to_peer`
- `first_message_send_prekey`
- `steady_state_send`
- `steady_state_receive`
- `ping_pong_roundtrip`
- `fanout_send_to_k_recipients`
- `fanout_receive_one`
- optional `session_reestablish` only if well-justified

### Tasks
1. Remove/deprecate Signal-side operations such as:
    - `create_group`
    - `commit`
    - `welcome`
    - `receive_group_change`
    - `self_update` if it implies MLS-style semantics
2. Update worker commands, runner logic, and profiling names.
3. Ensure every exported operation name is honest.

### Deliverables
- old-to-new operation mapping
- updated command enums / APIs
- updated documentation comments

### Constraints
- Do not keep old names that imply fake protocol equivalence with MLS.

---

## Phase 10 — Rewrite the staircase scenario into honest pairwise fanout

### Objective
Preserve the useful workload shape without pretending Signal has shared group state.

### Semantics
A plateau of size `N` means:
- there are `N` active benchmark participants
- one chosen sender sends to `N-1` recipients
- this results in `N-1` independent pairwise Signal encryptions
- each recipient decrypts independently

### Tasks
1. Keep useful orchestration patterns if desired:
    - increasing plateau sizes
    - repeated rounds
    - varying payload sizes
    - sampled senders
2. Remove protocol dependence on shared state.
3. At each plateau, measure separately:
    - session setup cost for required links
    - sender total fanout cost
    - sender per-recipient cost
    - receiver per-message cost
    - total protocol bytes
4. Validate success via decryptability, not epoch equality.

### Deliverables
- rewritten staircase runner
- precise plateau semantics documented in code/comments
- updated exported metrics

### Constraints
- No `group_id`, `epoch`, or convergence as protocol state.

---

## Phase 11 — Separate protocol bytes from harness metadata bytes

### Objective
Make byte accounting honest.

### Tasks
1. Inspect every place where artifact sizes are recorded.
2. Split byte categories into:
    - `protocol_bytes`
    - `wire_bytes`
    - `relay_overhead_bytes`
    - `harness_metadata_bytes`
3. Ensure CSV/JSONL export reflects these distinctions.
4. Exclude logging/export overhead from protocol measurement.

### Deliverables
- byte accounting model
- code comments for each byte category
- updated measurement fills

### Constraints
- Never present orchestration metadata bytes as Signal protocol bytes.

---

## Phase 12 — Make OpenMLS vs Signal comparisons fair

### Objective
Prevent misleading comparisons.

### Comparison rules
1. OpenMLS group send must be compared against **Signal sender total fanout cost**, not against one per-recipient send.
2. Receiver cost must be compared per recipient.
3. Setup cost must be separate from steady-state cost.
4. Charts and CSVs must not hide the O(k) sender cost of pairwise fanout.

### Add derived metrics
- `sender_cpu_total_ns`
- `sender_cpu_per_recipient_ns`
- `receiver_cpu_ns_per_recipient`
- `total_ciphertext_count`
- `mean_ciphertext_bytes`
- `max_ciphertext_bytes`
- `session_setup_cost_ns`
- `steady_state_cost_ns`

### Deliverables
- fair-comparison reporting fields
- updated analysis helpers or notebooks if present
- short interpretation notes in docs

### Constraints
- No single “send” number that obscures whether it is one group artifact or k pairwise encryptions.

---

## Phase 13 — Build a correctness-focused test suite

### Objective
Ensure the benchmark is valid before optimizing or polishing.

### Minimum required tests
1. X3DH setup with OPK
2. X3DH setup without OPK
3. OPK consumed once
4. first message path correct
5. steady-state message path correct
6. monotonic session progression
7. out-of-order delivery handling
8. duplicate handling
9. fanout to `k` recipients produces `k` independent deliveries
10. excluded recipient cannot decrypt when not in the recipient set

### Deliverables
- deterministic tests where possible
- helpful assertion messages
- coverage summary

### Constraints
- Correctness first, performance second.

---

## Phase 14 — Clean up service boundaries and APIs

### Objective
Make the codebase reflect the new architecture clearly.

### Tasks
1. Refactor responsibilities among:
    - worker/client
    - key_repository
    - relay
    - runner
2. Simplify commands/endpoints.
3. Remove group-control responsibilities from the wrong layers.
4. Keep Docker/runtime integration functional.

### Deliverables
- before/after responsibility table
- updated APIs/commands
- build status

### Constraints
- No ambiguous service that acts like both a prekey server and an MLS delivery service.

---

## Phase 15 — Update scripts, Docker, and docs

### Objective
Make the repository self-explanatory.

### Tasks
1. Update scripts and Docker setup for the new benchmark semantics.
2. Remove stale MLS-shaped assumptions from Signal-specific scripts.
3. Write/update `README.md`.

### README must cover
- what this benchmark measures
- what “vanilla Signal” means here
- what is explicitly excluded
- how fanout/group-size is modeled without Sender Keys
- how to run validation scenarios
- how to interpret exported metrics
- caveats when comparing to OpenMLS

### Deliverables
- updated scripts
- updated Docker config if needed
- complete README

---

## Phase 16 — Final consistency pass

### Objective
Ensure the repo no longer reads like an OpenMLS fork with renamed labels.

### Tasks
1. Search for stale terms and remove or justify them:
    - epoch
    - tree_size
    - commit
    - welcome
    - delivery service
    - convergence
    - self_update if ambiguous
2. Check code, logs, CSV, JSONL, docs, scripts.
3. Run final formatting/build/tests.
4. Produce a final report.

### Final report must include
- what is now protocol-faithful
- what remains an approximation, if anything
- exact benchmark semantics
- known limitations
- how to compare the results to OpenMLS honestly

### Constraints
- Avoid cosmetic-only churn unless it removes ambiguity.

---

# Preferred implementation strategy

When making changes, prefer this sequence:

1. Audit and architecture
2. Schema cleanup
3. Removal of fake group state
4. Migration to protocol-faithful libsignal path
5. OPK correctness
6. Out-of-order correctness
7. Operation redesign
8. Staircase/fanout rewrite
9. Fair reporting
10. Tests
11. Docs and final cleanup

---

# Mandatory “stop and explain” conditions

Codex must stop and explain before proceeding only if one of these occurs:

1. The vendored libsignal crates are insufficient for the intended session/message API.
2. A staged migration temporarily requires coexistence of old and new code.
3. A build/test failure reveals a design contradiction that requires a structural decision.
4. A benchmark choice affects fairness/meaning and needs explicit confirmation.

If none of those occur, continue automatically phase by phase.

---

# Required output format after each phase

After each phase, print:

1. `Phase X complete`
2. `Changed files:`
3. `What changed`
4. `Why this is more protocol-correct`
5. `Build/test results`
6. `Remaining risks before next phase`

---

# Hard bans

The following are banned from the final Signal benchmark implementation:

- Sender Keys
- synthetic protocol group epochs
- commit/welcome emulation
- tree metrics
- fake “group protocol” envelopes presented as vanilla Signal
- collapsing k pairwise sends into one misleading “group send” metric
- reporting harness metadata as protocol bytes
- rejecting out-of-order messages due only to simplistic local counters when the protocol/library should handle them

---

# Final success criteria

The refactor is complete only when all of the following are true:

1. The repo no longer contains MLS-shaped Signal metrics such as `group_epoch` or `tree_size`.
2. The Signal path uses protocol-faithful pairwise session/message behavior.
3. OPK lifecycle is correct.
4. Out-of-order behavior is correct or honestly documented if bounded by library APIs.
5. Fanout is measured as honest pairwise fanout.
6. Reporting distinguishes protocol bytes from harness bytes.
7. OpenMLS comparisons are fair and explicit.
8. The code, logs, schema, and docs consistently describe a vanilla Signal benchmark.