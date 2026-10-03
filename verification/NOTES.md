# chp-core-rs — Lean verification notes

Model: [`Core.lean`](Core.lean) (Lean 4.34.1, core library only, no
`sorry`/`admit`/custom axioms; `#print axioms` on the main theorems shows
only `propext`, `Quot.sound`, and several theorems use no axioms at all).
Compile check: `~/.elan/bin/lean Core.lean` → exit 0.

The chain hash is an **abstract parameter `H`** throughout: every ledger
theorem is structural and holds for any hash function. The one place a
hash property is needed (tamper detection) takes it as an explicit
hypothesis — the formal shadow of SHA-256 collision resistance.

**Scope note.** This crate contains *no money*: the "ledger" is a
decision ledger (votes, phases, envelopes), so there are no balances and
no double-entry conservation law to state. The conservation-style
invariant the code actually maintains is the hash chain itself
(`Chain`), proved below. Scores (`foundation`) are `u32` compared
against floors with no arithmetic; `phase`/`round` are `u8`/`u32`,
modelled as `Nat`.

---

## Theorem → source mapping

### Ledger (`src/ledger.rs`)

| Model | Rust source | Theorems |
|---|---|---|
| `Fields`, `Entry` | entry JSON; hash inputs read at `ledger.rs:138-152` (format string `"{index+1:05}\|{ts}\|{decision_id}\|{phase}\|{round}\|{entry_type}\|{prev}\|{body}\|{envelope}"`, `:147-150`) | — |
| `sealAt` | `seal` + call-site `prev_hash` assignment, `ledger.rs:154-158`, `:185`, `:228` | `sealAt_prevHash`, `sealAt_entryHash` |
| `Chain` | the invariant `create`/`append` maintain and `repair` restores: per-entry `prev_hash` = previous *stored* `entry_hash`, genesis anchored at `GENESIS_HASH = ""` (`:36`) | — |
| `createOp` | `create`, `ledger.rs:161-190` (file-exists error `:170-175`; `entries.clear()` + genesis push `:186-187`) | `createOp_file_exists` (error leaves state untouched), `createOp_fresh`, `createOp_chain`, `createOp_genesis_prev` |
| `appendEntry`, `appendOp` | `append`, `ledger.rs:194-235` (no-genesis error `:203-207`; seal with last stored hash `:226-229`) | `appendOp_empty`, **`appendEntry_prefix`** (history is a prefix of the result — append never rewrites), `appendEntry_length`, **`appendEntry_chain`** (append preserves `Chain`) |
| `chain_append`, `chain_append_inv` | decomposition lemmas over the entry vector | (helpers) |
| `verifyFrom`, `verify` | `verify`, `ledger.rs:245-271` — flags an entry iff recomputed hash ≠ stored hash **or** `prev_hash` ≠ previous *stored* hash; the walk always continues with stored hashes (`:262-269`), so indexes are preserved | **`verifyFrom_of_chain`** (well-formed ⇒ nothing flagged), **`chain_of_verifyFrom_eq_nil`** (nothing flagged ⇒ well-formed — the two `verify` checks are *exactly* the chain conditions), `verify_eq_nil_iff_chain`, `verifyFrom_append` |
| (tamper) | `body_tamper_detected_but_index_preserved` test, `ledger.rs:395-432` | **`verify_flags_body_tamper`**: changing one entry's `body` (hash fields untouched) in a well-formed chain flags exactly that entry's 1-based index — under the hypothesis that `H` separates the tampered fields |
| `repairFrom`, `repair` | `repair`, `ledger.rs:276-290` (reseal every entry in order; stamp `repair_reason` on broken ones) | **`repairFrom_chain` / `repair_chain`** (repair restores `Chain` for *any* input), **`verify_repair`** (post-repair verify is empty), `repairFrom_length`, **`repairFrom_content`** (repair rewrites only the chain fields — application content and order preserved, indexes preserved) |

Model divergences from the Rust, by construction: `verify` in Rust also
*stamps* `envelope_valid`/`integrity_valid` fields (not part of the
hash, never affecting the returned indexes — see Finding 4); `repair`'s
`repair_reason` string is abstracted away. `create`'s model makes the
ledger state an explicit input/output instead of `&mut self`.

### Consensus replay (`src/consensus.rs`)

`Round` = the two things `replay` reads from a round body (`:47-52`):
`vote: Option<String>` and "echo explicitly `false`". `grade` =
`replay`'s per-decision grading (`:55-65`); the Rust test
`dedup(votes).len() ≤ 1` is modelled by the equivalent decidable
predicate `allSameVote` ("all votes equal" — the two conditions agree
on every input).

| Theorem | Claim |
|---|---|
| `grade_eq` | Every decision gets exactly one of the three grades (grading is total). |
| `grade_insufficient_of_missing` | A round entry with no vote ⇒ `insufficient` (`:55-57`). |
| `grade_insufficient_of_unconfirmed` | A round entry with `payload_echo_confirmed == false` ⇒ `insufficient` (`:50-52`). |
| `grade_unanimous_all_eq` | `unanimous` ⇒ no unconfirmed echoes, and **all recorded votes are the same string**. |
| `grade_ne_unanimous_of_dissent` | Two entries voting differently ⇒ never `unanimous`. Acceptance = unanimity over recorded entries. |
| `grade_single` | **One** agreeing confirmed entry already grades `unanimous` — the minimum quorum is 1 entry. |
| `grade_nil` | The grading function maps an empty round list to `unanimous` (vacuous) — unreachable in `replay`, whose map only holds ids with ≥ 1 round entry (`:28-35`). |

### Third-party validation (`src/validators.rs`, `src/orchestrator.rs`)

`applyTP` = `apply_third_party_validation` (`validators.rs:39-62`);
`none` is `Err(InvalidTransition)`, returned **before any mutation**
(`:44-48`).

| Theorem | Claim |
|---|---|
| `applyTP_none_of_not_provisional` | Any status ≠ `PROVISIONAL_LOCK` ⇒ transition rejected, case unchanged. |
| `applyTP_locked_absorbing` | `LOCKED` is absorbing for this operation. |
| `applyTP_confirm_status` | CONFIRM from `PROVISIONAL_LOCK` ⇒ `LOCKED`. |
| `applyTP_confirm_records` | CONFIRM records the item in `locked_decisions`. |
| `applyTP_confirm_nodup` (+ `nodup_append_singleton`) | `locked_decisions` stays duplicate-free — the `contains` dedup at `validators.rs:54-56` is load-bearing and correct. |
| `applyTP_reject` | REJECT ⇒ back to `EXPLORING`, `locked_decisions` untouched, exactly one flip criterion `"Validation rejected: {item}"` appended, validation logged. |

Session-level failure atomicity (orchestrator, cited not re-modelled):
R0 failure ⇒ `new_case` errors before `ledger.create` — no ledger
written (`orchestrator.rs:58-63`, test `r0_failure_refuses_to_open`);
invalid devil round ⇒ `REFRAME` returned before any append
(`orchestrator.rs:124-133`); invalid third-party transition ⇒
`PHASE_GATE_FAIL` outcome with no append (`orchestrator.rs:224-228`).

### R0 gate (`src/gates.rs`) and foundation floors (`src/foundation.rs`)

| Model | Rust source | Theorems |
|---|---|---|
| `r0Pass` | `evaluate_r0_gate`, `gates.rs:38-55` (verdict `PASS` iff all four checks `PASS`) | `r0Pass_iff` (PASS ⟺ all four), `r0Pass_false_of_any` (any FATAL ⇒ HALT) |
| `foundationFloor` | `foundation_floor`, `foundation.rs:23-47`; floors table `:13-28`; unknown ⇒ default 70 | `foundationFloor_range` (always 70/85/100 — never 0), `foundationFloor_ge` (≥ 70), `foundationFloor_finance` = 100, `foundationFloor_blockchain` = 85, `foundationFloor_general` = 70, `foundationFloor_unknown` (unlisted ⇒ 70) |
| `foundationPass` | `foundation_verdict`, `foundation.rs:60-66` (PASS iff score ≥ floor) | `foundationPass_finance` (finance passes ⟺ score ≥ 100) |

(The model takes the domain key already trimmed/lowercased, as
`foundation_floor` normalises before lookup, `foundation.rs:24`. The
near-match warning at `:31-45` does not change the returned floor.)

### SwarmFi gate (`src/swarmfi_gate.rs`)

`swarmGate` abstracts the f64 weighted-median arithmetic into a `split`
input and keeps the count quorum (`MIN_SOURCES = 3`, `:36`):

| Theorem | Claim |
|---|---|
| `swarm_noData_of_lt_three` | < 3 votes ⇒ `NO_DATA`, no median — for any weights/values. |
| `swarm_decides_of_ge_three` | ≥ 3 votes ⇒ a median is produced and the verdict is `PASS`/`SPLIT_DAMPED`. |
| `swarm_noData_iff` | `NO_DATA` ⟺ below the 3-vote quorum. |

---

## Findings (from the code, not the README)

1. **There is no quorum of distinct approvers anywhere.** The task's
   premise doesn't survive contact with the code:
   - `consensus.rs` round bodies carry **no voter identity at all** —
     only `vote` and `payload_echo_confirmed`. Grading counts round
     *entries*; entries are grouped by `decision_id` only (the `phase`
     and `round` fields are never read in replay), so duplicate rounds
     count repeatedly and one entry suffices for `unanimous`
     (`grade_single`).
   - The third-party lock is **1-of-1**: a single validation from *any*
     `validator` string locks the case; the validator is recorded but
     never allowlisted, counted, or required to be distinct from the
     proposer (`validators.rs:39-62`).

2. **`PROVISIONAL_LOCK` is unreachable inside the crate.**
   `orchestrator.rs:5-6` states `promote` is not in v0.1, and nothing in
   the crate sets `ProvisionalLock` — only tests assign
   `case.status = SessionStatus::ProvisionalLock` directly
   (`orchestrator.rs` test `third_party_confirm_locks`). So the
   `LOCKED` state, and the safety of the "requires PROVISIONAL_LOCK"
   check, depend on the *caller* managing the middle state honestly.
   Six of the nine `SessionStatus` variants (`models.rs:66-76`) are
   never produced by any transition in the crate.

3. **`create` can silently wipe history.** Its only overwrite guard is
   the ledger *file's* existence (`ledger.rs:170-175`); it then does
   `entries.clear()` (`:186`). For an in-memory ledger (empty path,
   `with_clock`) `create` always succeeds and discards all entries —
   "append-only" is a property of `append`, not of the ledger object.
   Modelled exactly (`createOp` ignores the previous state).

4. **`verify` mutates, and `repair` doesn't clear the marks.** `verify`
   writes `envelope_valid`/`integrity_valid = false` into flagged
   entries (`ledger.rs:256-257`) — a check with side effects, persisted
   by the next `persist()` from any operation. `repair` reseals hashes
   but never resets those flags (`:280-286`), so a repaired,
   verify-clean entry still carries `"integrity_valid": false` in the
   JSON. It also sets `repair_reason` only on entries listed in
   `broken` while resealing *all* entries — after a repair, later
   entries' hashes change without any `repair_reason` marking them.

5. **Failed appends/creates are not atomic.** `append` pushes the entry
   into memory *before* `persist()?` (`ledger.rs:231-232`; same pattern
   in `create`, `:187-188`). On an I/O error the caller sees `Err` but
   the in-memory ledger has advanced; a caller that retries the append
   creates a duplicate entry, and the next successful persist writes
   the whole in-memory chain, silently including the "failed" entry.

6. **`repair` reports success unconditionally.** `let _ =
   self.persist();` (`ledger.rs:288`) discards persistence errors, and
   `repair` always returns an empty "remaining" list — matching the
   README but meaning a repair that never reached disk is
   indistinguishable from one that did.

7. **`replay` never verifies the chain.** `consensus::replay` loads the
   file and grades bodies directly (`consensus.rs:26-27`); `load`
   itself validates only JSON well-formedness (`ledger.rs:315-330`).
   A tampered ledger replays to exactly the same grades as the intact
   one with the same bodies — tamper evidence exists only if someone
   calls `verify` separately.

8. **Missing echo field counts as confirmed.** Only an explicit JSON
   `false` for `payload_echo_confirmed` marks a round unconfirmed
   (`consensus.rs:50-52`); absent/null/non-boolean all count as
   confirmed and can still grade `unanimous`. (The other direction is
   safe: an unparseable body degrades to vote `None` ⇒ `insufficient`.)

9. **Opened-but-unvoted decisions are invisible in replay.** The
   summary only includes ids with ≥ 1 `round` entry
   (`consensus.rs:28-35`); a case with only a GENESIS entry appears
   nowhere — not even as `insufficient`.

10. **Hash-input canonicalisation caveats.** `entry_hash` coerces
    `phase`/`round` via `as_i64().unwrap_or(0)` (`ledger.rs:141-142`):
    JSON values `1`, `1.0`, and `"1"` in those fields all hash as
    `1`/`0` rather than failing — distinct on-disk entries can share a
    hash input. Tampering is still detected (the stored hash won't
    match the recomputation), but the hash binds the *coerced* values,
    not the bytes.

11. **Index casts.** `verify`/`repair` use `(i + 1) as u32`
    (`ledger.rs:255`, `:278`) — ledgers beyond `u32::MAX` entries would
    truncate indexes. `entry_hash`'s `index + 1` is `usize` (safe).
    No other overflow surface: floors are compared, never computed;
    `format_iso8601` arithmetic is on `u64` seconds.

12. **SwarmFi gate: inputs are unvalidated f64s.** Weights are never
    checked (`swarmfi_gate.rs:52-61`): negative weights invert the
    cumulative-median logic, a zero total makes the first (smallest)
    value the median (`cumulative >= 0.0` immediately), and NaN
    weights/values are silently absorbed by
    `partial_cmp().unwrap_or(Ordering::Equal)` (`:47-51`) — NaN sorts as
    "equal to everything". Also: "damping" can *amplify* — the factor
    is `side_size / len * 2` (`:97-100`), which exceeds 1 for the larger
    side of a split; and `consensus_ratio` (`:119-123`) is reported but
    never gates the verdict, so `PASS` is compatible with a ratio
    near 0. Like the other gates, the 3-source minimum counts slice
    entries, not identified independent sources (`:39-46`).

13. **Payload ids are predictable and can collide.** `make_payload_id`
    (`ledger.rs:333-354`) is an LCG re-seeded per call from wall-clock
    sub-second nanos; two `oracle_post` appends in the same clock tick
    produce the *same* payload id. (Peripheral to the chain, but the
    envelope presents `payload_id` as an identifier.)

14. **Known divergence (already documented in the source).**
    `ledger.rs:11-15` and `lib.rs` state that exact reason strings and
    entry-type vocabulary were "recorded from memory" and are pending a
    differential conformance diff against the Python reference; this
    model follows the **Rust code as-is**, per the task instruction.
