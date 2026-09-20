# chp-core-rs

Canonical Rust port of the Consensus-Hardening Protocol (CHP) decision
substrate — the native Profile A implementation for the Cubiczan portfolio.
A language-neutral JSON-over-stdio gate binary (`chp-gate`) plus a Rust
library covering the same semantics: R0 gates, deterministic foundation
scoring, devil's-advocate validation, third-party locks, payload envelopes,
a tamper-evident hash-linked JSONL ledger, consensus replay, and the
SwarmFi weighted-median gate.

## Why

Portfolio consumers (TypeScript services, Python orchestrators, Rust
agents) previously each re-implemented CHP gates. This crate is the single
canonical native substrate: one deterministic implementation, one JSON
interface, embedded in any process via stdio.

## Build

```
cargo build --release
```

The binary lands at `target/release/chp-gate`.

## The gate binary

`chp-gate` reads JSON requests from stdin (one per line) and writes one
JSON response per line to stdout. No daemon state, no sockets, no auth —
the calling process owns the ledger paths and trust boundaries.

Request shape:

```json
{"method": "evaluate_r0_gate", "params": {"solvable": true, "scoped": true, "valid": true, "worth_it": true}}
```

Response shape (per request):

```json
{"results": [["Solvable", "PASS"], ["Scoped", "PASS"], ["Valid", "PASS"], ["Worth_it", "PASS"]], "verdict": "PASS"}
```

Result keys are capitalized (`Solvable`, `Scoped`, `Valid`, `Worth_it`)
with values `PASS`/`FATAL`, matching the Python reference. A failed check
yields `verdict: "HALT"`.

### Methods

| Method | Params | Response |
|---|---|---|
| `evaluate_r0_gate` | `solvable, scoped, valid, worth_it` (booleans) | `results` rows + `verdict` |
| `foundation_floor` | `domain` | `floor` (general/AI/agents 70, blockchain/defi 85, finance/CFO/capital-allocation/board 100; unknown domains default to 70 with a warning) |
| `foundation_verdict` | `score`, `domain` (+ optional disclosures/attacks) | `verdict` PASS/REFRAME |
| `evaluate_devils_advocate` | `why_direction_wrong, what_not_seeing, false_consensus_risk, structural_vulnerabilities` | `verdict` + `errors` |
| `payload_build` | `body` (canonical JSON string), `route`, optional `payload_id` | `rendered` (BEGIN_PAYLOAD/END_PAYLOAD envelope) |
| `payload_validate` | `rendered` | `valid` (structure-only — NOT content integrity) |
| `ledger_create` | `path`, `decision_id`, `phase`, `round`, `body` | `entry` (genesis; rejects overwriting an existing file) |
| `ledger_append` | `path`, `entry_type`, `decision_id`, `phase`, `round`, `body` | `entry` (hash-linked) |
| `ledger_verify` | `path` | `broken` (1-based indexes of tampered/broken entries) |
| `ledger_repair` | `path`, `broken` | `remaining` (always empty after a full reseal) |

Unknown methods and malformed lines return `{"error": ...}` responses —
the process never panics on bad input, and the stream continues.

### Example session

```bash
printf '%s\n' \
  '{"method":"evaluate_r0_gate","params":{"solvable":true,"scoped":true,"valid":true,"worth_it":true}}' \
  '{"method":"foundation_floor","params":{"domain":"defi"}}' \
  | ./target/release/chp-gate
```

## Library use

```rust
use chp_core::gates;
use chp_core::ledger::DecisionLedger;

let verdict = gates::evaluate_r0_gate(true, true, true, true);
assert_eq!(verdict.verdict, "PASS");

let mut ledger = DecisionLedger::new("decision.jsonl");
ledger.create("d-1", 0, 0, &serde_json::json!({"title": "demo"}))?;
ledger.append("context_append", "d-1", 1, 1, &serde_json::json!({"a": 1}))?;
assert!(ledger.verify().is_empty());
```

## Ledger semantics

The ledger is an append-only JSONL file. Each entry carries:

- `ts` — canonical ISO-8601 UTC timestamp
- `body` — canonical JSON of the decision payload (sorted keys, Python-style
  separators — byte-identical to the Python reference serializer)
- `envelope` — for `oracle_post` entries, a version-1 payload envelope with
  the body's SHA-256
- `prev_hash` — the previous entry's recorded hash (`""`-anchored genesis
  constant `GENESIS_HASH` at the root)
- `entry_hash` — SHA-256 over the canonical entry (sealed by `seal`)

`verify()` recomputes each entry's hash and flags (1-based) any entry whose
recomputed hash differs from its recorded hash, or whose `prev_hash` no
longer matches the previous entry's **stored** hash. Consequence: an entry
whose stored `entry_hash` field is rewritten flags both itself and the next
entry (its link now dangles) until `repair()` reseals the chain from the
recomputed hashes. A body tamper (body changed, hashes intact) flags exactly
that entry — index preserved, chain not advanced.

`repair(&broken)` walks the whole chain, marks the broken entries
`BROKEN_CHAIN`, reseals every `prev_hash`/`entry_hash` from the recomputed
values, and persists. The pending reasons on the affected case are reset —
repair is a decision, not an invisible patch.

## Conformance

The crate's canonical JSON, R0 vocabulary, foundation floors, payload
envelopes, and ledger hashing are kept byte-compatible with the Python
reference (`consensus-hardening-protocol`). The session's verified
regressions pin: capitalized result keys with FATAL values, HALT on any
failure, floors 70/85/100, payload markers, SHA-256 body integrity, and
SwarmFi's weighted-median replay tolerance.

## Tests

```
cargo test
```

61 tests: 58 unit tests across the modules plus 3 stdio integration tests
that spawn the compiled binary and drive the real protocol. Lint gate:
`cargo clippy --all-targets -- -D warnings` clean; formatting:
`cargo fmt --check` clean.

## CI

GitHub Actions runs fmt check, clippy `-D warnings`, build, and the full
test suite on every push and PR (`.github/workflows/ci.yml`).

## License

MIT
