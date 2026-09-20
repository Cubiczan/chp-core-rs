//! chp-core-rs — native Rust port of the Consensus Hardening Protocol core
//! (reference: `consensus-hardening-protocol` 0.1.1, Python).
//!
//! **Scope.** The protocol's deterministic substrate: R0 viability gate,
//! deterministic foundation scoring with domain floors, payload envelopes,
//! third-party (HITL) validation state transitions, the tamper-evident JSONL
//! decision ledger, devil's advocate rounds, cross-model parity contracts,
//! the oracle disclosure gate, session orchestration helpers, consensus
//! replay, the SwarmFi consensus gate, and a JSON-over-stdio bridge
//! (`bin/chp-gate`) so any language can drive the protocol — the Profile A
//! surface that replaces per-repo Python subprocess bridges.
//!
//! **Faithfulness statement.** Ported against the published consensus
//! hardening semantics verified this session: capitalized R0 keys with
//! PASS/FATAL values, HALT on any failed check, foundation floors
//! 70/85/100 with unknown-domain default 70, PROVISIONAL_LOCK→LOCKED on
//! confirm / →EXPLORING on reject, payload envelope framing, SHA-256 chain
//! integrity with index-preserving tamper detection, and replay-graded
//! consensus.
//!
//! **Known divergences (pending differential conformance).** Exact ledger
//! reason strings, entry-type vocabulary for non-genesis entries, and the
//! devil's-advocate envelope route were recorded from the source but are
//! pending a byte-level diff against the Python reference. The conformance
//! harness (driving both implementations through the same bridge requests)
//! is the gate that retires this caveat; the crate is not "byte-faithful"
//! until it passes.

pub mod bridge;
pub mod canonical;
pub mod consensus;
pub mod devil;
pub mod foundation;
pub mod gates;
pub mod ledger;
pub mod models;
pub mod oracle;
pub mod orchestrator;
pub mod parity;
pub mod payloads;
pub mod swarmfi_gate;
pub mod validators;

pub use foundation::{foundation_floor, foundation_verdict};
pub use gates::evaluate_r0_gate;
pub use ledger::{DecisionLedger, LedgerError};
pub use models::{
    DecisionCase, DevilsAdvocateRound, Dossier, Phase, SessionStatus, ValidationResult, Verdict,
};
pub use validators::{apply_third_party_validation, ChpError};
