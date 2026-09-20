//! chp-gate — CHP consensus-hardening gate over stdio.
//!
//! Reads JSON requests (one per line) from stdin, writes JSON responses (one
//! per line) to stdout. Methods: evaluate_r0_gate, foundation_floor,
//! foundation_verdict, evaluate_devils_advocate, payload_build,
//! payload_validate, ledger_create, ledger_append, ledger_verify,
//! ledger_repair.

fn main() {
    chp_core::bridge::serve();
}
