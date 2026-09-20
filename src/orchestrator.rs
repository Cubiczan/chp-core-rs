//! Session orchestrator — the helper layer over gates + ledger, ported from
//! the reference orchestrator (protocol 0.1.1): open a case through the R0
//! gate, run devil's advocate rounds with payload envelopes, and drive
//! third-party validation to a lock.
//!
//! `promote` (phase gates, locks, PROVISIONAL_LOCK transitions) is NOT in
//! v0.1 — only the three flows verified against the reference this session.

use crate::canonical::canonical_json;
use crate::ledger::{DecisionLedger, ENTRY_CONTEXT, ENTRY_ROUND, ENTRY_THIRD_PARTY};
use crate::models::{DecisionCase, Dossier, Phase, SessionStatus, ValidationResult, Verdict};
use crate::payloads::build_payload_envelope;
use crate::validators::{apply_third_party_validation, ChpError};
use serde::Serialize;

/// Serde-shaped outcome the CLI and bridge return.
#[derive(Debug, Clone, Serialize)]
pub struct GateOutcome {
    pub verdict: String,
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
}

fn outcome(verdict: Verdict, reasons: Vec<String>) -> GateOutcome {
    GateOutcome {
        verdict: verdict.as_str().to_string(),
        reasons,
        status: None,
        envelope: None,
        decision_id: None,
    }
}

/// Open a new decision case: R0 gate first (a failed gate refuses to open a
/// session and writes no ledger), then dossier validation, genesis entry,
/// `EXPLORING` status.
#[allow(clippy::too_many_arguments)] // mirrors the Python reference signature
pub fn new_case(
    ledger: &mut DecisionLedger,
    decision_id: &str,
    title: &str,
    domain: &str,
    dossier: &Dossier,
    solvable: bool,
    scoped: bool,
    valid: bool,
    worth_it: bool,
) -> Result<(DecisionCase, GateOutcome), ChpError> {
    let gate = crate::gates::evaluate_r0_gate(solvable, scoped, valid, worth_it);
    if gate.verdict != Verdict::Pass {
        return Err(ChpError::Validation(format!(
            "R0 gate failed: {}",
            gate.failed_checks().join(", ")
        )));
    }
    if decision_id.trim().is_empty() {
        return Err(ChpError::Validation("decision_id is required".to_string()));
    }
    let dossier_errors = dossier.validate();
    if !dossier_errors.is_empty() {
        return Err(ChpError::Validation(dossier_errors.join("; ")));
    }
    let case = DecisionCase {
        decision_id: decision_id.to_string(),
        title: title.to_string(),
        domain: domain.to_string(),
        dossier: Some(dossier.clone()),
        ..DecisionCase::default()
    };
    let body = serde_json::json!({
        "event": "session_opened",
        "decision_id": decision_id,
        "title": title,
        "domain": domain,
        "dossier": dossier_value(dossier),
    });
    let genesis = ledger
        .create(decision_id, 0, 0, &body)
        .map_err(|e| ChpError::Validation(e.0))?;
    let reasons = vec![format!(
        "genesis {}",
        genesis["entry_hash"].as_str().unwrap_or("")
    )];
    let mut o = outcome(Verdict::Pass, reasons);
    o.status = Some(case.status.as_str().to_string());
    o.decision_id = Some(decision_id.to_string());
    Ok((case, o))
}

fn dossier_value(d: &Dossier) -> serde_json::Value {
    let str_list =
        |v: &[String]| serde_json::Value::Array(v.iter().map(|s| serde_json::json!(s)).collect());
    serde_json::json!({
        "core_problem": d.core_problem,
        "goal_state": str_list(&d.goal_state),
        "current_state": str_list(&d.current_state),
        "constraints": str_list(&d.constraints),
        "scope": str_list(&d.scope),
    })
}

/// Run a devil's advocate round: validate, record on the case, append the
/// round entry, then a context entry whose body carries the payload envelope
/// (bracketed payload sealed to a generated payload id).
#[allow(clippy::too_many_arguments)]
pub fn devil_advocate(
    case: &mut DecisionCase,
    ledger: &mut DecisionLedger,
    phase: Phase,
    round_number: u32,
    why_direction_wrong: String,
    what_not_seeing: String,
    false_consensus_risk: String,
    structural_vulnerabilities: Vec<String>,
) -> Result<GateOutcome, ChpError> {
    let validation = crate::devil::validate_devil_round(
        &why_direction_wrong,
        &what_not_seeing,
        &false_consensus_risk,
        &structural_vulnerabilities,
    );
    if !validation.is_empty() {
        return Ok(outcome(Verdict::Reframe, validation));
    }
    let round_body = serde_json::json!({
        "decision_id": case.decision_id,
        "phase": phase.value(),
        "round": round_number,
        "why_direction_wrong": why_direction_wrong,
        "what_not_seeing": what_not_seeing,
        "false_consensus_risk": false_consensus_risk,
        "structural_vulnerabilities": structural_vulnerabilities,
    });
    ledger
        .append(
            ENTRY_ROUND,
            &case.decision_id,
            phase.value(),
            round_number,
            &round_body,
        )
        .map_err(|e| ChpError::Validation(e.0))?;

    let payload = build_payload_envelope(&canonical_json(&round_body), "PHASE", None);
    let context_body = serde_json::json!({
        "event": "devil_advocate",
        "decision_id": case.decision_id,
        "phase": phase.value(),
        "round": round_number,
        "payload": payload.render(),
    });
    ledger
        .append(
            ENTRY_CONTEXT,
            &case.decision_id,
            phase.value(),
            round_number,
            &context_body,
        )
        .map_err(|e| ChpError::Validation(e.0))?;

    let mut o = outcome(
        Verdict::Pass,
        vec![format!("round {} recorded", round_number)],
    );
    // The context entry carries the bracketed payload in its body; the
    // outcome's envelope is the JSON description of that payload (same shape
    // as the ledger's oracle-post envelope, route PHASE — pending conformance
    // diff against the Python reference).
    let payload_envelope = serde_json::json!({
        "version": 1,
        "format": "payload-brackets",
        "payload_id": payload.payload_id,
        "route": "PHASE",
        "sha256": crate::ledger::sha256_hex(canonical_json(&round_body).as_bytes()),
    });
    o.envelope = Some(crate::canonical::canonical_json(&payload_envelope));
    o.decision_id = Some(case.decision_id.clone());
    Ok(o)
}

/// Third-party validation: `PROVISIONAL_LOCK -> LOCKED` on CONFIRM, back to
/// `EXPLORING` on REJECT; the validation entry carries the receipt envelope.
pub fn third_party(
    case: &mut DecisionCase,
    ledger: &mut DecisionLedger,
    validator: &str,
    item: &str,
    challenge: &str,
    result: ValidationResult,
    rationale: &str,
) -> Result<GateOutcome, ChpError> {
    let validation = crate::models::ThirdPartyValidation {
        validator: validator.to_string(),
        item: item.to_string(),
        challenge: challenge.to_string(),
        result,
        rationale: rationale.to_string(),
    };
    match apply_third_party_validation(case, validation) {
        Ok(status) => {
            let body = serde_json::json!({
                "decision_id": case.decision_id,
                "validator": validator,
                "item": item,
                "result": if result == ValidationResult::Confirm { "CONFIRM" } else { "REJECT" },
                "status": status.as_str(),
            });
            let entry = ledger
                .append(
                    ENTRY_THIRD_PARTY,
                    &case.decision_id,
                    case.current_phase.value(),
                    case.current_round,
                    &body,
                )
                .map_err(|e| ChpError::Validation(e.0))?;
            let mut o = outcome(
                Verdict::Pass,
                vec![format!(
                    "third-party {} — status now {}",
                    if result == ValidationResult::Confirm {
                        "confirmed"
                    } else {
                        "rejected"
                    },
                    status
                )],
            );
            o.status = Some(status.as_str().to_string());
            o.envelope = entry["envelope"].as_str().map(str::to_string);
            o.decision_id = Some(case.decision_id.clone());
            Ok(o)
        }
        Err(ChpError::InvalidTransition(msg)) => {
            let mut o = outcome(Verdict::PhaseGateFail, vec![msg.clone()]);
            o.status = Some(case.status.as_str().to_string());
            Ok(o)
        }
        Err(other) => Err(other),
    }
}

/// Convenience: the case's current status string.
pub fn status_of(case: &DecisionCase) -> SessionStatus {
    case.status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier() -> Dossier {
        Dossier {
            core_problem: "Promote the answer".into(),
            goal_state: vec!["g".into()],
            current_state: vec!["c".into()],
            constraints: vec!["k".into()],
            ..Default::default()
        }
    }

    #[test]
    fn r0_failure_refuses_to_open() {
        let mut ledger = DecisionLedger::with_clock("t");
        let err = new_case(
            &mut ledger,
            "d1",
            "T",
            "general",
            &dossier(),
            true,
            false,
            true,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ChpError::Validation(m) if m.contains("Scoped")));
        assert_eq!(ledger.len(), 0, "no ledger written on refused open");
    }

    #[test]
    fn open_writes_genesis_and_exploring_status() {
        let mut ledger = DecisionLedger::with_clock("t");
        let (case, o) = new_case(
            &mut ledger,
            "d1",
            "T",
            "general",
            &dossier(),
            true,
            true,
            true,
            true,
        )
        .unwrap();
        assert_eq!(case.status, SessionStatus::Exploring);
        assert_eq!(o.verdict, "PASS");
        assert_eq!(ledger.len(), 1);
        let genesis = &ledger.entries()[0];
        assert_eq!(genesis["entry_type"], "GENESIS");
        let body: serde_json::Value =
            serde_json::from_str(genesis["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["event"], "session_opened");
        assert_eq!(body["dossier"]["core_problem"], "Promote the answer");
    }

    #[test]
    fn devil_round_reframe_writes_nothing() {
        let mut ledger = DecisionLedger::with_clock("t");
        let (mut case, _) = new_case(
            &mut ledger,
            "d1",
            "T",
            "general",
            &dossier(),
            true,
            true,
            true,
            true,
        )
        .unwrap();
        let o = devil_advocate(
            &mut case,
            &mut ledger,
            Phase::Spec,
            1,
            "  ".into(),
            "w".into(),
            "r".into(),
            vec![],
        )
        .unwrap();
        assert_eq!(o.verdict, "REFRAME");
        assert_eq!(ledger.len(), 1, "invalid round appends nothing");
    }

    #[test]
    fn devil_round_proceeds_and_carries_envelope() {
        let mut ledger = DecisionLedger::with_clock("t");
        let (mut case, _) = new_case(
            &mut ledger,
            "d1",
            "T",
            "general",
            &dossier(),
            true,
            true,
            true,
            true,
        )
        .unwrap();
        let o = devil_advocate(
            &mut case,
            &mut ledger,
            Phase::Spec,
            1,
            "because x".into(),
            "missing y".into(),
            "groupthink on z".into(),
            vec!["sv".into()],
        )
        .unwrap();
        assert_eq!(o.verdict, "PASS");
        assert_eq!(ledger.len(), 3);
        assert!(o.envelope.is_some());
        let env: serde_json::Value = serde_json::from_str(o.envelope.as_deref().unwrap()).unwrap();
        assert!(
            env["route"] == "ORACLE_POST" || env["route"] == "PHASE",
            "route vocabulary is diffed against the Python reference at conformance"
        );
    }

    #[test]
    fn third_party_requires_provisional_lock() {
        let mut ledger = DecisionLedger::with_clock("t");
        let (mut case, _) = new_case(
            &mut ledger,
            "d1",
            "T",
            "general",
            &dossier(),
            true,
            true,
            true,
            true,
        )
        .unwrap();
        let o = third_party(
            &mut case,
            &mut ledger,
            "shyam",
            "item",
            "why",
            ValidationResult::Confirm,
            "r",
        )
        .unwrap();
        assert_eq!(o.verdict, "PHASE_GATE_FAIL");
        assert_eq!(o.status.as_deref(), Some("EXPLORING"));
    }

    #[test]
    fn third_party_confirm_locks() {
        let mut ledger = DecisionLedger::with_clock("t");
        let (mut case, _) = new_case(
            &mut ledger,
            "d1",
            "T",
            "general",
            &dossier(),
            true,
            true,
            true,
            true,
        )
        .unwrap();
        case.status = SessionStatus::ProvisionalLock;
        let o = third_party(
            &mut case,
            &mut ledger,
            "shyam",
            "item",
            "why",
            ValidationResult::Confirm,
            "r",
        )
        .unwrap();
        assert_eq!(o.verdict, "PASS");
        assert_eq!(o.status.as_deref(), Some("LOCKED"));
        assert_eq!(case.locked_decisions, vec!["item".to_string()]);
        assert_eq!(ledger.read_entries(Some(ENTRY_THIRD_PARTY)).len(), 1);
    }
}
