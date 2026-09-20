//! Lock progression — ported from `chp/validators.py` (protocol 0.1.1).
//!
//! Third-party validation requires `PROVISIONAL_LOCK` status. `CONFIRM`
//! locks the case (`LOCKED`) and records the item in `locked_decisions`;
//! anything else (i.e. `REJECT`) flips the case back to `EXPLORING` and
//! appends a flip criterion.

use crate::models::{DecisionCase, SessionStatus, ThirdPartyValidation, ValidationResult};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChpError {
    /// Python reference raises `ValueError`.
    InvalidTransition(String),
    /// Python reference raises `ValueError` over validation errors.
    Validation(String),
}

impl fmt::Display for ChpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChpError::InvalidTransition(m) | ChpError::Validation(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ChpError {}

/// Third-party confirmation: `PROVISIONAL_LOCK -> LOCKED` (or back to
/// `EXPLORING` on rejection). Mutates the case exactly like the reference.
pub fn apply_third_party_validation(
    case: &mut DecisionCase,
    validation: ThirdPartyValidation,
) -> Result<SessionStatus, ChpError> {
    if case.status != SessionStatus::ProvisionalLock {
        return Err(ChpError::InvalidTransition(
            "third-party validation requires PROVISIONAL_LOCK status".to_string(),
        ));
    }
    let confirmed = validation.result == ValidationResult::Confirm;
    let item = validation.item.clone();
    case.third_party_log.push(validation);
    if confirmed {
        case.status = SessionStatus::Locked;
        if !case.locked_decisions.contains(&item) {
            case.locked_decisions.push(item);
        }
    } else {
        case.status = SessionStatus::Exploring;
        case.flip_criteria
            .push(format!("Validation rejected: {item}"));
    }
    Ok(case.status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provisional_case() -> DecisionCase {
        DecisionCase {
            status: SessionStatus::ProvisionalLock,
            ..Default::default()
        }
    }

    fn validation(result: ValidationResult) -> ThirdPartyValidation {
        ThirdPartyValidation {
            validator: "shyam".into(),
            item: "decision-1".into(),
            challenge: "Confirm the decision".into(),
            result,
            rationale: "named human".into(),
        }
    }

    #[test]
    fn confirm_locks_and_records() {
        let mut case = provisional_case();
        let status =
            apply_third_party_validation(&mut case, validation(ValidationResult::Confirm)).unwrap();
        assert_eq!(status, SessionStatus::Locked);
        assert_eq!(case.status, SessionStatus::Locked);
        assert_eq!(case.locked_decisions, vec!["decision-1".to_string()]);
        assert_eq!(case.third_party_log.len(), 1);
    }

    #[test]
    fn reject_flips_back_to_exploring() {
        let mut case = provisional_case();
        let status =
            apply_third_party_validation(&mut case, validation(ValidationResult::Reject)).unwrap();
        assert_eq!(status, SessionStatus::Exploring);
        assert!(case.locked_decisions.is_empty());
        assert_eq!(
            case.flip_criteria,
            vec!["Validation rejected: decision-1".to_string()]
        );
    }

    #[test]
    fn requires_provisional_lock() {
        let mut case = DecisionCase::default(); // EXPLORING
        let err = apply_third_party_validation(&mut case, validation(ValidationResult::Confirm))
            .unwrap_err();
        assert_eq!(
            err,
            ChpError::InvalidTransition(
                "third-party validation requires PROVISIONAL_LOCK status".to_string()
            )
        );
    }

    #[test]
    fn locked_decisions_deduplicated() {
        let mut case = provisional_case();
        apply_third_party_validation(&mut case, validation(ValidationResult::Confirm)).unwrap();
        // Re-locking requires PROVISIONAL_LOCK, so simulate a fresh provisional stage.
        case.status = SessionStatus::ProvisionalLock;
        apply_third_party_validation(&mut case, validation(ValidationResult::Confirm)).unwrap();
        assert_eq!(case.locked_decisions.len(), 1);
    }
}
