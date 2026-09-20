//! Deterministic devil's advocate — ported from `chp/devil.py` (protocol 0.1.1).
//!
//! The devil's advocate is a required adversarial role every round: three
//! forced answers (why the direction is wrong, what we're not seeing, the
//! false-consensus risk) plus at most three structural vulnerabilities.

use crate::models::{DecisionCase, DevilsAdvocateRound, Phase, Verdict};

/// The prompt every origin packet must carry to its partner model.
pub const DEVIL_PROMPT: &str = "You are the devil's advocate. Answer three questions:\n\
1. Why is this direction WRONG? (steelman the opposite decision)\n\
2. What are we NOT seeing? (blind spots, missing evidence, unexamined assumptions)\n\
3. Where is the FALSE CONSENSUS risk? (where would both models agree too easily?)\n\
Additionally, list at most three STRUCTURAL vulnerabilities in the current reasoning.\n\
Empty or evasive answers fail the round.";

/// Validate a devil's advocate round against the three required dimensions.
/// Errors are one string per failed requirement, matching the reference.
pub fn validate_devil_round(
    why_direction_wrong: &str,
    what_not_seeing: &str,
    false_consensus_risk: &str,
    structural_vulnerabilities: &[String],
) -> Vec<String> {
    let mut errors = Vec::new();
    if why_direction_wrong.trim().is_empty() {
        errors.push("why_direction_wrong is required".to_string());
    }
    if what_not_seeing.trim().is_empty() {
        errors.push("what_not_seeing is required".to_string());
    }
    if false_consensus_risk.trim().is_empty() {
        errors.push("false_consensus_risk is required".to_string());
    }
    if structural_vulnerabilities.len() > 3 {
        errors.push("structural_vulnerabilities is limited to three items".to_string());
    }
    errors
}

/// Verdict for a round's devil's advocate answers: `PROCEED` when the round
/// passes, `REFRAME` when it fails (the origin must reframe, not continue).
pub fn devils_advocate_verdict(errors: &[String]) -> Verdict {
    if errors.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Reframe
    }
}

/// Build a validated devil's advocate round and record it on the case.
/// Returns the validation errors instead when the round is not clean.
pub fn apply_devil_round(
    case: &mut DecisionCase,
    phase: Phase,
    round_number: u32,
    why_direction_wrong: String,
    what_not_seeing: String,
    false_consensus_risk: String,
    structural_vulnerabilities: Vec<String>,
) -> Result<DevilsAdvocateRound, Vec<String>> {
    let errors = validate_devil_round(
        &why_direction_wrong,
        &what_not_seeing,
        &false_consensus_risk,
        &structural_vulnerabilities,
    );
    if !errors.is_empty() {
        return Err(errors);
    }
    let round = DevilsAdvocateRound {
        phase,
        round_number,
        why_direction_wrong,
        what_not_seeing,
        false_consensus_risk,
        structural_vulnerabilities,
    };
    case.devil_advocate_rounds.push(round.clone());
    case.structural_vulnerabilities = round.structural_vulnerabilities.clone();
    Ok(round)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_round_passes() {
        let errors = validate_devil_round("because", "x", "y", &[]);
        assert!(errors.is_empty());
        assert_eq!(devils_advocate_verdict(&errors), Verdict::Pass);
    }

    #[test]
    fn whitespace_only_answers_fail() {
        let errors = validate_devil_round("  ", "x", "y", &[]);
        assert_eq!(errors, vec!["why_direction_wrong is required".to_string()]);
        assert_eq!(devils_advocate_verdict(&errors), Verdict::Reframe);
    }

    #[test]
    fn more_than_three_vulnerabilities_fail() {
        let vulns: Vec<String> = (0..4).map(|i| format!("v{i}")).collect();
        let errors = validate_devil_round("a", "b", "c", &vulns);
        assert!(errors.iter().any(|e| e.contains("three items")));
    }

    #[test]
    fn apply_records_round_and_structural_list() {
        let mut case = DecisionCase::default();
        let round = apply_devil_round(
            &mut case,
            Phase::Spec,
            1,
            "why".into(),
            "what".into(),
            "risk".into(),
            vec!["sv1".into(), "sv2".into()],
        )
        .unwrap();
        assert_eq!(case.devil_advocate_rounds.len(), 1);
        assert_eq!(case.structural_vulnerabilities, vec!["sv1", "sv2"]);
        assert_eq!(round.round_number, 1);
    }
}
