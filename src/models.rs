//! Canonical CHP data model — ported from `chp/models.py` (protocol 0.1.1).
//!
//! Enum `as_str()` values match the Python `str`-enum values exactly
//! (ledger entries and gate outcomes embed them verbatim).

use std::fmt;

/// Session phase (int enum in the reference: 0/1/2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Foundation,
    Spec,
    Implementation,
}

impl Phase {
    pub fn value(self) -> u8 {
        match self {
            Phase::Foundation => 0,
            Phase::Spec => 1,
            Phase::Implementation => 2,
        }
    }
    pub fn from_value(v: u8) -> Phase {
        match v {
            1 => Phase::Spec,
            2 => Phase::Implementation,
            _ => Phase::Foundation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Halt,
    Reframe,
    Iterate,
    Converged,
    PhaseGateFail,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Halt => "HALT",
            Verdict::Reframe => "REFRAME",
            Verdict::Iterate => "ITERATE",
            Verdict::Converged => "CONVERGED",
            Verdict::PhaseGateFail => "PHASE_GATE_FAIL",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionStatus {
    #[default]
    Exploring,
    Provisional,
    ProvisionalLock,
    Locked,
    Converged,
    Unresolved,
    RequiresHumanVerification,
    ReframeRequired,
    Halt,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Exploring => "EXPLORING",
            SessionStatus::Provisional => "PROVISIONAL",
            SessionStatus::ProvisionalLock => "PROVISIONAL_LOCK",
            SessionStatus::Locked => "LOCKED",
            SessionStatus::Converged => "CONVERGED",
            SessionStatus::Unresolved => "UNRESOLVED",
            SessionStatus::RequiresHumanVerification => "REQUIRES_HUMAN_VERIFICATION",
            SessionStatus::ReframeRequired => "REFRAME_REQUIRED",
            SessionStatus::Halt => "HALT",
        }
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Confirm,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dossier {
    pub core_problem: String,
    pub goal_state: Vec<String>,
    pub current_state: Vec<String>,
    pub prior_decisions: Vec<String>,
    pub constraints: Vec<String>,
    pub unknowns: Vec<String>,
    pub scope: Vec<String>,
    pub origin_direction: Vec<String>,
    pub prior_round_summary: Vec<String>,
    pub unknowns_carried: Vec<String>,
    pub foundation_score: Option<u32>,
    pub structural_vulnerabilities: Vec<String>,
}

impl Dossier {
    /// `core_problem` is required (and must not be `"UNKNOWN"`); the dossier
    /// must include at least three populated context sections among
    /// goal_state / current_state / constraints / scope.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.core_problem.is_empty() || self.core_problem == "UNKNOWN" {
            errors.push("core_problem is required".to_string());
        }
        let populated = [
            &self.goal_state,
            &self.current_state,
            &self.constraints,
            &self.scope,
        ]
        .iter()
        .filter(|s| !s.is_empty())
        .count();
        if populated < 3 {
            errors
                .push("dossier must include at least three populated context sections".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FoundationDisclosure {
    pub weakest_assumptions: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub key_vulnerability: String,
}

impl FoundationDisclosure {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.weakest_assumptions.is_empty() || self.weakest_assumptions.len() > 3 {
            errors.push("weakest_assumptions must include 1-3 items".to_string());
        }
        if self.invalidation_conditions.is_empty() || self.invalidation_conditions.len() > 2 {
            errors.push("invalidation_conditions must include 1-2 items".to_string());
        }
        if self.key_vulnerability.is_empty() {
            errors.push("key_vulnerability is required".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FoundationAttack {
    pub assumption_attacks: Vec<String>,
    pub invalidation_exploitation: Vec<String>,
    pub vulnerability_strike: String,
    pub foundation_score: u32,
    pub attack_summary: String,
}

impl FoundationAttack {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.assumption_attacks.is_empty() {
            errors.push("assumption_attacks is required".to_string());
        }
        if self.vulnerability_strike.is_empty() {
            errors.push("vulnerability_strike is required".to_string());
        }
        if self.foundation_score > 100 {
            errors.push("foundation_score must be between 0 and 100".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThirdPartyValidation {
    pub validator: String,
    pub item: String,
    pub challenge: String,
    pub result: ValidationResult,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DevilsAdvocateRound {
    pub phase: Phase,
    pub round_number: u32,
    pub why_direction_wrong: String,
    pub what_not_seeing: String,
    pub false_consensus_risk: String,
    pub structural_vulnerabilities: Vec<String>,
}

impl DevilsAdvocateRound {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.why_direction_wrong.is_empty() {
            errors.push("why_direction_wrong is required".to_string());
        }
        if self.what_not_seeing.is_empty() {
            errors.push("what_not_seeing is required".to_string());
        }
        if self.false_consensus_risk.is_empty() {
            errors.push("false_consensus_risk is required".to_string());
        }
        if self.structural_vulnerabilities.len() > 3 {
            errors.push("structural_vulnerabilities is limited to three items".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VCLDiagnosis {
    pub item: String,
    pub symptom_altitude: String,
    pub constraint_altitude: String,
    pub diagnosis: String,
}

impl VCLDiagnosis {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let allowed = |alt: &str| {
            let first = alt.split_whitespace().next().unwrap_or("");
            (1..=10).any(|i| first == format!("R{i}"))
        };
        if !allowed(&self.symptom_altitude) {
            errors.push("symptom_altitude must start with R1-R10".to_string());
        }
        if !allowed(&self.constraint_altitude) {
            errors.push("constraint_altitude must start with R1-R10".to_string());
        }
        if self.diagnosis.is_empty() {
            errors.push("diagnosis is required".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelParityCheck {
    pub origin: String,
    pub partner: String,
    pub delta: String,
    pub advisory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ContextCheck {
    pub memory_tools: String,      // default "UNAVAILABLE"
    pub prior_sessions_count: u32, // default 0
    pub prior_lock_versions: Vec<String>,
    pub legacy_warning: bool, // default false
    pub related_locks: Vec<String>,
    pub assessment: String, // default "SPARSE"
    pub action: String,     // default "PROCEED"
}

impl ContextCheck {
    /// The fresh-orchestrator default (no registry): SPARSE / PROCEED.
    pub fn sparse() -> Self {
        ContextCheck {
            memory_tools: "UNAVAILABLE".to_string(),
            prior_sessions_count: 0,
            prior_lock_versions: vec![],
            legacy_warning: false,
            related_locks: vec![],
            assessment: "SPARSE".to_string(),
            action: "PROCEED".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StateSnapshot {
    pub phase: Phase,
    pub round_number: u32,
    pub status: SessionStatus,
    pub payload_echo: String,
    pub foundation_score: Option<u32>,
    pub locked: Vec<String>,
    pub provisional: Vec<String>,
    pub provisional_lock: Vec<String>,
    pub flip_active: Vec<String>,
    pub blind_spots_acknowledged: Vec<(String, Vec<String>)>,
    pub structural_vulnerabilities: Vec<String>,
    pub third_party_pending: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoundRecord {
    pub decision_id: String,
    pub phase: Phase,
    pub round_number: u32,
    pub payload_id: String,
    pub origin_packet: String,
    pub partner_packet: String,
    pub payload_echo_confirmed: bool,
    pub state_snapshot: serde_json::Value,
}

/// A CHP decision case — the durable unit the gate opens, locks, and records.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionCase {
    pub decision_id: String,
    pub title: String,
    pub domain: String,
    pub created_at: String,
    pub owner: String,
    pub status: SessionStatus,
    pub high_stakes: bool,
    pub current_phase: Phase,
    pub current_round: u32,
    pub origin_system: String,
    pub origin_model: String,
    pub partner_system: String,
    pub partner_model: String,
    pub context_check: Option<ContextCheck>,
    pub model_parity: Option<ModelParityCheck>,
    pub dossier: Option<Dossier>,
    pub foundation_score: Option<u32>,
    pub locked_decisions: Vec<String>,
    pub structural_vulnerabilities: Vec<String>,
    pub blind_spots: Vec<String>,
    pub flip_criteria: Vec<String>,
    pub devil_advocate_rounds: Vec<DevilsAdvocateRound>,
    pub vcl_diagnoses: Vec<VCLDiagnosis>,
    pub state_snapshots: Vec<StateSnapshot>,
    pub third_party_log: Vec<ThirdPartyValidation>,
    pub rounds: Vec<RoundRecord>,
}

impl Default for DecisionCase {
    fn default() -> Self {
        DecisionCase {
            decision_id: String::new(),
            title: String::new(),
            domain: String::new(),
            created_at: String::new(),
            owner: String::new(),
            status: SessionStatus::Exploring,
            high_stakes: false,
            current_phase: Phase::Foundation,
            current_round: 0,
            origin_system: "Claude".to_string(),
            origin_model: "UNKNOWN".to_string(),
            partner_system: "UNKNOWN".to_string(),
            partner_model: "UNKNOWN".to_string(),
            context_check: None,
            model_parity: None,
            dossier: None,
            foundation_score: None,
            locked_decisions: vec![],
            structural_vulnerabilities: vec![],
            blind_spots: vec![],
            flip_criteria: vec![],
            devil_advocate_rounds: vec![],
            vcl_diagnoses: vec![],
            state_snapshots: vec![],
            third_party_log: vec![],
            rounds: vec![],
        }
    }
}

impl DecisionCase {
    pub fn add_round(&mut self, record: RoundRecord) {
        self.current_phase = record.phase;
        self.current_round = record.round_number;
        self.rounds.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_strings_match_reference() {
        assert_eq!(Verdict::PhaseGateFail.as_str(), "PHASE_GATE_FAIL");
        assert_eq!(SessionStatus::ProvisionalLock.as_str(), "PROVISIONAL_LOCK");
        assert_eq!(
            SessionStatus::RequiresHumanVerification.as_str(),
            "REQUIRES_HUMAN_VERIFICATION"
        );
        assert_eq!(Phase::Foundation.value(), 0);
        assert_eq!(Phase::from_value(2), Phase::Implementation);
    }

    #[test]
    fn dossier_needs_three_populated_sections() {
        let mut d = Dossier {
            core_problem: "Promote the answer".into(),
            goal_state: vec!["g".into()],
            current_state: vec!["c".into()],
            constraints: vec!["k".into()],
            ..Default::default()
        };
        assert!(d.validate().is_empty());
        d.constraints.clear();
        assert!(d.validate().iter().any(|e| e.contains("three populated")));
        d.core_problem = "UNKNOWN".into();
        assert!(d.validate().iter().any(|e| e.contains("core_problem")));
    }

    #[test]
    fn disclosure_bounds() {
        let d = FoundationDisclosure {
            weakest_assumptions: vec!["a".into()],
            invalidation_conditions: vec!["i".into(), "j".into()],
            key_vulnerability: "v".into(),
        };
        assert!(d.validate().is_empty());
        let mut d2 = d.clone();
        d2.invalidation_conditions.push("k".into());
        assert!(d2.validate().iter().any(|e| e.contains("1-2")));
    }

    #[test]
    fn vcl_altitudes() {
        let ok = VCLDiagnosis {
            item: "x".into(),
            symptom_altitude: "R2 Task".into(),
            constraint_altitude: "R4 System".into(),
            diagnosis: "d".into(),
        };
        assert!(ok.validate().is_empty());
        let bad = VCLDiagnosis {
            symptom_altitude: "R99 Task".into(),
            ..ok.clone()
        };
        assert!(bad.validate().iter().any(|e| e.contains("R1-R10")));
        let _ = bad;
    }
}
