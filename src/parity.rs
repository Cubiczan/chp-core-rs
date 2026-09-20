//! Cross-model parity and session contracts — ported from `chp/parity.py` and
//! `chp/contract.py` (protocol 0.1.1).
//!
//! Two independent models must independently agree on a promotion before the
//! gate accepts it. Parity is computed as an absolute delta over a shared
//! scalar (score, price, count) with a configured tolerance.

use crate::models::ModelParityCheck;

#[derive(Debug, Clone, PartialEq)]
pub struct OriginContract {
    pub system: String,
    pub model: String,
    pub contract_version: String,
    pub decision_id: String,
    pub round: u32,
}

impl OriginContract {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.system.trim().is_empty() {
            errors.push("system is required".to_string());
        }
        if self.model.trim().is_empty() {
            errors.push("model is required".to_string());
        }
        if self.contract_version.trim().is_empty() {
            errors.push("contract_version is required".to_string());
        }
        if self.decision_id.trim().is_empty() {
            errors.push("decision_id is required".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PartnerContract {
    pub system: String,
    pub model: String,
    pub contract_version: String,
    pub decision_id: String,
    pub round: u32,
    pub countersign: Option<String>,
}

impl PartnerContract {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.system.trim().is_empty() {
            errors.push("system is required".to_string());
        }
        if self.model.trim().is_empty() {
            errors.push("model is required".to_string());
        }
        if self.contract_version.trim().is_empty() {
            errors.push("contract_version is required".to_string());
        }
        if self.decision_id.trim().is_empty() {
            errors.push("decision_id is required".to_string());
        }
        if self.countersign.is_none() {
            errors.push("countersign is required for a partner countersignature".to_string());
        }
        errors
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParityResult {
    pub delta: f64,
    pub within_tolerance: bool,
    pub advisory: Option<String>,
}

/// Compare the two models' scalars. `advisory` carries a non-blocking note
/// when the pair matches exactly (both models returning the identical number
/// is itself worth recording) or when the delta breaches tolerance.
pub fn compare_parity(
    origin_contract: &OriginContract,
    partner_contract: &PartnerContract,
    origin_value: f64,
    partner_value: f64,
    tolerance: f64,
) -> Result<ParityResult, Vec<String>> {
    let mut contract_errors = origin_contract.validate();
    contract_errors.extend(partner_contract.validate());
    if !contract_errors.is_empty() {
        return Err(contract_errors);
    }
    let delta = (origin_value - partner_value).abs();
    let within_tolerance = delta <= tolerance;
    let advisory = if within_tolerance && delta == 0.0 {
        Some("identical values from independent models — verify they are not derived from the same source".to_string())
    } else if !within_tolerance {
        Some(format!(
            "parity delta {delta} exceeds tolerance {tolerance} — origin and partner disagree"
        ))
    } else {
        None
    };
    Ok(ParityResult {
        delta,
        within_tolerance,
        advisory,
    })
}

/// Materialize the parity check onto a case's model-pair record.
pub fn build_parity_check(
    origin_contract: &OriginContract,
    partner_contract: &PartnerContract,
    result: &ParityResult,
) -> ModelParityCheck {
    ModelParityCheck {
        origin: format!("{}/{}", origin_contract.system, origin_contract.model),
        partner: format!("{}/{}", partner_contract.system, partner_contract.model),
        delta: format!("{:.6}", result.delta),
        advisory: result.advisory.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contracts() -> (OriginContract, PartnerContract) {
        (
            OriginContract {
                system: "Claude".into(),
                model: "opus-4.1".into(),
                contract_version: "1.0.0".into(),
                decision_id: "oracle-post-1-BTC-USD".into(),
                round: 1,
            },
            PartnerContract {
                system: "GPT".into(),
                model: "gpt-5".into(),
                contract_version: "1.0.0".into(),
                decision_id: "oracle-post-1-BTC-USD".into(),
                round: 1,
                countersign: Some("sig".into()),
            },
        )
    }

    #[test]
    fn parity_within_tolerance_passes() {
        let (o, p) = contracts();
        let r = compare_parity(&o, &p, 70.0, 71.0, 2.0).unwrap();
        assert!(r.within_tolerance);
        assert_eq!(r.delta, 1.0);
        assert!(r.advisory.is_none());
        let check = build_parity_check(&o, &p, &r);
        assert_eq!(check.origin, "Claude/opus-4.1");
        assert_eq!(check.partner, "GPT/gpt-5");
    }

    #[test]
    fn parity_beyond_tolerance_carries_advisory() {
        let (o, p) = contracts();
        let r = compare_parity(&o, &p, 70.0, 95.0, 2.0).unwrap();
        assert!(!r.within_tolerance);
        assert!(r.advisory.is_some());
    }

    #[test]
    fn identical_values_flag_shared_source() {
        let (o, p) = contracts();
        let r = compare_parity(&o, &p, 70.0, 70.0, 2.0).unwrap();
        assert!(r.advisory.as_deref().unwrap().contains("same source"));
    }

    #[test]
    fn missing_countsign_is_a_contract_error() {
        let (o, mut p) = contracts();
        p.countersign = None;
        let err = compare_parity(&o, &p, 1.0, 1.0, 1.0).unwrap_err();
        assert!(err.iter().any(|e| e.contains("countersign")));
        let _ = o;
    }
}
