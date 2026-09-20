//! Oracle disclosure gate — ported from `chp/oracle.py` (protocol 0.1.1).
//!
//! Public reference data (indices, widely-quoted prices) needs no ceremony;
//! proprietary or confidential inputs force a disclosure statement before
//! their value may drive a promotion.

use crate::models::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OracleTrustProfile {
    #[default]
    PublicReference,
    Professional,
    Confidential,
}

impl OracleTrustProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            OracleTrustProfile::PublicReference => "PUBLIC_REFERENCE",
            OracleTrustProfile::Professional => "PROFESSIONAL",
            OracleTrustProfile::Confidential => "CONFIDENTIAL",
        }
    }
    pub fn requires_disclosure(&self) -> bool {
        !matches!(self, OracleTrustProfile::PublicReference)
    }
}

/// The route name oracle-post entries carry in the ledger and in payload
/// envelopes (matches the reference `Route.ORACLE_POST` value).
pub const ORACLE_POST_ROUTE: &str = "ORACLE_POST";

/// Normalize an asset key for oracle-post decision ids
/// (`oracle-post-<round>-<ASSET>`), uppercasing separators.
pub fn asset_key(asset: &str) -> String {
    asset.trim().to_uppercase().replace(['/', ' '], "-")
}

pub fn oracle_post_decision_id(round: u32, asset: &str) -> String {
    format!("oracle-post-{round}-{}", asset_key(asset))
}

/// The disclosure gate: `PASS` when public reference data or a disclosure
/// statement is present, `REFRAME` when a protected profile tries to skip it.
pub fn evaluate_oracle_gate(profile: OracleTrustProfile, disclosure: Option<&str>) -> Verdict {
    match profile {
        OracleTrustProfile::PublicReference => Verdict::Pass,
        _ => {
            if disclosure.map(|d| !d.trim().is_empty()).unwrap_or(false) {
                Verdict::Pass
            } else {
                Verdict::Reframe
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_reference_needs_no_disclosure() {
        assert_eq!(
            evaluate_oracle_gate(OracleTrustProfile::PublicReference, None),
            Verdict::Pass
        );
        assert!(!OracleTrustProfile::PublicReference.requires_disclosure());
    }

    #[test]
    fn protected_profiles_require_disclosure() {
        assert_eq!(
            evaluate_oracle_gate(OracleTrustProfile::Professional, None),
            Verdict::Reframe
        );
        assert_eq!(
            evaluate_oracle_gate(OracleTrustProfile::Confidential, Some("  ")),
            Verdict::Reframe
        );
        assert_eq!(
            evaluate_oracle_gate(
                OracleTrustProfile::Confidential,
                Some("Bloomberg terminal snapshot 2026-09-19")
            ),
            Verdict::Pass
        );
    }

    #[test]
    fn asset_keys_normalize() {
        assert_eq!(asset_key("BTC/USD"), "BTC-USD");
        assert_eq!(
            oracle_post_decision_id(1, "btc usd"),
            "oracle-post-1-BTC-USD"
        );
        assert_eq!(ORACLE_POST_ROUTE, "ORACLE_POST");
    }
}
