//! Foundation stage — ported from `chp/foundation.py` (protocol 0.1.1).
//!
//! Domain floors (spec §5.3): `general`/`ai`/`agents` 70, `blockchain`/`defi`
//! 85, `finance`/`cfo`/`capital_allocation`/`board_decision` 100. Unknown
//! domains gate at the default floor (70) — never 0, never 100 — with a
//! warning when the name merely *resembles* a stricter listed domain
//! (divergence D-A1 protection).

use crate::models::{FoundationAttack, FoundationDisclosure, Verdict};

pub const DEFAULT_FOUNDATION_FLOOR: u32 = 70;

/// Domain → floor, in reference insertion order (the near-match warning scans
/// this order).
pub const FOUNDATION_FLOORS: [(&str, u32); 9] = [
    ("general", 70),
    ("ai", 70),
    ("agents", 70),
    ("blockchain", 85),
    ("defi", 85),
    ("finance", 100),
    ("cfo", 100),
    ("capital_allocation", 100),
    ("board_decision", 100),
];

/// Resolve the foundation-score floor for a domain. Case-insensitive, exact
/// match; unknown domains fall back to [`DEFAULT_FOUNDATION_FLOOR`].
pub fn foundation_floor(domain: Option<&str>) -> u32 {
    let key = domain.unwrap_or("").trim().to_lowercase();
    for (known, floor) in FOUNDATION_FLOORS {
        if key == known {
            return floor;
        }
    }
    for (known, floor) in FOUNDATION_FLOORS {
        if floor > DEFAULT_FOUNDATION_FLOOR && key.starts_with(known) {
            log::warn!(
                "domain {:?} is unlisted so it gates at the default floor {}, but it \
                 resembles {:?} which requires {} — rename it or add it to \
                 FOUNDATION_FLOORS if the stricter floor was intended",
                domain.unwrap_or(""),
                DEFAULT_FOUNDATION_FLOOR,
                known,
                floor
            );
            break;
        }
    }
    DEFAULT_FOUNDATION_FLOOR
}

/// Gate a foundation score against its domain floor: `PASS` above the floor,
/// `REFRAME` below it.
pub fn foundation_verdict(score: u32, domain: &str) -> Verdict {
    if score >= foundation_floor(Some(domain)) {
        Verdict::Pass
    } else {
        Verdict::Reframe
    }
}

/// The adversary must address each disclosed weak assumption
/// (`min(3, len(assumptions))` attacks), plus both disclosure and attack
/// self-validation.
pub fn validate_foundation_pair(
    disclosure: &FoundationDisclosure,
    attack: &FoundationAttack,
) -> Vec<String> {
    let mut errors = disclosure.validate();
    errors.extend(attack.validate());
    if !disclosure.weakest_assumptions.is_empty() && !attack.assumption_attacks.is_empty() {
        let required = 3.min(disclosure.weakest_assumptions.len());
        if attack.assumption_attacks.len() < required {
            errors.push("attack must address each disclosed weak assumption".to_string());
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_match_reference() {
        assert_eq!(foundation_floor(Some("general")), 70);
        assert_eq!(foundation_floor(Some("AI")), 70);
        assert_eq!(foundation_floor(Some(" agents ")), 70);
        assert_eq!(foundation_floor(Some("blockchain")), 85);
        assert_eq!(foundation_floor(Some("DeFi")), 85);
        assert_eq!(foundation_floor(Some("finance")), 100);
        assert_eq!(foundation_floor(Some("CFO")), 100);
        assert_eq!(foundation_floor(Some("capital_allocation")), 100);
        assert_eq!(foundation_floor(Some("board_decision")), 100);
    }

    #[test]
    fn unknown_and_empty_domains_use_default() {
        assert_eq!(foundation_floor(Some("finance_adversary")), 70);
        assert_eq!(foundation_floor(Some(" unknown ")), 70);
        assert_eq!(foundation_floor(None), 70);
    }

    #[test]
    fn verdict_gates_on_floor() {
        assert_eq!(foundation_verdict(70, "general"), Verdict::Pass);
        assert_eq!(foundation_verdict(69, "general"), Verdict::Reframe);
        assert_eq!(foundation_verdict(85, "blockchain"), Verdict::Pass);
        assert_eq!(foundation_verdict(99, "finance"), Verdict::Reframe);
        assert_eq!(foundation_verdict(100, "finance"), Verdict::Pass);
    }

    #[test]
    fn pair_validation_requires_min_three_attacks() {
        let d = FoundationDisclosure {
            weakest_assumptions: vec!["a".into(), "b".into(), "c".into()],
            invalidation_conditions: vec!["i".into()],
            key_vulnerability: "v".into(),
        };
        let mut a = FoundationAttack {
            assumption_attacks: vec!["1".into(), "2".into()],
            invalidation_exploitation: vec![],
            vulnerability_strike: "s".into(),
            foundation_score: 70,
            attack_summary: "x".into(),
        };
        let errors = validate_foundation_pair(&d, &a);
        assert!(errors.iter().any(|e| e.contains("address each disclosed")));

        a.assumption_attacks.push("3".into());
        assert!(validate_foundation_pair(&d, &a).is_empty());
    }
}
