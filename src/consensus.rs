//! Consensus replay — read a JSONL ledger back and grade each decision's
//! dual-model agreement (ported from the reference `consensus.py` replay).
//!
//! A decision is `unanimous` when every round recorded a vote and they all
//! agree; `disputed` when votes disagree; `insufficient` when any round is
//! missing a vote or an unconfirmed payload echo.

use crate::ledger::DecisionLedger;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConsensusSummary {
    pub decisions: usize,
    pub unanimous: Vec<String>,
    pub disputed: Vec<String>,
    pub insufficient: Vec<String>,
}

/// Replay a ledger file and grade consensus per decision id.
pub fn replay(path: &std::path::Path) -> Result<ConsensusSummary, crate::ledger::LedgerError> {
    let ledger = DecisionLedger::load(path)?;
    let mut by_decision: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for entry in ledger.read_entries(Some("round")) {
        let id = entry["decision_id"].as_str().unwrap_or("").to_string();
        if id.is_empty() {
            continue;
        }
        by_decision.entry(id).or_default().push(entry);
    }
    let mut summary = ConsensusSummary {
        decisions: by_decision.len(),
        unanimous: vec![],
        disputed: vec![],
        insufficient: vec![],
    };
    for (id, rounds) in by_decision {
        let mut votes: Vec<Option<String>> = Vec::new();
        let mut confirmed_all = true;
        for round in &rounds {
            let body: Value = serde_json::from_str(round["body"].as_str().unwrap_or("{}"))
                .unwrap_or(serde_json::json!({}));
            votes.push(body["vote"].as_str().map(str::to_string));
            if body["payload_echo_confirmed"] == serde_json::json!(false) {
                confirmed_all = false;
            }
        }
        let all_voted = votes.iter().all(|v| v.is_some());
        if !all_voted || !confirmed_all {
            summary.insufficient.push(id);
        } else {
            let mut distinct: Vec<&String> = votes.iter().flatten().collect();
            distinct.sort();
            distinct.dedup();
            if distinct.len() <= 1 {
                summary.unanimous.push(id);
            } else {
                summary.disputed.push(id);
            }
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ENTRY_ROUND;

    fn write_round(ledger: &mut DecisionLedger, decision: &str, vote: Option<&str>, echo: bool) {
        let body = serde_json::json!({
            "decision_id": decision,
            "vote": vote,
            "payload_echo_confirmed": echo,
        });
        ledger.append(ENTRY_ROUND, decision, 1, 1, &body).unwrap();
    }

    #[test]
    fn unanimous_disputed_and_insufficient() {
        let dir = std::env::temp_dir().join(format!("chp-consensus-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut ledger = crate::ledger::DecisionLedger::with_clock("t");
        ledger.set_path(&path);
        ledger.create("seed", 0, 0, &serde_json::json!({})).unwrap();
        write_round(&mut ledger, "alpha", Some("PROMOTE"), true);
        write_round(&mut ledger, "alpha", Some("PROMOTE"), true);
        write_round(&mut ledger, "beta", Some("PROMOTE"), true);
        write_round(&mut ledger, "beta", Some("HOLD"), true);
        write_round(&mut ledger, "gamma", None, true);
        write_round(&mut ledger, "delta", Some("PROMOTE"), false);

        // append() persists each entry, so load() reconstructs the same set.
        let summary = replay(&path).unwrap();
        assert!(summary.unanimous.contains(&"alpha".to_string()));
        assert!(summary.disputed.contains(&"beta".to_string()));
        assert!(summary.insufficient.contains(&"gamma".to_string()));
        assert!(summary.insufficient.contains(&"delta".to_string()));
        assert_eq!(summary.decisions, 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
