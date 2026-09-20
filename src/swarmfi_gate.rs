//! SwarmFi consensus gate — the weighted-median + split-damping gate the
//! swarmfi Rust binary currently inlines, extracted so `chp-core` is the one
//! implementation (this crate is the canonical package; swarmfi switches to
//! it per the Rust port plan).
//!
//! Gate: no votes → `NO_DATA`; fewer than three independent sources →
//! `NO_DATA`; otherwise the weighted median, and when a split exists (max
//! adjacent gap over `split_threshold_pct` of the median with at least two
//! votes on each side) weights are damped toward the median and the verdict
//! notes the damping.
//!
//! Route vocabulary note: verdict strings (`NO_DATA`, `PASS`, `SPLIT_DAMPED`)
//! follow the swarmfi gate this was extracted from; the conformance harness
//! diffs them against the binary before the switch PR lands.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SwarmGateOutcome {
    pub verdict: String,
    pub weighted_median: Option<f64>,
    pub consensus_ratio: f64,
    pub reasons: Vec<String>,
}

/// One source's vote: its weight (signal reliability) and its value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vote {
    pub weight: f64,
    pub value: f64,
}

pub const MIN_SOURCES: usize = 3;

pub fn evaluate_swarm_gate(votes: &[Vote], split_threshold_pct: f64) -> SwarmGateOutcome {
    if votes.is_empty() {
        return SwarmGateOutcome {
            verdict: "NO_DATA".to_string(),
            weighted_median: None,
            consensus_ratio: 0.0,
            reasons: vec!["no rows returned".to_string()],
        };
    }
    if votes.len() < MIN_SOURCES {
        return SwarmGateOutcome {
            verdict: "NO_DATA".to_string(),
            weighted_median: None,
            consensus_ratio: 0.0,
            reasons: vec!["too few rows".to_string()],
        };
    }
    let mut sorted: Vec<Vote> = votes.to_vec();
    sorted.sort_by(|a, b| {
        a.value
            .partial_cmp(&b.value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let total_weight: f64 = sorted.iter().map(|v| v.weight).sum();
    let mut cumulative = 0.0;
    let mut median = sorted[sorted.len() - 1].value;
    for v in &sorted {
        cumulative += v.weight;
        if cumulative >= total_weight / 2.0 {
            median = v.value;
            break;
        }
    }
    let mut reasons: Vec<String> = Vec::new();
    let mut weights: Vec<f64> = sorted.iter().map(|v| v.weight).collect();
    let mut split_detected = false;

    // Split detection: largest adjacent gap vs the median.
    let mut max_gap = 0.0_f64;
    let mut gap_at = 0usize;
    for w in 1..sorted.len() {
        let gap = sorted[w].value - sorted[w - 1].value;
        if gap > max_gap {
            max_gap = gap;
            gap_at = w;
        }
    }
    let threshold = median.abs() * split_threshold_pct / 100.0;
    let lower = gap_at;
    let upper = sorted.len() - gap_at;
    if max_gap > threshold && lower >= 2 && upper >= 2 {
        split_detected = true;
        // Damp each side toward its side's size (larger side keeps more weight).
        for (i, w) in weights.iter_mut().enumerate() {
            let side_size = if i < lower { lower } else { upper };
            *w *= side_size as f64 / sorted.len() as f64 * 2.0;
        }
        reasons.push(format!(
            "split detected: max gap {max_gap} exceeds {threshold} — weights damped"
        ));
    }

    // Recompute the median on damped weights.
    if !reasons.is_empty() {
        let total: f64 = weights.iter().sum();
        let mut cumulative = 0.0;
        for (i, v) in sorted.iter().enumerate() {
            cumulative += weights[i];
            if cumulative >= total / 2.0 {
                median = v.value;
                break;
            }
        }
    }
    let within_band = sorted
        .iter()
        .filter(|v| (v.value - median).abs() <= median.abs().max(1.0) * 0.02)
        .count();
    let consensus_ratio = within_band as f64 / sorted.len() as f64;
    if reasons.is_empty() {
        reasons.push("weighted median over all sources".to_string());
    }
    SwarmGateOutcome {
        verdict: if split_detected {
            "SPLIT_DAMPED".to_string()
        } else {
            "PASS".to_string()
        },
        weighted_median: Some(median),
        consensus_ratio,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_sparse_inputs_return_no_data() {
        let empty = evaluate_swarm_gate(&[], 20.0);
        assert_eq!(empty.verdict, "NO_DATA");
        assert_eq!(empty.reasons, vec!["no rows returned"]);
        let sparse = evaluate_swarm_gate(
            &[
                Vote {
                    weight: 1.0,
                    value: 1.0,
                },
                Vote {
                    weight: 1.0,
                    value: 2.0,
                },
            ],
            20.0,
        );
        assert_eq!(sparse.verdict, "NO_DATA");
        assert_eq!(sparse.reasons, vec!["too few rows"]);
    }

    #[test]
    fn weighted_median_uses_weights_not_counts() {
        let votes = vec![
            Vote {
                weight: 9.0,
                value: 100.0,
            },
            Vote {
                weight: 1.0,
                value: 60.0,
            },
            Vote {
                weight: 1.0,
                value: 50.0,
            },
        ];
        let out = evaluate_swarm_gate(&votes, 20.0);
        assert_eq!(out.verdict, "PASS");
        assert_eq!(out.weighted_median, Some(100.0));
    }

    #[test]
    fn split_detected_and_damped() {
        let votes = vec![
            Vote {
                weight: 1.0,
                value: 100.0,
            },
            Vote {
                weight: 1.0,
                value: 101.0,
            },
            Vote {
                weight: 1.0,
                value: 200.0,
            },
            Vote {
                weight: 1.0,
                value: 201.0,
            },
        ];
        let out = evaluate_swarm_gate(&votes, 20.0);
        assert_eq!(out.verdict, "SPLIT_DAMPED");
        assert!(out.reasons[0].contains("damped"));
        assert!(out.weighted_median.unwrap() < 200.0);
    }
}
