//! R0 session gate — ported 1:1 from `chp/gates.py` (consensus-hardening-protocol 0.1.1).
//!
//! Result keys are capitalized (`Solvable`, `Scoped`, `Valid`, `Worth_it`);
//! any `FATAL` result makes the verdict `HALT`. Stored results keep the
//! Python insertion order; [`GateEvaluation::failed_checks`] returns the
//! failed names sorted (matching the reference gates' `sorted(failed)`).

use crate::models::Verdict;

/// The R0 evaluation: four capitalized checks plus the aggregate verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvaluation {
    /// `(check name, "PASS" | "FATAL")` in reference insertion order.
    pub results: Vec<(String, String)>,
    /// `PASS` iff every check passed, otherwise `HALT`.
    pub verdict: Verdict,
}

impl GateEvaluation {
    /// Failed check names, sorted (the reference gates build refusal reasons
    /// with `", ".join(sorted(failed))`).
    pub fn failed_checks(&self) -> Vec<String> {
        let mut failed: Vec<String> = self
            .results
            .iter()
            .filter(|(_, r)| r != "PASS")
            .map(|(n, _)| n.clone())
            .collect();
        failed.sort();
        failed
    }
}

/// Evaluate the R0 solvability gate.
pub fn evaluate_r0_gate(
    solvable: bool,
    scoped: bool,
    valid: bool,
    worth_it: bool,
) -> GateEvaluation {
    let results = vec![
        ("Solvable".to_string(), pass_or_fatal(solvable)),
        ("Scoped".to_string(), pass_or_fatal(scoped)),
        ("Valid".to_string(), pass_or_fatal(valid)),
        ("Worth_it".to_string(), pass_or_fatal(worth_it)),
    ];
    let verdict = if results.iter().all(|(_, r)| r == "PASS") {
        Verdict::Pass
    } else {
        Verdict::Halt
    };
    GateEvaluation { results, verdict }
}

fn pass_or_fatal(ok: bool) -> String {
    if ok {
        "PASS".to_string()
    } else {
        "FATAL".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_pass_yields_pass() {
        let e = evaluate_r0_gate(true, true, true, true);
        assert_eq!(e.verdict, Verdict::Pass);
        assert!(e.failed_checks().is_empty());
        assert_eq!(
            e.results
                .iter()
                .map(|(n, r)| (n.as_str(), r.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Solvable", "PASS"),
                ("Scoped", "PASS"),
                ("Valid", "PASS"),
                ("Worth_it", "PASS")
            ]
        );
    }

    #[test]
    fn any_fatal_yields_halt() {
        let e = evaluate_r0_gate(true, false, true, true);
        assert_eq!(e.verdict, Verdict::Halt);
        assert_eq!(e.failed_checks(), vec!["Scoped".to_string()]);
    }

    #[test]
    fn failed_checks_are_sorted_like_python() {
        // Python: sorted(["Solvable","Scoped","Valid","Worth_it"]) — capital
        // letters sort before lowercase, and "Scoped" < "Solvable".
        let e = evaluate_r0_gate(false, false, false, false);
        assert_eq!(
            e.failed_checks(),
            vec!["Scoped", "Solvable", "Valid", "Worth_it"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }
}
