//! JSON-over-stdio bridge — the Profile A, language-neutral surface.
//!
//! One JSON request per line on stdin, one JSON response per line on stdout.
//! This is the surface the conformance harness drives and the one downstream
//! consumers (swarmfi, compliance-as-code-agent) call instead of the Python
//! subprocess bridge. Method vocabulary is snake_case and stable; responses
//! are compact single lines (no pretty-printing).

use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn handle(method: &str, params: &Value) -> Value {
    match method {
        "evaluate_r0_gate" => {
            let b = |k: &str| params[k].as_bool().unwrap_or(false);
            let gate = crate::gates::evaluate_r0_gate(
                b("solvable"),
                b("scoped"),
                b("valid"),
                b("worth_it"),
            );
            json!({
                "results": gate.results.iter()
                    .map(|(k, v)| json!([k, v.as_str()]))
                    .collect::<Vec<_>>(),
                "verdict": gate.verdict.as_str(),
            })
        }
        "foundation_floor" => {
            json!({ "floor": crate::foundation::foundation_floor(params["domain"].as_str()) })
        }
        "foundation_verdict" => {
            let score = params["score"].as_f64().unwrap_or(0.0) as u32;
            let domain = params["domain"].as_str().unwrap_or("");
            json!({
                "verdict": crate::foundation::foundation_verdict(score, domain).as_str(),
                "floor": crate::foundation::foundation_floor(params["domain"].as_str()),
            })
        }
        "evaluate_devils_advocate" => {
            let vulns: Vec<String> = params["structural_vulnerabilities"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let errors = crate::devil::validate_devil_round(
                params["why_direction_wrong"].as_str().unwrap_or(""),
                params["what_not_seeing"].as_str().unwrap_or(""),
                params["false_consensus_risk"].as_str().unwrap_or(""),
                &vulns,
            );
            json!({
                "errors": errors,
                "verdict": crate::devil::devils_advocate_verdict(&errors).as_str(),
            })
        }
        "payload_build" => {
            let body = params["body"].as_str().unwrap_or("");
            let route = params["route"].as_str().unwrap_or("ORACLE_POST");
            let payload_id = params["payload_id"].as_str();
            let envelope = crate::payloads::build_payload_envelope(body, route, payload_id);
            json!({ "rendered": envelope.render() })
        }
        "payload_validate" => {
            json!({
                "valid": crate::payloads::validate_payload_envelope(params["rendered"].as_str().unwrap_or(""))
            })
        }
        "ledger_create" | "ledger_append" => {
            let result = if method == "ledger_create" {
                // Create starts a FRESH ledger at the path; create() itself
                // rejects overwriting an existing file.
                let mut l = DecisionLedgerForBridge::new(params["path"].as_str().unwrap_or(""));
                let body = params.get("body").cloned().unwrap_or(json!({}));
                l.create(
                    params["decision_id"].as_str().unwrap_or(""),
                    params["phase"].as_u64().unwrap_or(0) as u8,
                    params["round"].as_u64().unwrap_or(0) as u32,
                    &body,
                )
                .map(|entry| json!({ "entry": entry }))
            } else {
                with_ledger(params, |l, p| {
                    let body = p.get("body").cloned().unwrap_or(json!({}));
                    l.append(
                        p["entry_type"].as_str().unwrap_or("context_append"),
                        p["decision_id"].as_str().unwrap_or(""),
                        p["phase"].as_u64().unwrap_or(0) as u8,
                        p["round"].as_u64().unwrap_or(0) as u32,
                        &body,
                    )
                    .map(|entry| json!({ "entry": entry }))
                })
            };
            match result {
                Ok(v) => v,
                Err(e) => json!({ "error": e.0 }),
            }
        }
        "ledger_verify" => {
            match DecisionLedgerForBridge::load(params["path"].as_str().unwrap_or("")) {
                Ok(mut l) => json!({ "broken": l.verify() }),
                Err(e) => json!({ "error": e.0 }),
            }
        }
        "ledger_repair" => {
            match DecisionLedgerForBridge::load(params["path"].as_str().unwrap_or("")) {
                Ok(mut l) => {
                    let broken: Vec<u32> = params["broken"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u32))
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({ "remaining": l.repair(&broken) })
                }
                Err(e) => json!({ "error": e.0 }),
            }
        }
        other => json!({ "error": format!("unknown method: {other}") }),
    }
}

// The ledger module lives at crate::ledger; alias keeps the match arms terse.
use crate::ledger::DecisionLedger as DecisionLedgerForBridge;

fn with_ledger<F>(params: &Value, f: F) -> Result<Value, crate::ledger::LedgerError>
where
    F: FnOnce(&mut DecisionLedgerForBridge, &Value) -> Result<Value, crate::ledger::LedgerError>,
{
    let mut ledger = DecisionLedgerForBridge::load(params["path"].as_str().unwrap_or(""))?;
    f(&mut ledger, params)
}

/// Serve one request per stdin line until EOF.
pub fn serve() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let method = req["method"].as_str().unwrap_or("").to_string();
                let params = req.get("params").cloned().unwrap_or(json!({}));
                handle(&method, &params)
            }
            Err(e) => json!({ "error": format!("bad request line: {e}") }),
        };
        let _ = writeln!(out, "{response}");
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r0_bridge_roundtrip() {
        let req = json!({
            "method": "evaluate_r0_gate",
            "params": { "solvable": true, "scoped": false, "valid": true, "worth_it": true }
        });
        let res = handle(req["method"].as_str().unwrap(), &req["params"]);
        assert_eq!(res["verdict"], "HALT");
        let results = res["results"].as_array().unwrap();
        // Declaration order is preserved; the Scoped row is the failing one.
        assert_eq!(results[0][0].as_str().unwrap(), "Solvable");
        assert_eq!(results[0][1], "PASS");
        let scoped = results.iter().find(|r| r[0] == "Scoped").unwrap();
        assert_eq!(scoped[1], "FATAL");
    }

    #[test]
    fn floor_and_verdict_bridge() {
        let res = handle("foundation_floor", &json!({ "domain": "finance" }));
        assert_eq!(res["floor"], 100);
        let res = handle(
            "foundation_verdict",
            &json!({ "score": 85, "domain": "defi" }),
        );
        assert_eq!(res["verdict"], "PASS");
        let res = handle(
            "foundation_verdict",
            &json!({ "score": 84, "domain": "defi" }),
        );
        assert_eq!(res["verdict"], "REFRAME");
    }

    #[test]
    fn devil_bridge_rejects_empty() {
        let res = handle(
            "evaluate_devils_advocate",
            &json!({
                "why_direction_wrong": "", "what_not_seeing": "x", "false_consensus_risk": "y",
                "structural_vulnerabilities": []
            }),
        );
        assert_eq!(res["verdict"], "REFRAME");
        assert_eq!(res["errors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn payload_bridge_builds_and_validates() {
        let res = handle(
            "payload_build",
            &json!({ "body": "{\"a\":1}", "route": "ORACLE_POST", "payload_id": "ABC123" }),
        );
        let rendered = res["rendered"].as_str().unwrap().to_string();
        assert!(rendered.starts_with("BEGIN_PAYLOAD"));
        let res = handle("payload_validate", &json!({ "rendered": rendered }));
        assert_eq!(res["valid"], true);
        let res = handle(
            "payload_validate",
            &json!({ "rendered": "{\"no\":\"markers\"}" }),
        );
        assert_eq!(res["valid"], false);
    }

    #[test]
    fn unknown_method_is_an_error_not_a_panic() {
        let res = handle("no_such_method", &json!({}));
        assert!(res["error"].as_str().unwrap().contains("unknown method"));
    }
}
