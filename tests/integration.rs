//! End-to-end tests: drive the compiled `chp-gate` binary over its real
//! stdio protocol (newline-delimited JSON, one response per request line).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

struct Gate {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl Gate {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_chp-gate"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn chp-gate");
        let stdin = child.stdin.take().expect("stdin");
        let reader = BufReader::new(child.stdout.take().expect("stdout"));
        Gate {
            child,
            stdin,
            reader,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let line = json!({ "method": method, "params": params }).to_string();
        writeln!(self.stdin, "{line}").expect("write request");
        self.stdin.flush().expect("flush request");
        let mut response = String::new();
        self.reader.read_line(&mut response).expect("read response");
        serde_json::from_str(response.trim()).expect("valid JSON response")
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn gate_answers_r0_foundation_and_payload_requests() {
    let mut gate = Gate::spawn();

    let res = gate.request(
        "evaluate_r0_gate",
        json!({ "solvable": true, "scoped": true, "valid": true, "worth_it": true }),
    );
    assert_eq!(res["verdict"], "PASS");

    let res = gate.request(
        "evaluate_r0_gate",
        json!({ "solvable": true, "scoped": false, "valid": true, "worth_it": true }),
    );
    assert_eq!(res["verdict"], "HALT");

    let res = gate.request("foundation_floor", json!({ "domain": "defi" }));
    assert_eq!(res["floor"], 85);

    let res = gate.request(
        "foundation_verdict",
        json!({ "score": 85, "domain": "defi" }),
    );
    assert_eq!(res["verdict"], "PASS");

    let res = gate.request(
        "payload_build",
        json!({ "body": "{\"a\":1}", "route": "ORACLE_POST", "payload_id": "ABC123" }),
    );
    let rendered = res["rendered"].as_str().unwrap().to_string();
    assert!(rendered.starts_with("BEGIN_PAYLOAD"));
    let res = gate.request("payload_validate", json!({ "rendered": rendered }));
    assert_eq!(res["valid"], true);
}

#[test]
fn gate_ledger_lifecycle_over_stdio() {
    let mut gate = Gate::spawn();
    let dir = std::env::temp_dir().join(format!("chp-gate-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("d.jsonl");
    let path = path.to_str().unwrap();

    let res = gate.request(
        "ledger_create",
        json!({ "path": path, "decision_id": "demo-1", "phase": 0, "round": 0, "body": { "title": "demo" } }),
    );
    assert!(res["entry"]["entry_hash"].as_str().is_some());

    let res = gate.request(
        "ledger_append",
        json!({ "path": path, "entry_type": "context_append", "decision_id": "demo-1", "phase": 1, "round": 1, "body": { "a": 1 } }),
    );
    assert!(res["entry"]["entry_hash"].as_str().is_some());

    // Creating over the existing file is rejected, never silent.
    let res = gate.request(
        "ledger_create",
        json!({ "path": path, "decision_id": "demo-2", "phase": 0, "round": 0, "body": {} }),
    );
    assert!(res["error"].as_str().unwrap().contains("already exists"));

    let res = gate.request("ledger_verify", json!({ "path": path }));
    assert_eq!(res["broken"], json!([]));

    let res = gate.request("ledger_repair", json!({ "path": path, "broken": [] }));
    assert_eq!(res["remaining"], json!([]));

    let contents = std::fs::read_to_string(path).unwrap();
    assert_eq!(contents.lines().count(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gate_survives_garbage_and_unknown_methods() {
    let mut gate = Gate::spawn();

    let res = gate.request("no_such_method", json!({}));
    assert!(res["error"].as_str().unwrap().contains("unknown method"));

    // A malformed line yields an error response, then the stream continues.
    writeln!(self_stdin_reset(&mut gate), "not json").unwrap();
    let mut response = String::new();
    gate.reader.read_line(&mut response).unwrap();
    let res: Value = serde_json::from_str(response.trim()).unwrap();
    assert!(res["error"]
        .as_str()
        .unwrap()
        .starts_with("bad request line"));

    // Still alive afterwards.
    let res = gate.request("foundation_floor", json!({ "domain": "general" }));
    assert_eq!(res["floor"], 70);
}

// Helper keeps the garbage-line test readable: writeln! needs the stdin handle
// mutably while `gate.request` also borrows it.
fn self_stdin_reset(gate: &mut Gate) -> &mut ChildStdin {
    &mut gate.stdin
}
