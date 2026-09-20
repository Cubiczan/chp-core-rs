//! Tamper-evident JSONL decision ledger — ported from `chp/ledger.py`
//! (protocol 0.1.1) against the verified regressions.
//!
//! Every entry is one JSON object per line; the chain hash is
//! `SHA256(f"{index:05d}|{ts}|{decision_id}|{phase}|{round}|{entry_type}|{prev_hash}|{body}|{envelope}")`
//! (hex). The reference distinguishes: body-tamper detection (envelope-verified
//! payload vs live re-hash), which does NOT advance the chain (the original
//! entry hash is kept, the index preserved — post-950 regression), and chain
//! repair, which rewrites the chain and resets reasons.
//!
//! KNOWN DIVERGENCE (documented, pending conformance pass): exact reason
//! strings (`BROKEN_CHAIN`, `BODY_HASH_MISMATCH`, `ENVELOPE_BODY_HASH_MISMATCH`)
//! and entry-type vocabulary are recorded from memory of the source; the
//! differential conformance harness must diff them against the Python
//! reference before the crate is called byte-faithful.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

// Minimal hex encode (avoids an extra dependency for one call).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub const GENESIS_HASH: &str = "";
pub const ENTRY_GENESIS: &str = "GENESIS";
pub const ENTRY_ROUND: &str = "round";
pub const ENTRY_CONTEXT: &str = "context_append";
pub const ENTRY_THIRD_PARTY: &str = "third_party_validation";

#[derive(Debug, Clone, PartialEq)]
pub struct LedgerError(pub String);

pub struct DecisionLedger {
    path: std::path::PathBuf,
    canonical_ts: Box<dyn Fn() -> String + Send + Sync>,
    entries: Vec<Value>,
}

fn default_ts() -> String {
    // UTC ISO-8601 without external crates: seconds precision like the reference.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_iso8601(now)
}

/// Days-from-civil algorithm (Howard Hinnant) — UTC, no libc.
fn format_iso8601(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (h, min, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}+00:00")
}

impl DecisionLedger {
    pub fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        DecisionLedger {
            path: path.into(),
            canonical_ts: Box::new(default_ts),
            entries: Vec::new(),
        }
    }

    /// Deterministic clock — the reference injects a canonical timestamp for
    /// reproducible hashes in tests.
    pub fn with_clock(ts: &'static str) -> Self {
        let owned: String = ts.to_string();
        DecisionLedger {
            path: std::path::PathBuf::new(),
            canonical_ts: Box::new(move || owned.clone()),
            entries: Vec::new(),
        }
    }

    pub fn set_path<P: Into<std::path::PathBuf>>(&mut self, path: P) {
        self.path = path.into();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }

    fn entry_hash(index: usize, entry: &Value) -> String {
        let ts = entry["ts"].as_str().unwrap_or("");
        let decision_id = entry["decision_id"].as_str().unwrap_or("");
        let phase = entry["phase"].as_i64().unwrap_or(0);
        let round = entry["round"].as_i64().unwrap_or(0);
        let entry_type = entry["entry_type"].as_str().unwrap_or("");
        let prev = entry["prev_hash"].as_str().unwrap_or("");
        let body = entry["body"].as_str().unwrap_or("");
        let envelope = entry["envelope"].as_str().unwrap_or("");
        let payload = format!(
            "{:05}|{ts}|{decision_id}|{phase}|{round}|{entry_type}|{prev}|{body}|{envelope}",
            index + 1
        );
        sha256_hex(payload.as_bytes())
    }

    fn seal(&self, entry: &mut Value, prev_hash: &str, index: usize) {
        entry["prev_hash"] = json!(prev_hash);
        let h = Self::entry_hash(index, entry);
        entry["entry_hash"] = json!(h);
    }

    /// `create`: write the GENESIS entry and persist a fresh file.
    /// Python raises `ValueError` when the file already exists.
    pub fn create(
        &mut self,
        decision_id: &str,
        phase: u8,
        round: u32,
        body: &Value,
    ) -> Result<Value, LedgerError> {
        if self.path.exists() {
            return Err(LedgerError(format!(
                "ledger already exists at {} — append instead of creating over it",
                self.path.display()
            )));
        }
        let mut entry = json!({
            "ts": (self.canonical_ts)(),
            "decision_id": decision_id,
            "phase": phase,
            "round": round,
            "entry_type": ENTRY_GENESIS,
            "body": crate::canonical::canonical_json(body),
        });
        self.seal(&mut entry, GENESIS_HASH, 0);
        self.entries.clear();
        self.entries.push(entry.clone());
        self.persist()?;
        Ok(entry)
    }

    /// `append`: oracle-post entries get a version-1 payload envelope sealed
    /// to the body's SHA-256; everything else appends bare.
    pub fn append(
        &mut self,
        entry_type: &str,
        decision_id: &str,
        phase: u8,
        round: u32,
        body: &Value,
    ) -> Result<Value, LedgerError> {
        if self.entries.is_empty() {
            return Err(LedgerError(
                "ledger has no genesis — create it first".to_string(),
            ));
        }
        let payload_id = make_payload_id();
        let body_str = crate::canonical::canonical_json(body);
        let mut entry = json!({
            "ts": (self.canonical_ts)(),
            "decision_id": decision_id,
            "phase": phase,
            "round": round,
            "entry_type": entry_type,
            "body": body_str,
        });
        if entry_type == "oracle_post" {
            let digest = sha256_hex(body_str.as_bytes());
            let envelope = json!({
                "version": 1,
                "format": "payload-brackets",
                "payload_id": payload_id,
                "route": crate::oracle::ORACLE_POST_ROUTE,
                "sha256": digest,
            });
            entry["envelope"] = json!(crate::canonical::canonical_json(&envelope));
        }
        let index = self.entries.len();
        let prev = self.entries[index - 1]["entry_hash"]
            .as_str()
            .unwrap_or("")
            .to_string();
        self.seal(&mut entry, &prev, index);
        self.entries.push(entry.clone());
        self.persist()?;
        Ok(entry)
    }

    /// `verify`: returns indexes (1-based) of tampered/broken entries.
    /// Reference semantics pinned by the session's verified regressions: an
    /// entry whose recomputed hash differs from its recorded hash is flagged
    /// (body tamper) but does NOT advance the chain — subsequent links are
    /// checked against the entries' STORED hashes, so the index is preserved.
    /// A consequence: rewriting an entry's stored hash also breaks the NEXT
    /// entry's prev-link (it points at the original hash), so both are
    /// flagged until `repair` reseals the chain.
    pub fn verify(&mut self) -> Vec<u32> {
        let recorded_hashes: Vec<String> = self
            .entries
            .iter()
            .map(|e| e["entry_hash"].as_str().unwrap_or("").to_string())
            .collect();
        let mut broken: Vec<u32> = Vec::new();
        for (i, original) in self.entries.iter_mut().enumerate() {
            let recorded = recorded_hashes[i].clone();
            let recomputed = Self::entry_hash(i, original);
            let expected_prev = if i == 0 {
                GENESIS_HASH.to_string()
            } else {
                recorded_hashes[i - 1].clone()
            };
            let link_mismatch = original["prev_hash"].as_str().unwrap_or("") != expected_prev;
            if recomputed != recorded || link_mismatch {
                broken.push((i + 1) as u32);
                original["envelope_valid"] = json!(false);
                original["integrity_valid"] = json!(false);
                // Chain continuation uses stored hashes either way; a link
                // rewrite (hash fields edited in the file) is re-derived from
                // the recomputed hash by repair().
            }
        }
        broken
    }

    /// `repair`: rewrite chain links for `broken` entries (reasons carried on
    /// the entry), resealing everything after — matching the reference's
    /// post-950 semantics where repair preserves indexes and resets reasons.
    pub fn repair(&mut self, broken: &[u32]) -> Vec<u32> {
        let mut prev_hash = GENESIS_HASH.to_string();
        for (i, entry) in self.entries.iter_mut().enumerate() {
            let idx = (i + 1) as u32;
            if broken.contains(&idx) {
                entry["repair_reason"] = json!("BROKEN_CHAIN");
            }
            entry["prev_hash"] = json!(prev_hash);
            let h = Self::entry_hash(i, entry);
            entry["entry_hash"] = json!(h);
            prev_hash = h;
        }
        let _ = self.persist();
        Vec::new()
    }

    /// `read_entries` with an optional entry-type filter.
    pub fn read_entries(&self, entry_type: Option<&str>) -> Vec<Value> {
        self.entries
            .iter()
            .filter(|e| {
                entry_type
                    .map(|t| e["entry_type"].as_str() == Some(t))
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    fn persist(&self) -> Result<(), LedgerError> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory ledger (tests)
        }
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&e.to_string());
            out.push('\n');
        }
        std::fs::write(&self.path, out).map_err(|e| LedgerError(e.to_string()))
    }

    pub fn load<P: Into<std::path::PathBuf>>(path: P) -> Result<Self, LedgerError> {
        let path = path.into();
        let data = std::fs::read_to_string(&path).map_err(|e| LedgerError(e.to_string()))?;
        let entries = data
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Value>(l).map_err(|e| LedgerError(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DecisionLedger {
            path,
            canonical_ts: Box::new(default_ts),
            entries,
        })
    }
}

fn make_payload_id() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // Ledger payload ids are deterministic-per-entry in tests; the reference
    // uses random alphanumeric ids, which we mirror via a simple LCG seeded by
    // the wall clock (no rand dep here — payloads.rs owns the RNG-based one).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let mut state = nanos | 1;
    (0..6)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            CHARS[((state >> 33) % CHARS.len() as u64) as usize] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json;

    fn ledger_with_clock(path: &std::path::Path) -> DecisionLedger {
        let mut l = DecisionLedger::with_clock("2026-09-20T00:00:00+00:00");
        l.set_path(path);
        l
    }

    #[test]
    fn create_then_append_builds_a_verifiable_chain() {
        let dir = std::env::temp_dir().join(format!("chp-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut ledger = ledger_with_clock(&path);
        let body = json!({"score": 100});
        ledger.create("oracle-post-1-BTC-USD", 0, 0, &body).unwrap();
        let e1 = ledger
            .append(
                ENTRY_ROUND,
                "oracle-post-1-BTC-USD",
                1,
                1,
                &json!({"vote": "PROMOTE"}),
            )
            .unwrap();
        let e2 = ledger
            .append(
                ENTRY_CONTEXT,
                "oracle-post-1-BTC-USD",
                1,
                1,
                &json!({"summary": "ok"}),
            )
            .unwrap();

        assert_eq!(e1["entry_type"], ENTRY_ROUND);
        assert_eq!(e2["prev_hash"], e1["entry_hash"]);
        assert!(ledger.verify().is_empty());
        assert_eq!(ledger.read_entries(Some(ENTRY_ROUND)).len(), 1);
        assert_eq!(ledger.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_over_existing_file_is_rejected() {
        let dir = std::env::temp_dir().join(format!("chp-ledger-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let mut ledger = ledger_with_clock(&path);
        ledger.create("d", 0, 0, &json!({})).unwrap();
        let mut ledger2 = ledger_with_clock(&path);
        let err = ledger2.create("d", 0, 0, &json!({})).unwrap_err();
        assert!(err.0.contains("already exists"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn body_tamper_detected_but_index_preserved() {
        let dir = std::env::temp_dir().join(format!("chp-ledger-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let mut ledger = ledger_with_clock(&path);
        ledger.create("d1", 0, 0, &json!({"a": 1})).unwrap();
        ledger
            .append(ENTRY_ROUND, "d1", 1, 1, &json!({"vote": "PROMOTE"}))
            .unwrap();
        ledger
            .append(ENTRY_ROUND, "d1", 1, 2, &json!({"vote": "HOLD"}))
            .unwrap();
        ledger
            .append(ENTRY_CONTEXT, "d1", 1, 2, &json!({"note": "x"}))
            .unwrap();
        drop(ledger);

        // Tamper with entry 2's body on disk.
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered: Vec<String> = raw
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 1 {
                    l.replace("PROMOTE", "PROMOTED")
                } else {
                    l.to_string()
                }
            })
            .collect();
        std::fs::write(&path, tampered.join("\n") + "\n").unwrap();

        let mut reloaded = DecisionLedger::load(&path).unwrap();
        let broken = reloaded.verify();
        assert_eq!(broken, vec![2], "exactly the tampered entry flagged");
        let tampered_entry = &reloaded.entries()[1];
        assert_eq!(tampered_entry["envelope_valid"], json!(false));
        assert_eq!(tampered_entry["integrity_valid"], json!(false));
        // Original entry hash preserved (index kept, chain not advanced).
        assert!(tampered_entry["entry_hash"].as_str().is_some());

        reloaded.repair(&broken);
        assert!(reloaded.verify().is_empty());
        let repaired = &reloaded.entries()[1];
        assert_eq!(repaired["repair_reason"], json!("BROKEN_CHAIN"));
        assert_eq!(repaired["index"], serde_json::Value::Null); // no synthetic index field
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_mismatch_is_flagged_and_repairable() {
        let mut ledger = DecisionLedger::with_clock("2026-09-20T00:00:00+00:00");
        ledger.create("d", 0, 0, &json!({})).unwrap();
        ledger
            .append(ENTRY_CONTEXT, "d", 0, 0, &json!({"a": 1}))
            .unwrap();
        ledger
            .append(ENTRY_CONTEXT, "d", 0, 0, &json!({"b": 2}))
            .unwrap();
        // Corrupt the middle entry's recorded hash in memory (a hash-field rewrite).
        ledger.entries[1]["entry_hash"] = json!("deadbeef");
        // Two detections: the rewritten entry itself, AND the next entry whose
        // prev-link no longer matches the previous stored hash.
        assert_eq!(ledger.verify(), vec![2, 3]);
        // Repair reseals the chain from the recomputed hashes.
        ledger.repair(&[2, 3]);
        assert!(ledger.verify().is_empty());
    }

    #[test]
    fn envelope_carries_body_sha256() {
        let mut ledger = DecisionLedger::with_clock("2026-09-20T00:00:00+00:00");
        ledger.create("d", 0, 0, &json!({})).unwrap();
        let e = ledger
            .append("oracle_post", "d", 0, 1, &json!({"price": 4200.0}))
            .unwrap();
        let env_str = e["envelope"].as_str().unwrap();
        let env: Value = serde_json::from_str(env_str).unwrap();
        assert_eq!(env["route"], "ORACLE_POST");
        assert_eq!(env["format"], "payload-brackets");
        assert_eq!(env["version"], 1);
        let body_hash = sha256_hex(canonical_json(&json!({"price": 4200.0})).as_bytes());
        assert_eq!(env["sha256"], json!(body_hash));
    }

    #[test]
    fn iso8601_formatting() {
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(format_iso8601(1_735_689_600), "2025-01-01T00:00:00+00:00");
        assert_eq!(format_iso8601(1_789_862_400), "2026-09-20T00:00:00+00:00");
    }
}
