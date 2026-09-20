//! Payload-integrity helpers — ported from `chp/payloads.py` (protocol 0.1.1).
//!
//! The envelope validates **structure only** (matching BEGIN/END brackets);
//! body tampering is caught by the ledger's own SHA-256 digest, not here.

use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadEnvelope {
    pub route: String,
    pub payload_id: String,
    pub body: String,
}

impl PayloadEnvelope {
    pub fn render(&self) -> String {
        format!(
            "BEGIN_PAYLOAD [{route}] [{payload_id}]\n{body}\nEND_PAYLOAD [{route}] [{payload_id}]",
            route = self.route,
            payload_id = self.payload_id,
            body = self.body
        )
    }
}

fn make_payload_id() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

pub fn build_payload_envelope(
    body: &str,
    route: &str,
    payload_id: Option<&str>,
) -> PayloadEnvelope {
    PayloadEnvelope {
        route: route.to_string(),
        payload_id: payload_id
            .map(str::to_string)
            .unwrap_or_else(make_payload_id),
        body: body.to_string(),
    }
}

/// Structure-only validation: at least three lines, first begins
/// `BEGIN_PAYLOAD [`, last begins `END_PAYLOAD [`, and their bracketed
/// remainders match exactly.
pub fn validate_payload_envelope(rendered: &str) -> bool {
    let lines: Vec<&str> = rendered.trim().split('\n').map(|l| l.trim_end()).collect();
    if lines.len() < 3 {
        return false;
    }
    let first = lines[0];
    let last = lines[lines.len() - 1];
    if !first.starts_with("BEGIN_PAYLOAD [") || !last.starts_with("END_PAYLOAD [") {
        return false;
    }
    first.replacen("BEGIN_PAYLOAD", "", 1).trim() == last.replacen("END_PAYLOAD", "", 1).trim()
}

pub fn payload_echo_confirmed(route: &str, payload_id: &str, echo: &str) -> bool {
    echo.trim() == format!("[{route}] [{payload_id}] CONFIRMED")
}

pub fn extract_payload_id(rendered: &str) -> Option<String> {
    let lines: Vec<&str> = rendered.trim().split('\n').collect();
    let first = *lines.first()?;
    if !first.starts_with("BEGIN_PAYLOAD [") {
        return None;
    }
    let parts: Vec<&str> = first.split('[').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(parts[2].trim_end_matches(']').trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_validate_round_trip() {
        let env = build_payload_envelope("hello\nworld", "PROMOTE", Some("ABC123"));
        let rendered = env.render();
        assert!(validate_payload_envelope(&rendered));
        assert_eq!(extract_payload_id(&rendered).as_deref(), Some("ABC123"));
    }

    #[test]
    fn generated_id_is_six_chars() {
        let env = build_payload_envelope("b", "RX", None);
        assert_eq!(env.payload_id.len(), 6);
        assert!(env
            .payload_id
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn tampered_tail_fails_structure() {
        let env = build_payload_envelope("body", "ORACLE_POST", Some("XYZ789"));
        let rendered = env.render();
        // Trailing whitespace on the frame is tolerated (rstrip semantics).
        assert!(validate_payload_envelope(&format!("{rendered} ")));
        // An id mismatch between the BEGIN and END brackets fails structure.
        let lines: Vec<String> = rendered
            .split('\n')
            .enumerate()
            .map(|(i, l)| {
                if i == 2 {
                    l.replace("XYZ789", "ZZZ789")
                } else {
                    l.to_string()
                }
            })
            .collect();
        assert!(!validate_payload_envelope(&lines.join("\n")));
    }

    #[test]
    fn too_short_fails() {
        assert!(!validate_payload_envelope("BEGIN_PAYLOAD [R] [ID]"));
    }

    #[test]
    fn echo_confirmation() {
        assert!(payload_echo_confirmed(
            "RX",
            "ABC123",
            "[RX] [ABC123] CONFIRMED\n"
        ));
        assert!(!payload_echo_confirmed(
            "RX",
            "ABC123",
            "[RX] [ABC123] CONFIRM"
        ));
    }
}
