//! Canonical JSON — byte-compatible with the reference gates' ledger bodies:
//! `json.dumps(obj, sort_keys=True, ensure_ascii=False)` (Python default
//! separators `", "` / `": "`, keys sorted by code point, non-ASCII kept
//! literal UTF-8).
//!
//! Divergences (documented): NaN/Infinity cannot appear (serde_json forbids
//! them); extreme-magnitude floats (|x| >= 1e16 or < 1e-4) format in Python
//! e-notation, with shortest-round-trip mantissas — value domains outside
//! prices/scores/deltas are untested against CPython byte-for-byte.

use serde_json::Value;

pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_number(n)),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort(); // String Ord = code point order, matching Python sort
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_string(out, key);
                out.push_str(": ");
                write_value(out, &map[*key]);
            }
            out.push('}');
        }
    }
}

fn format_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    format_float(f)
}

/// Python `repr(float)` for the common domains, e-notation outside.
pub fn format_float(f: f64) -> String {
    if f.is_nan() || f.is_infinite() {
        // serde_json cannot store these; fall back to Python's output tokens.
        return if f.is_nan() {
            "NaN".to_string()
        } else if f > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let abs = f.abs();
    if abs >= 1e16 || abs < 1e-4 {
        // Python switches to e-notation here: shortest mantissa + e±NN.
        let s = format!("{:e}", f); // Rust: "1e20", "1.25e-7"
        if let Some((mantissa, exp)) = s.split_once('e') {
            let exp_val: i32 = exp.parse().unwrap_or(0);
            return format!("{m}e{exp:+03}", m = mantissa, exp = exp_val);
        }
        return s;
    }
    if f.fract() == 0.0 {
        // Python always shows a decimal point on integral floats.
        return format!("{:.1}", f);
    }
    format!("{}", f) // Rust {} for f64 = shortest round-trip, matching repr
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c), // ensure_ascii=False: non-ASCII stays literal
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python_json_dumps_sort_keys() {
        // Python: json.dumps({"b": 1, "a": [2, "x"]}, sort_keys=True)
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": [2, "x"]})),
            r#"{"a": [2, "x"], "b": 1}"#
        );
    }

    #[test]
    fn nested_objects_sorted_recursively() {
        assert_eq!(
            canonical_json(&json!({"outer": {"z": 1, "a": {"m": null}}})),
            r#"{"outer": {"a": {"m": null}, "z": 1}}"#
        );
    }

    #[test]
    fn non_ascii_stays_literal() {
        assert_eq!(canonical_json(&json!("café")), "\"café\"");
    }

    #[test]
    fn control_chars_escaped_like_python() {
        // Python json.dumps escapes \x01 as \u0001 and \n/\t as short escapes.
        assert_eq!(
            canonical_json(&json!("a\u{01}b\nc\td")),
            "\"a\\u0001b\\nc\\td\""
        );
    }

    #[test]
    fn float_formats_like_python_repr() {
        assert_eq!(format_float(1.0), "1.0");
        assert_eq!(format_float(0.1), "0.1");
        assert_eq!(format_float(-2.5), "-2.5");
        assert_eq!(format_float(0.0001), "0.0001");
        assert_eq!(format_float(1234567890123456.0), "1234567890123456.0");
        assert_eq!(format_float(1e20), "1e+20");
        assert_eq!(format_float(1e-6), "1e-06");
    }

    #[test]
    fn canonical_round_trip_through_digest() {
        let v = json!({
            "decision_id": "oracle-post-1-BTC-USD",
            "foundation_score": 100,
            "parity": {"delta": 0.0, "within_tolerance": true}
        });
        let body = canonical_json(&v);
        use sha2::Digest;
        let digest = sha2::Sha256::digest(body.as_bytes());
        let hexed: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hexed.len(), 64);
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(canonical_json(&parsed), body); // idempotent
    }
}
