//! Shared test helpers: the adversarial canary encoding generator.
//!
//! Copied from `kleos-phylax/tests/common/mod.rs` (integration tests cannot
//! share code across crates); keep the two in step.
//!
//! [`Canary`] expands one secret into every textual form a leak could take in
//! an HTTP response, so a test can assert that none of them appears. Base64 is
//! covered at all three alignments (the secret preceded by 0, 1 or 2 bytes of
//! other data), because a base64 encoder emits different characters for the
//! same bytes depending on the offset modulo 3.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;

/// Minimum length of an alignment-independent base64 core; shorter needles
/// would match by chance.
const MIN_CORE_LEN: usize = 8;

/// One labelled byte pattern that must never appear in a response.
#[derive(Debug, Clone)]
pub struct Needle {
    /// Human-readable description, e.g. `base64-url-nopad@align1`.
    pub label: String,
    /// The bytes searched for.
    pub bytes: Vec<u8>,
}

/// Every encoding of one secret that a leak could take.
#[derive(Debug, Clone)]
pub struct Canary {
    /// All needles derived from the secret.
    pub needles: Vec<Needle>,
}

/// Needle generation and leak detection.
impl Canary {
    /// Expand `secret` into raw, hex, base64, percent and JSON-escaped needles.
    pub fn new(secret: &str) -> Self {
        let bytes = secret.as_bytes();
        let mut needles = Vec::new();
        let mut add = |label: String, needle: Vec<u8>| {
            assert!(!needle.is_empty(), "empty needle for {label}");
            needles.push(Needle {
                label,
                bytes: needle,
            });
        };

        add("raw".into(), bytes.to_vec());
        add("hex-lower".into(), hex::encode(bytes).into_bytes());
        add("hex-upper".into(), hex::encode_upper(bytes).into_bytes());

        // Whole-value base64, padded and unpadded, both alphabets (alignment 0).
        add(
            "base64-std-padded".into(),
            STANDARD.encode(bytes).into_bytes(),
        );
        add(
            "base64-std-nopad".into(),
            STANDARD_NO_PAD.encode(bytes).into_bytes(),
        );
        add(
            "base64-url-padded".into(),
            URL_SAFE.encode(bytes).into_bytes(),
        );
        add(
            "base64-url-nopad".into(),
            URL_SAFE_NO_PAD.encode(bytes).into_bytes(),
        );

        // Alignment-independent cores at all three alignments.
        for alignment in 0..3usize {
            for (name, core) in [
                ("base64-std", base64_core(bytes, alignment, false)),
                ("base64-url", base64_core(bytes, alignment, true)),
            ] {
                add(format!("{name}-core@align{alignment}"), core);
            }
        }

        add(
            "pct-upper".into(),
            percent_encode(bytes, false, true).into_bytes(),
        );
        add(
            "pct-lower".into(),
            percent_encode(bytes, false, false).into_bytes(),
        );
        add(
            "pct-all-upper".into(),
            percent_encode(bytes, true, true).into_bytes(),
        );
        add(
            "pct-all-lower".into(),
            percent_encode(bytes, true, false).into_bytes(),
        );

        let json = serde_json::to_string(secret).expect("serialize secret as JSON string");
        let json_inner = json[1..json.len() - 1].to_string();
        add("json-escaped".into(), json_inner.clone().into_bytes());
        let double = serde_json::to_string(&json_inner).expect("serialize escaped JSON string");
        add(
            "json-double-escaped".into(),
            double.as_bytes()[1..double.len() - 1].to_vec(),
        );
        add(
            "json-unicode-escaped-lower".into(),
            unicode_escape(secret, false).into_bytes(),
        );
        add(
            "json-unicode-escaped-upper".into(),
            unicode_escape(secret, true).into_bytes(),
        );

        Self { needles }
    }

    /// Label of the first needle found in `haystack`, if any.
    pub fn find_leak(&self, haystack: &[u8]) -> Option<&str> {
        self.needles
            .iter()
            .find(|n| contains(haystack, &n.bytes))
            .map(|n| n.label.as_str())
    }
}

/// True when `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Alignment-independent base64 core of `secret` placed after `alignment`
/// filler bytes.
///
/// The leading characters that mix filler bits with secret bits, and the
/// trailing characters of a final partial group (which depend on what follows
/// the secret), are dropped; what remains appears verbatim in any base64 stream
/// that carries the secret at that offset modulo 3.
fn base64_core(secret: &[u8], alignment: usize, url_safe: bool) -> Vec<u8> {
    let mut stream = vec![0xA5u8; alignment];
    stream.extend_from_slice(secret);
    let encoded = if url_safe {
        URL_SAFE_NO_PAD.encode(&stream)
    } else {
        STANDARD_NO_PAD.encode(&stream)
    };
    // Characters touched by filler bits: ceil(8 * alignment / 6).
    let skip = (alignment * 8).div_ceil(6);
    let end = (stream.len() / 3) * 4;
    assert!(
        end > skip && end - skip >= MIN_CORE_LEN,
        "secret too short for a meaningful base64 core"
    );
    encoded.as_bytes()[skip..end].to_vec()
}

/// Percent-encode `bytes`; `all` encodes every byte, otherwise only bytes
/// outside the RFC 3986 unreserved set.
fn percent_encode(bytes: &[u8], all: bool, upper: bool) -> String {
    let mut out = String::new();
    for &b in bytes {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved && !all {
            out.push(b as char);
        } else if upper {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

/// Escape every non-ASCII-alphanumeric char as `\uXXXX` (surrogate pairs for
/// astral chars), the form a JSON encoder may emit for arbitrary text.
fn unicode_escape(text: &str, upper: bool) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            if upper {
                out.push_str(&format!("\\u{unit:04X}"));
            } else {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// Fixture secret used by the canary tests: distinctive, long enough for
/// meaningful base64 cores, and containing characters whose percent, JSON and
/// base64-alphabet encodings all differ from the raw text (`/ + = " & < >` and
/// a non-ASCII letter).
pub const CANARY_SECRET: &str = "CNRY/Zq+9=\"x&\u{e9}<>-7f3a91c2e8b04d56-tail";

/// Detector self-checks: a canary that cannot see a leak proves nothing.
#[cfg(test)]
mod tests {
    use super::*;

    /// Each needle is found when embedded in surrounding noise.
    #[test]
    fn every_needle_is_detected_in_noise() {
        let canary = Canary::new(CANARY_SECRET);
        for needle in &canary.needles {
            let mut haystack = b"{\"x\":\"noise-".to_vec();
            haystack.extend_from_slice(&needle.bytes);
            haystack.extend_from_slice(b"-noise\"}");
            assert!(
                canary.find_leak(&haystack).is_some(),
                "needle {} not detected",
                needle.label
            );
        }
    }

    /// Base64 of the secret at every offset-mod-3 and every trailing length,
    /// in both alphabets and with and without padding, is detected.
    #[test]
    fn base64_detected_at_all_alignments_and_paddings() {
        let canary = Canary::new(CANARY_SECRET);
        for prefix in 0..3usize {
            for suffix in 0..3usize {
                let mut stream = vec![0x11u8; prefix];
                stream.extend_from_slice(CANARY_SECRET.as_bytes());
                stream.extend_from_slice(&vec![0x7Eu8; suffix]);
                for encoded in [
                    STANDARD.encode(&stream),
                    STANDARD_NO_PAD.encode(&stream),
                    URL_SAFE.encode(&stream),
                    URL_SAFE_NO_PAD.encode(&stream),
                ] {
                    assert!(
                        canary.find_leak(encoded.as_bytes()).is_some(),
                        "missed base64 leak prefix={prefix} suffix={suffix}: {encoded}"
                    );
                }
            }
        }
    }

    /// Unrelated text is not flagged.
    #[test]
    fn clean_text_is_not_flagged() {
        let canary = Canary::new(CANARY_SECRET);
        assert!(canary
            .find_leak(br#"{"error":"permission denied","status":403}"#)
            .is_none());
    }
}
