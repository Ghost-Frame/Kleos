//! Streaming secret redaction for proxied responses.
//!
//! A [`Redactor`] knows a set of secrets and, for each one, every textual form
//! a leak could take: the raw bytes, lower and upper hex, base64 (standard and
//! URL-safe alphabet, padded and unpadded, at all three alignments a base64
//! stream can carry the secret at), percent-encoding, and JSON string escaping.
//! Any occurrence in the data is replaced by [`REPLACEMENT`].
//!
//! The scan is streaming: [`Redactor::feed`] accepts arbitrary chunks and holds
//! back the last `max_needle_len - 1` bytes, so a match split across chunk
//! boundaries is still found and the output is identical to redacting the
//! concatenated input in one pass.
//!
//! Redaction is best effort against encodings it knows about: a party that
//! already holds the secret can always re-encode it in a form no scanner
//! predicts. The proxy therefore relies on origin pinning to bound who ever
//! receives the secret, and on this module to close the accidental and the
//! lazily adversarial echo paths.

use std::collections::BTreeSet;
use std::fmt;

use aho_corasick::{AhoCorasick, MatchKind};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use thiserror::Error;

/// Bytes written in place of every redacted occurrence.
pub const REPLACEMENT: &[u8] = b"[REDACTED]";

/// Shortest secret a [`Redactor`] accepts. Shorter values cannot be told apart
/// from ordinary text, so callers must refuse to proxy them.
pub const MIN_SECRET_LEN: usize = 3;

/// Shortest base64 alignment core that is searched for. A core under four
/// characters carries at most 12 bits of the secret and would match ordinary
/// text by chance, garbling responses without hiding anything.
const MIN_CORE_LEN: usize = 4;

/// Filler byte placed before the secret when deriving base64 alignment cores.
const ALIGN_FILLER: u8 = 0xA5;

/// Why a [`Redactor`] could not be built.
#[derive(Debug, Error)]
pub enum RedactError {
    /// A secret was shorter than [`MIN_SECRET_LEN`] bytes.
    #[error("secret is shorter than 3 bytes and cannot be redacted safely")]
    SecretTooShort,
    /// The multi-pattern matcher could not be constructed.
    #[error("redactor construction failed: {0}")]
    Build(String),
}

/// Multi-secret streaming redactor. Create one per response; it is stateful.
pub struct Redactor {
    /// Matcher over every encoding of every secret; `None` when there are no
    /// secrets (pass-through).
    matcher: Option<AhoCorasick>,
    /// Length of the longest needle.
    max_len: usize,
    /// Number of distinct needles (for diagnostics and tests).
    needle_count: usize,
    /// Tail of the input not yet emitted (at most `max_len - 1` bytes, plus
    /// nothing else): it may be the start of a match completed by later bytes.
    carry: Vec<u8>,
}

/// Never prints needles: they are the secrets.
impl fmt::Debug for Redactor {
    /// Format only sizes, never needle contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("needles", &self.needle_count)
            .field("max_needle_len", &self.max_len)
            .field("carry_len", &self.carry.len())
            .finish()
    }
}

/// Construction and scanning.
impl Redactor {
    /// Build a redactor for `secrets`. Duplicate needles are merged. Returns
    /// [`RedactError::SecretTooShort`] if any secret is under
    /// [`MIN_SECRET_LEN`] bytes.
    pub fn new(secrets: &[Vec<u8>]) -> Result<Self, RedactError> {
        let mut needles: BTreeSet<Vec<u8>> = BTreeSet::new();
        for secret in secrets {
            if secret.len() < MIN_SECRET_LEN {
                return Err(RedactError::SecretTooShort);
            }
            needles.extend(encodings(secret));
        }
        let needle_count = needles.len();
        let max_len = needles.iter().map(Vec::len).max().unwrap_or(0);
        let matcher = if needles.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&needles)
                    .map_err(|e| RedactError::Build(e.to_string()))?,
            )
        };
        Ok(Self {
            matcher,
            max_len,
            needle_count,
            carry: Vec::new(),
        })
    }

    /// Number of distinct needles being searched for.
    pub fn needle_count(&self) -> usize {
        self.needle_count
    }

    /// Length of the longest needle; the carry never exceeds one less.
    pub fn max_needle_len(&self) -> usize {
        self.max_len
    }

    /// Feed the next chunk and return the bytes that are safe to emit now.
    ///
    /// A match that starts at offset `s` is decided only once `max_len` bytes
    /// are visible from `s`, which is exactly when `s` falls before the held
    /// back tail. Everything at or after that point stays in the carry.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(matcher) = &self.matcher else {
            return chunk.to_vec();
        };
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let hold = self.max_len.saturating_sub(1);
        let safe_end = buf.len().saturating_sub(hold);

        let mut out = Vec::with_capacity(buf.len());
        let mut pos = 0usize;
        for m in matcher.find_iter(&buf) {
            if m.start() >= safe_end {
                break;
            }
            out.extend_from_slice(&buf[pos..m.start()]);
            out.extend_from_slice(REPLACEMENT);
            pos = m.end();
        }
        let cut = pos.max(safe_end);
        out.extend_from_slice(&buf[pos..cut]);
        self.carry = buf[cut..].to_vec();
        out
    }

    /// Flush the carry once the stream has ended.
    pub fn finish(mut self) -> Vec<u8> {
        let carry = std::mem::take(&mut self.carry);
        self.redact_slice(&carry)
    }

    /// Redact one complete value (a header value, say) without touching the
    /// streaming state.
    pub fn redact_slice(&self, input: &[u8]) -> Vec<u8> {
        let Some(matcher) = &self.matcher else {
            return input.to_vec();
        };
        let mut out = Vec::with_capacity(input.len());
        let mut pos = 0usize;
        for m in matcher.find_iter(input) {
            out.extend_from_slice(&input[pos..m.start()]);
            out.extend_from_slice(REPLACEMENT);
            pos = m.end();
        }
        out.extend_from_slice(&input[pos..]);
        out
    }

    /// True when `input` contains any needle.
    pub fn contains_secret(&self, input: &[u8]) -> bool {
        self.matcher
            .as_ref()
            .is_some_and(|matcher| matcher.is_match(input))
    }
}

/// Every needle derived from one secret.
///
/// Per secret this is at most 21 needles: raw (1), hex (2), whole-value base64
/// (4), base64 alignment cores (6), percent-encoding (4) and JSON escapes (4,
/// only when the secret is UTF-8). Duplicates collapse in the caller.
pub fn encodings(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![
        secret.to_vec(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
        STANDARD.encode(secret).into_bytes(),
        STANDARD_NO_PAD.encode(secret).into_bytes(),
        URL_SAFE.encode(secret).into_bytes(),
        URL_SAFE_NO_PAD.encode(secret).into_bytes(),
    ];

    // Base64 of the secret as it appears when it starts at byte offset 0, 1 or
    // 2 of a group: encode `filler || secret`, drop the characters that mix in
    // filler bits (ceil(8 * a / 6)), and drop the trailing partial group, whose
    // characters depend on the bytes after the secret.
    for alignment in 0..3usize {
        let mut stream = vec![ALIGN_FILLER; alignment];
        stream.extend_from_slice(secret);
        let skip = (alignment * 8).div_ceil(6);
        let end = (stream.len() / 3) * 4;
        if end <= skip || end - skip < MIN_CORE_LEN {
            continue;
        }
        for encoded in [
            STANDARD_NO_PAD.encode(&stream),
            URL_SAFE_NO_PAD.encode(&stream),
        ] {
            out.push(encoded.as_bytes()[skip..end].to_vec());
        }
    }

    for all in [false, true] {
        for upper in [false, true] {
            out.push(percent_encode(secret, all, upper).into_bytes());
        }
    }

    if let Ok(text) = std::str::from_utf8(secret) {
        if let Ok(json) = serde_json::to_string(text) {
            let inner = json[1..json.len() - 1].to_string();
            if let Ok(double) = serde_json::to_string(&inner) {
                out.push(double.as_bytes()[1..double.len() - 1].to_vec());
            }
            out.push(inner.into_bytes());
        }
        out.push(unicode_escape(text, false).into_bytes());
        out.push(unicode_escape(text, true).into_bytes());
    }

    out.retain(|needle| !needle.is_empty());
    out
}

/// Percent-encode `bytes`. With `all` every byte is encoded, otherwise only
/// bytes outside the RFC 3986 unreserved set.
fn percent_encode(bytes: &[u8], all: bool, upper: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
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

/// Unit and property tests for the redactor.
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Feed `input` in chunks of the given sizes (cycled) and collect the output.
    fn run_chunked(mut redactor: Redactor, input: &[u8], sizes: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut i = 0usize;
        while pos < input.len() {
            let size = sizes[i % sizes.len()].max(1);
            let end = (pos + size).min(input.len());
            out.extend(redactor.feed(&input[pos..end]));
            pos = end;
            i += 1;
        }
        out.extend(redactor.finish());
        out
    }

    /// Replace every [`REPLACEMENT`] token with a NUL byte, so the replacement
    /// text itself (which may contain a short secret) is not scanned.
    fn strip_replacements(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0usize;
        while i < data.len() {
            if data[i..].starts_with(REPLACEMENT) {
                out.push(0);
                i += REPLACEMENT.len();
            } else {
                out.push(data[i]);
                i += 1;
            }
        }
        out
    }

    /// True when `needle` occurs in `haystack`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Secrets under three bytes are refused.
    #[test]
    fn short_secrets_are_refused() {
        assert!(matches!(
            Redactor::new(&[b"ab".to_vec()]),
            Err(RedactError::SecretTooShort)
        ));
        assert!(Redactor::new(&[b"abc".to_vec()]).is_ok());
    }

    /// A raw match inside text is replaced, surrounding bytes are kept.
    #[test]
    fn raw_match_is_replaced() {
        let r = Redactor::new(&[b"sk-live-12345".to_vec()]).unwrap();
        let out = r.redact_slice(b"Bearer sk-live-12345 ok");
        assert_eq!(out, b"Bearer [REDACTED] ok");
    }

    /// A match split across three chunks is still found and nothing leaks.
    #[test]
    fn match_split_across_three_chunks() {
        let secret = b"sk-live-1234567890".to_vec();
        let r = Redactor::new(std::slice::from_ref(&secret)).unwrap();
        let input = b"prefix sk-live-1234567890 suffix";
        let start = 7;
        let a = &input[..start + 4];
        let b = &input[start + 4..start + 11];
        let c = &input[start + 11..];
        let mut r = r;
        let mut out = r.feed(a);
        out.extend(r.feed(b));
        out.extend(r.feed(c));
        out.extend(r.finish());
        assert_eq!(out, b"prefix [REDACTED] suffix");
    }

    /// One byte at a time still redacts, including a match at the very end.
    #[test]
    fn byte_at_a_time_and_match_at_end() {
        let r = Redactor::new(&[b"hunter2!".to_vec()]).unwrap();
        let out = run_chunked(r, b"pw=hunter2!", &[1]);
        assert_eq!(out, b"pw=[REDACTED]");
    }

    /// A secret echoed inside a Set-Cookie header value is redacted when the
    /// header value is passed through `redact_slice`.
    #[test]
    fn match_inside_set_cookie_value() {
        let r = Redactor::new(&[b"sk-live-abcdef".to_vec()]).unwrap();
        let value = b"session=sk-live-abcdef; Path=/; HttpOnly";
        let out = r.redact_slice(value);
        assert_eq!(out, b"session=[REDACTED]; Path=/; HttpOnly");
        assert!(!r.contains_secret(&out));
    }

    /// Each encoding of a secret is found when embedded in noise, and the
    /// needle set stays within the documented size.
    #[test]
    fn every_encoding_is_redacted_and_set_is_bounded() {
        let secret = "CNRY/Zq+9=\"x&\u{e9}<>-7f3a91c2e8b04d56-tail";
        let needles = encodings(secret.as_bytes());
        assert!(needles.len() <= 21, "needle set grew: {}", needles.len());
        let r = Redactor::new(&[secret.as_bytes().to_vec()]).unwrap();
        for needle in &needles {
            let mut hay = b"{\"x\":\"noise-".to_vec();
            hay.extend_from_slice(needle);
            hay.extend_from_slice(b"-noise\"}");
            let out = r.redact_slice(&hay);
            assert!(
                !contains(&out, needle),
                "needle {:?} survived",
                String::from_utf8_lossy(needle)
            );
            assert!(contains(&out, REPLACEMENT));
        }
    }

    /// Base64 at every alignment and trailing length is hidden.
    #[test]
    fn base64_hidden_at_all_alignments() {
        let secret = b"0123456789abcdefghij-KEY".to_vec();
        let r = Redactor::new(std::slice::from_ref(&secret)).unwrap();
        for prefix in 0..3usize {
            for suffix in 0..3usize {
                let mut stream = vec![0x11u8; prefix];
                stream.extend_from_slice(&secret);
                stream.extend_from_slice(&vec![0x7Eu8; suffix]);
                for encoded in [
                    STANDARD.encode(&stream),
                    STANDARD_NO_PAD.encode(&stream),
                    URL_SAFE.encode(&stream),
                    URL_SAFE_NO_PAD.encode(&stream),
                ] {
                    let out = r.redact_slice(encoded.as_bytes());
                    let skip = (prefix * 8).div_ceil(6);
                    let end = ((prefix + secret.len()) / 3) * 4;
                    let core = &encoded.as_bytes()[skip..end];
                    assert!(
                        !contains(&out, core),
                        "base64 core survived prefix={prefix} suffix={suffix}"
                    );
                }
            }
        }
    }

    /// Debug output never contains needle bytes.
    #[test]
    fn debug_does_not_print_needles() {
        let r = Redactor::new(&[b"super-secret-value".to_vec()]).unwrap();
        assert!(!format!("{r:?}").contains("super-secret-value"));
    }

    /// No secrets means pass-through.
    #[test]
    fn empty_redactor_passes_through() {
        let mut r = Redactor::new(&[]).unwrap();
        assert_eq!(r.feed(b"anything"), b"anything");
        assert!(r.finish().is_empty());
    }

    /// The carry never exceeds `max_needle_len - 1` bytes.
    #[test]
    fn carry_is_bounded() {
        let mut r = Redactor::new(&[b"0123456789".to_vec()]).unwrap();
        let hold = r.max_needle_len() - 1;
        for _ in 0..50 {
            r.feed(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
            assert!(r.carry.len() <= hold);
        }
    }

    /// Printable ASCII secret bytes (covers JSON and percent specials).
    fn secret_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(0x20u8..=0x7E, 3..64)
    }

    /// Secrets long enough that chance collisions between one secret's
    /// encodings and another secret's needles are negligible, so exact output
    /// can be asserted.
    fn long_secret_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(0x20u8..=0x7E, 10..64)
    }

    /// Separator noise bytes that no needle can contain.
    fn noise_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(0x01u8..=0x08, 1..8)
    }

    /// The textual forms embedded by the exact-output property, built
    /// independently of [`encodings`].
    fn reference_forms(secret: &[u8]) -> Vec<Vec<u8>> {
        let text = String::from_utf8(secret.to_vec()).unwrap();
        let json = serde_json::to_string(&text).unwrap();
        let mut forms = vec![
            secret.to_vec(),
            secret
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into_bytes(),
            secret
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
                .into_bytes(),
            secret
                .iter()
                .map(|b| format!("%{b:02X}"))
                .collect::<String>()
                .into_bytes(),
            secret
                .iter()
                .map(|b| format!("%{b:02x}"))
                .collect::<String>()
                .into_bytes(),
            json.as_bytes()[1..json.len() - 1].to_vec(),
        ];
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            forms.push(engine.encode(secret).into_bytes());
        }
        forms
    }

    proptest! {
        /// Every embedded form of every secret becomes exactly one
        /// replacement, noise is preserved byte for byte, and the result does
        /// not depend on how the input is chunked.
        #[test]
        fn forms_are_replaced_exactly_for_any_chunking(
            secrets in proptest::collection::vec(long_secret_strategy(), 1..4),
            picks in proptest::collection::vec((any::<usize>(), any::<usize>(), noise_strategy()), 1..12),
            sizes in proptest::collection::vec(1usize..24, 1..8),
        ) {
            let mut input = Vec::new();
            let mut expected = Vec::new();
            for (which, form, noise) in &picks {
                let secret = &secrets[which % secrets.len()];
                let forms = reference_forms(secret);
                input.extend_from_slice(&forms[form % forms.len()]);
                expected.extend_from_slice(REPLACEMENT);
                input.extend_from_slice(noise);
                expected.extend_from_slice(noise);
            }
            let redactor = Redactor::new(&secrets).unwrap();
            let chunked = run_chunked(redactor, &input, &sizes);
            let one_shot = Redactor::new(&secrets).unwrap().redact_slice(&input);
            prop_assert_eq!(&chunked, &one_shot);
            prop_assert_eq!(&chunked, &expected);
        }

        /// A base64 stream carrying the secret at any alignment, with random
        /// bytes around it, never keeps the secret's characters, and the noise
        /// bytes survive in order, for any chunking.
        #[test]
        fn base64_streams_never_keep_the_secret(
            secret in secret_strategy(),
            prefix in proptest::collection::vec(any::<u8>(), 0..3),
            suffix in proptest::collection::vec(any::<u8>(), 0..3),
            noise in noise_strategy(),
            url_safe in any::<bool>(),
            padded in any::<bool>(),
            sizes in proptest::collection::vec(1usize..16, 1..6),
        ) {
            let mut stream = prefix.clone();
            stream.extend_from_slice(&secret);
            stream.extend_from_slice(&suffix);
            let encoded = match (url_safe, padded) {
                (false, true) => STANDARD.encode(&stream),
                (false, false) => STANDARD_NO_PAD.encode(&stream),
                (true, true) => URL_SAFE.encode(&stream),
                (true, false) => URL_SAFE_NO_PAD.encode(&stream),
            };
            let skip = (prefix.len() * 8).div_ceil(6);
            let end = ((prefix.len() + secret.len()) / 3) * 4;
            let mut input = noise.clone();
            input.extend_from_slice(encoded.as_bytes());
            input.extend_from_slice(&noise);

            let redactor = Redactor::new(std::slice::from_ref(&secret)).unwrap();
            let out = run_chunked(redactor, &input, &sizes);
            let scanned = strip_replacements(&out);

            // Only a core long enough to be searched for is guaranteed gone.
            if end > skip && end - skip >= MIN_CORE_LEN {
                let core = &encoded.as_bytes()[skip..end];
                prop_assert!(!contains(&scanned, core), "core survived");
            }
            prop_assert!(!contains(&scanned, &secret), "raw secret survived");
            let noise_out: Vec<u8> = out.iter().copied().filter(|b| (1..=8).contains(b)).collect();
            let noise_in: Vec<u8> = input.iter().copied().filter(|b| (1..=8).contains(b)).collect();
            prop_assert_eq!(noise_out, noise_in);
        }
    }
}
