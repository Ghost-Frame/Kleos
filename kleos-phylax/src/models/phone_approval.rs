//! Canonical encoding and cryptographic verification for exact-phone decisions.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Version of the exact-phone approval wire protocol.
pub const PHONE_APPROVAL_VERSION: u64 = 1;

/// Domain separator for an immutable approval request digest.
const REQUEST_DIGEST_DOMAIN: &[u8] = b"phylax-approval-request-v2\0";

/// Domain separator for the digest of request fields the phone does not display.
const HIDDEN_DIGEST_DOMAIN: &[u8] = b"phylax-approval-hidden-v1\0";

/// Domain separator for a phone-signed decision envelope.
const PHONE_DECISION_DOMAIN: &[u8] = b"phylax-phone-approval-v1\0";

/// Maximum length accepted for any canonical UTF-8 field.
const MAX_CANONICAL_FIELD_BYTES: usize = 16 * 1024;

/// A phone's explicit decision for one approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PhoneDecision {
    /// Authorize the exact request described by the bound digest.
    Approved,
    /// Reject the exact request described by the bound digest.
    Denied,
}

/// JSON transport object whose signature covers a deterministic binary form.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PhoneDecisionEnvelope {
    /// Wire protocol version.
    pub version: u64,
    /// Server-assigned approval row identifier.
    pub approval_id: i64,
    /// Base64url-encoded 32-byte server nonce.
    pub nonce: String,
    /// Base64url-encoded 32-byte immutable request digest.
    pub request_digest: String,
    /// Human decision bound by the signature.
    pub decision: PhoneDecision,
    /// Server-assigned enrolled device identifier.
    pub device_id: String,
    /// Phone wall-clock time as Unix seconds.
    pub issued_at: i64,
    /// Exact server-owned request expiry as Unix seconds.
    pub expires_at: i64,
    /// Base64url-encoded ASN.1 DER P-256 ECDSA signature.
    pub signature: String,
}

/// Request fields the phone displays, which it re-hashes on-device before signing.
#[derive(Debug, Clone)]
pub struct DisplayedApproval<'a> {
    /// Server-assigned approval row identifier.
    pub approval_id: i64,
    /// Agent requesting the operation.
    pub agent_name: &'a str,
    /// Credential category or public operation class.
    pub category: &'a str,
    /// Credential name or public operation target.
    pub secret_name: &'a str,
    /// Requested resolve mode or action.
    pub resolve_mode: &'a str,
    /// Server expiry time as Unix seconds.
    pub expires_at: i64,
}

/// Server-owned values that a submitted envelope must exactly match.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedPhoneDecision<'a> {
    /// Pending approval row identifier.
    pub approval_id: i64,
    /// Fresh nonce stored for the pending approval.
    pub nonce: &'a [u8; 32],
    /// Digest recomputed or loaded from the immutable request.
    pub request_digest: &'a [u8; 32],
    /// Enrolled device identifier associated with the verifying key.
    pub device_id: &'a str,
    /// Exact server-owned request expiry as Unix seconds.
    pub expires_at: i64,
    /// Current server time as Unix seconds.
    pub now: i64,
    /// Maximum absolute difference between phone and server clocks.
    pub max_clock_skew_seconds: i64,
}

/// Fail-closed errors produced while encoding or verifying a phone decision.
#[derive(Debug, thiserror::Error)]
pub enum PhoneApprovalError {
    /// A field is malformed, unsupported, or does not match server state.
    #[error("phone approval envelope rejected")]
    Rejected,
    /// The enrolled public key cannot be decoded as P-256 SPKI.
    #[error("phone approval key rejected")]
    InvalidPublicKey,
    /// The ECDSA signature is malformed or does not verify.
    #[error("phone approval signature rejected")]
    InvalidSignature,
}

/// Supplies deterministic binary encoding for a decision envelope.
impl PhoneDecisionEnvelope {
    /// Encode every signed field in the protocol-defined order.
    pub fn canonical_message(&self) -> Result<Vec<u8>, PhoneApprovalError> {
        let nonce = decode_fixed_32(&self.nonce)?;
        let request_digest = decode_fixed_32(&self.request_digest)?;
        let approval_id = u64::try_from(self.approval_id)
            .ok()
            .filter(|id| *id > 0)
            .ok_or(PhoneApprovalError::Rejected)?;

        let mut message = Vec::with_capacity(160 + self.device_id.len());
        message.extend_from_slice(PHONE_DECISION_DOMAIN);
        append_u64(&mut message, self.version);
        append_u64(&mut message, approval_id);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&request_digest);
        message.push(match self.decision {
            PhoneDecision::Approved => 1,
            PhoneDecision::Denied => 2,
        });
        append_bytes(&mut message, self.device_id.as_bytes())?;
        append_i64(&mut message, self.issued_at);
        append_i64(&mut message, self.expires_at);
        Ok(message)
    }
}

/// Hash the request fields the phone does not display into one opaque value.
///
/// The phone receives this value, so it can rebuild `request_digest` from
/// what it shows without learning or trusting the hidden fields themselves.
pub fn hidden_digest(
    user_id: i64,
    correlation_id: &str,
    operation_digest: Option<&[u8; 32]>,
    created_at: i64,
) -> Result<[u8; 32], PhoneApprovalError> {
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(HIDDEN_DIGEST_DOMAIN);
    append_i64(&mut encoded, user_id);
    append_bytes(&mut encoded, correlation_id.as_bytes())?;
    match operation_digest {
        Some(digest) => {
            encoded.push(1);
            encoded.extend_from_slice(digest);
        }
        None => encoded.push(0),
    }
    append_i64(&mut encoded, created_at);
    Ok(Sha256::digest(encoded).into())
}

/// Compute the immutable digest shown to and signed by the enrolled phone.
///
/// Covers the displayed fields directly and the hidden fields through
/// `hidden`, so the phone can recompute it from its own screen contents.
pub fn request_digest(
    displayed: &DisplayedApproval<'_>,
    hidden: &[u8; 32],
) -> Result<[u8; 32], PhoneApprovalError> {
    let mut encoded = Vec::with_capacity(256);
    encoded.extend_from_slice(REQUEST_DIGEST_DOMAIN);
    append_u64(&mut encoded, PHONE_APPROVAL_VERSION);
    append_i64(&mut encoded, displayed.approval_id);
    append_bytes(&mut encoded, displayed.agent_name.as_bytes())?;
    append_bytes(&mut encoded, displayed.category.as_bytes())?;
    append_bytes(&mut encoded, displayed.secret_name.as_bytes())?;
    append_bytes(&mut encoded, displayed.resolve_mode.as_bytes())?;
    append_i64(&mut encoded, displayed.expires_at);
    encoded.extend_from_slice(hidden);
    Ok(Sha256::digest(encoded).into())
}

/// Verify an envelope against enrolled key material and server-owned state.
pub fn verify_envelope(
    envelope: &PhoneDecisionEnvelope,
    public_key_der: &[u8],
    expected: &ExpectedPhoneDecision<'_>,
) -> Result<PhoneDecision, PhoneApprovalError> {
    if envelope.version != PHONE_APPROVAL_VERSION
        || envelope.approval_id != expected.approval_id
        || envelope.device_id != expected.device_id
        || envelope.expires_at != expected.expires_at
        || expected.now > expected.expires_at
        || envelope.issued_at > expected.expires_at
        || envelope.issued_at < expected.now.saturating_sub(expected.max_clock_skew_seconds)
        || envelope.issued_at > expected.now.saturating_add(expected.max_clock_skew_seconds)
    {
        return Err(PhoneApprovalError::Rejected);
    }

    let nonce = decode_fixed_32(&envelope.nonce)?;
    let digest = decode_fixed_32(&envelope.request_digest)?;
    if nonce.ct_eq(expected.nonce).unwrap_u8() != 1
        || digest.ct_eq(expected.request_digest).unwrap_u8() != 1
    {
        return Err(PhoneApprovalError::Rejected);
    }

    let verifying_key = VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|_| PhoneApprovalError::InvalidPublicKey)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| PhoneApprovalError::InvalidSignature)?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|_| PhoneApprovalError::InvalidSignature)?;
    let message = envelope.canonical_message()?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| PhoneApprovalError::InvalidSignature)?;
    Ok(envelope.decision)
}

/// Decode an unpadded base64url field that must contain exactly 32 bytes.
fn decode_fixed_32(value: &str) -> Result<[u8; 32], PhoneApprovalError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| PhoneApprovalError::Rejected)?;
    decoded.try_into().map_err(|_| PhoneApprovalError::Rejected)
}

/// Append an unsigned integer in canonical big-endian representation.
fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// Append a signed integer in canonical big-endian representation.
fn append_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// Append one bounded length-prefixed field to a fallible signed message.
fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PhoneApprovalError> {
    if value.len() > MAX_CANONICAL_FIELD_BYTES {
        return Err(PhoneApprovalError::Rejected);
    }
    let length = u32::try_from(value.len()).map_err(|_| PhoneApprovalError::Rejected)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
