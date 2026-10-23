//! Adversarial tests for exact-phone approval envelope verification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kleos_phylax::models::phone_approval::{
    hidden_digest, request_digest, verify_envelope, DisplayedApproval, ExpectedPhoneDecision,
    PhoneDecision, PhoneDecisionEnvelope, PHONE_APPROVAL_VERSION,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;

/// Displayed-field fixture shared by the digest tests and the Android golden vector.
fn displayed_fixture() -> DisplayedApproval<'static> {
    DisplayedApproval {
        approval_id: 42,
        agent_name: "codex",
        category: "ssh-ca",
        secret_name: "build-01",
        resolve_mode: "ssh_ca_sign",
        expires_at: 1_786_820_900,
    }
}

/// Creates a valid signed envelope and the matching verification context.
fn signed_fixture() -> (PhoneDecisionEnvelope, Vec<u8>, [u8; 32], [u8; 32]) {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .expect("encode test public key")
        .as_bytes()
        .to_vec();
    let nonce = [0x31; 32];
    let hidden = hidden_digest(1, "corr-123", None, 1_786_820_000).unwrap();
    let digest = request_digest(&displayed_fixture(), &hidden).unwrap();
    let mut envelope = PhoneDecisionEnvelope {
        version: PHONE_APPROVAL_VERSION,
        approval_id: 42,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        request_digest: URL_SAFE_NO_PAD.encode(digest),
        decision: PhoneDecision::Approved,
        device_id: "phone-primary".to_string(),
        issued_at: 1_786_820_180,
        expires_at: 1_786_820_900,
        signature: String::new(),
    };
    let message = envelope.canonical_message().expect("encode envelope");
    let signature: Signature = signing_key.sign(&message);
    envelope.signature = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());
    (envelope, public_key_der, nonce, digest)
}

/// Pins the cross-language byte format shared with the Android encoder.
#[test]
fn canonical_golden_vector_matches_android() {
    let envelope = PhoneDecisionEnvelope {
        version: PHONE_APPROVAL_VERSION,
        approval_id: 42,
        nonce: URL_SAFE_NO_PAD.encode([0x31; 32]),
        request_digest: URL_SAFE_NO_PAD.encode([0x77; 32]),
        decision: PhoneDecision::Approved,
        device_id: "phone-primary".to_string(),
        issued_at: 1_786_820_100,
        expires_at: 1_786_820_900,
        signature: String::new(),
    };
    let expected = "7068796c61782d70686f6e652d617070726f76616c2d763100\
        0000000000000001000000000000002a\
        3131313131313131313131313131313131313131313131313131313131313131\
        7777777777777777777777777777777777777777777777777777777777777777\
        010000000d70686f6e652d7072696d617279\
        000000006a80b604000000006a80b924"
        .replace(char::is_whitespace, "");

    assert_eq!(
        hex::encode(envelope.canonical_message().expect("canonical message")),
        expected
    );
}

/// Builds the server-owned values that a valid phone envelope must match.
fn expected<'a>(nonce: &'a [u8; 32], digest: &'a [u8; 32]) -> ExpectedPhoneDecision<'a> {
    ExpectedPhoneDecision {
        approval_id: 42,
        nonce,
        request_digest: digest,
        device_id: "phone-primary",
        expires_at: 1_786_820_900,
        now: 1_786_820_200,
        max_clock_skew_seconds: 60,
    }
}

/// Accepts a signature from the enrolled key over the exact pending request.
#[test]
fn valid_envelope_verifies() {
    let (envelope, public_key_der, nonce, digest) = signed_fixture();

    let decision = verify_envelope(&envelope, &public_key_der, &expected(&nonce, &digest))
        .expect("valid signature");

    assert_eq!(decision, PhoneDecision::Approved);
}

/// Rejects the exact signature when checked against an unregistered phone key.
#[test]
fn wrong_phone_key_is_rejected() {
    let (envelope, _, nonce, digest) = signed_fixture();
    let wrong_key = SigningKey::random(&mut OsRng);
    let wrong_der = wrong_key
        .verifying_key()
        .to_public_key_der()
        .expect("encode wrong public key");

    assert!(verify_envelope(&envelope, wrong_der.as_bytes(), &expected(&nonce, &digest),).is_err());
}

/// Rejects a relay mutation that changes the reviewed decision after signing.
#[test]
fn changed_decision_is_rejected() {
    let (mut envelope, public_key_der, nonce, digest) = signed_fixture();
    envelope.decision = PhoneDecision::Denied;

    assert!(verify_envelope(&envelope, &public_key_der, &expected(&nonce, &digest),).is_err());
}

/// Rejects a valid signature replayed against a different server nonce.
#[test]
fn changed_nonce_is_rejected() {
    let (envelope, public_key_der, _, digest) = signed_fixture();
    let different_nonce = [0x99; 32];

    assert!(verify_envelope(
        &envelope,
        &public_key_der,
        &expected(&different_nonce, &digest),
    )
    .is_err());
}

/// Rejects a valid signature replayed against mutated request metadata.
#[test]
fn changed_request_digest_is_rejected() {
    let (envelope, public_key_der, nonce, _) = signed_fixture();
    let different_digest = [0x77; 32];

    assert!(verify_envelope(
        &envelope,
        &public_key_der,
        &expected(&nonce, &different_digest),
    )
    .is_err());
}

/// Rejects a request after the server-owned expiry time has passed.
#[test]
fn expired_envelope_is_rejected() {
    let (envelope, public_key_der, nonce, digest) = signed_fixture();
    let mut expired = expected(&nonce, &digest);
    expired.now = expired.expires_at + 1;

    assert!(verify_envelope(&envelope, &public_key_der, &expired).is_err());
}

/// Rejects a phone timestamp too far ahead of the verifier clock.
#[test]
fn excessive_future_clock_skew_is_rejected() {
    let (mut envelope, public_key_der, nonce, digest) = signed_fixture();
    envelope.issued_at = 1_786_820_261;

    assert!(verify_envelope(&envelope, &public_key_der, &expected(&nonce, &digest),).is_err());
}

/// Rejects a phone timestamp too far behind the verifier clock.
#[test]
fn excessive_past_clock_skew_is_rejected() {
    let (mut envelope, public_key_der, nonce, digest) = signed_fixture();
    envelope.issued_at = 1_786_820_139;

    assert!(verify_envelope(&envelope, &public_key_der, &expected(&nonce, &digest),).is_err());
}

/// Rejects malformed base64 before attempting signature verification.
#[test]
fn malformed_encoding_is_rejected() {
    let (mut envelope, public_key_der, nonce, digest) = signed_fixture();
    envelope.signature = "not+base64url".to_string();

    assert!(verify_envelope(&envelope, &public_key_der, &expected(&nonce, &digest),).is_err());
}

/// Proves the digests change when any reviewed or hidden operation field changes.
#[test]
fn request_digest_binds_operation_metadata() {
    let hidden = hidden_digest(1, "corr-123", None, 1_786_820_000).unwrap();
    let base = request_digest(&displayed_fixture(), &hidden).unwrap();

    let mutated_target = DisplayedApproval {
        secret_name: "build-02",
        ..displayed_fixture()
    };
    assert_ne!(base, request_digest(&mutated_target, &hidden).unwrap());

    let operation_digest = [0x42; 32];
    let bound_hidden =
        hidden_digest(1, "corr-123", Some(&operation_digest), 1_786_820_000).unwrap();
    assert_ne!(hidden, bound_hidden);
    assert_ne!(
        base,
        request_digest(&displayed_fixture(), &bound_hidden).unwrap()
    );
}

/// Pins the cross-language request digest format shared with the Android encoder.
#[test]
fn request_digest_golden_vector_matches_android() {
    let digest = request_digest(&displayed_fixture(), &[0x55; 32]).unwrap();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "d8709ecce2ae14b2618d78f27630d8ba6f98cef26228ab89d769f66932218bea"
    );
}
