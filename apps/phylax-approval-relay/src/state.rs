//! Bounded in-memory capability state for exact-phone approvals.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Maximum live approvals retained by one relay process.
const MAX_PENDING_APPROVALS: usize = 256;

/// Maximum random-handle generation attempts before failing closed.
const MAX_HANDLE_ATTEMPTS: usize = 8;

/// Public immutable request metadata returned to the phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicApprovalRequest {
    /// Wire protocol version.
    pub version: u64,
    /// Phylax approval identifier.
    pub approval_id: i64,
    /// Base64url server nonce.
    pub nonce: String,
    /// Base64url immutable request digest.
    pub request_digest: String,
    /// Base64url digest of the request fields the phone does not display.
    pub hidden_digest: String,
    /// Sole enrolled device identifier selected by Phylax.
    pub device_id: String,
    /// Requested operation.
    pub action: String,
    /// Requesting agent.
    pub agent_name: String,
    /// Credential or operation category.
    pub category: String,
    /// Target shown for human review.
    pub target_name: String,
    /// Server-owned expiry as Unix seconds.
    pub expires_at: i64,
}

/// Phone-signed envelope forwarded unchanged to Phylax.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneDecisionEnvelope {
    /// Wire protocol version.
    pub version: u64,
    /// Phylax approval identifier.
    pub approval_id: i64,
    /// Base64url server nonce.
    pub nonce: String,
    /// Base64url immutable request digest.
    pub request_digest: String,
    /// Exact human decision.
    pub decision: String,
    /// Enrolled device identifier.
    pub device_id: String,
    /// Phone signing time as Unix seconds.
    pub issued_at: i64,
    /// Server-owned expiry as Unix seconds.
    pub expires_at: i64,
    /// Base64url DER ECDSA signature.
    pub signature: String,
}

/// Server-only capability released to one in-flight decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionCapability {
    /// Raw one-use Phylax capability token.
    pub token: String,
    /// Approval identifier used in the Phylax URL.
    pub approval_id: i64,
}

/// One pending approval stored only in relay memory.
#[derive(Debug, Clone)]
struct PendingEntry {
    /// Raw one-use Phylax capability token.
    token: String,
    /// Public metadata retrievable by the phone.
    request: PublicApprovalRequest,
    /// Whether one decision is currently being forwarded.
    in_flight: bool,
}

/// Shared map keyed by a random 256-bit pickup handle.
#[derive(Clone)]
pub struct ApprovalState {
    /// Mutex-protected pending approvals.
    entries: Arc<Mutex<HashMap<String, PendingEntry>>>,
    /// Hard ceiling preventing notification-driven memory exhaustion.
    max_entries: usize,
}

/// Fail-closed state transition errors exposed as uniform HTTP failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// Handle is absent, expired, or already consumed.
    Unavailable,
    /// Another decision is already being forwarded.
    InFlight,
    /// Envelope does not match immutable relay metadata.
    Mismatch,
    /// The bounded pending store is full.
    Capacity,
    /// Secure pickup entropy was unavailable.
    Entropy,
    /// Random handle generation repeatedly collided.
    Collision,
}

/// State operations for one-shot approval relay behavior.
impl ApprovalState {
    /// Construct an empty in-memory approval state.
    pub fn new() -> Self {
        Self::with_capacity(MAX_PENDING_APPROVALS)
    }

    /// Insert one approval and return a random 43-character pickup handle.
    pub fn insert(
        &self,
        token: String,
        request: PublicApprovalRequest,
        now: i64,
    ) -> Result<String, StateError> {
        let mut entries = self.entries.lock().map_err(|_| StateError::Unavailable)?;
        entries.retain(|_, entry| entry.request.expires_at > now);
        if entries.len() >= self.max_entries {
            return Err(StateError::Capacity);
        }
        for _ in 0..MAX_HANDLE_ATTEMPTS {
            let mut random = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| StateError::Entropy)?;
            let handle = URL_SAFE_NO_PAD.encode(random);
            if !entries.contains_key(&handle) {
                entries.insert(handle.clone(), pending_entry(token, request));
                return Ok(handle);
            }
        }
        Err(StateError::Collision)
    }

    /// Return public metadata only for a live pickup handle.
    pub fn get_public(&self, handle: &str, now: i64) -> Result<PublicApprovalRequest, StateError> {
        if !valid_handle(handle) {
            return Err(StateError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| StateError::Unavailable)?;
        remove_if_expired(&mut entries, handle, now);
        entries
            .get(handle)
            .filter(|entry| !entry.in_flight)
            .map(|entry| entry.request.clone())
            .ok_or(StateError::Unavailable)
    }

    /// Reserve one matching decision so concurrent submissions cannot both forward.
    pub fn begin_decision(
        &self,
        handle: &str,
        envelope: &PhoneDecisionEnvelope,
        now: i64,
    ) -> Result<DecisionCapability, StateError> {
        if !valid_handle(handle) {
            return Err(StateError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| StateError::Unavailable)?;
        remove_if_expired(&mut entries, handle, now);
        let entry = entries.get_mut(handle).ok_or(StateError::Unavailable)?;
        if entry.in_flight {
            return Err(StateError::InFlight);
        }
        if !envelope_matches(&entry.request, envelope) {
            return Err(StateError::Mismatch);
        }
        entry.in_flight = true;
        Ok(DecisionCapability {
            token: entry.token.clone(),
            approval_id: entry.request.approval_id,
        })
    }

    /// Consume a successful decision or release a failed delivery for retry.
    pub fn finish_decision(&self, handle: &str, accepted: bool) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if accepted {
            entries.remove(handle);
        } else if let Some(entry) = entries.get_mut(handle) {
            entry.in_flight = false;
        }
    }

    /// Remove all approvals whose server-owned expiry has elapsed.
    pub fn sweep_expired(&self, now: i64) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, entry| entry.request.expires_at > now);
    }

    /// Construct a bounded store, primarily for deterministic capacity tests.
    fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
        }
    }

    /// Insert a selected handle without replacing a live entry.
    #[cfg(test)]
    fn insert_with_handle(
        &self,
        handle: String,
        token: String,
        request: PublicApprovalRequest,
        now: i64,
    ) -> Result<(), StateError> {
        let mut entries = self.entries.lock().map_err(|_| StateError::Unavailable)?;
        entries.retain(|_, entry| entry.request.expires_at > now);
        if entries.len() >= self.max_entries {
            return Err(StateError::Capacity);
        }
        if entries.contains_key(&handle) {
            return Err(StateError::Collision);
        }
        entries.insert(handle, pending_entry(token, request));
        Ok(())
    }
}

/// Build one pending entry without duplicating secret-bearing construction.
fn pending_entry(token: String, request: PublicApprovalRequest) -> PendingEntry {
    PendingEntry {
        token,
        request,
        in_flight: false,
    }
}

/// Remove one entry if its server expiry has elapsed.
fn remove_if_expired(entries: &mut HashMap<String, PendingEntry>, handle: &str, now: i64) {
    if entries
        .get(handle)
        .is_some_and(|entry| entry.request.expires_at <= now)
    {
        entries.remove(handle);
    }
}

/// Compare all relay-known signed fields before releasing the server capability.
fn envelope_matches(request: &PublicApprovalRequest, envelope: &PhoneDecisionEnvelope) -> bool {
    envelope.version == request.version
        && envelope.approval_id == request.approval_id
        && envelope.nonce == request.nonce
        && envelope.request_digest == request.request_digest
        && envelope.device_id == request.device_id
        && envelope.expires_at == request.expires_at
        && matches!(envelope.decision.as_str(), "approved" | "denied")
        && envelope.signature.len() <= 512
}

/// Validate the canonical unpadded base64url pickup-handle shape.
fn valid_handle(handle: &str) -> bool {
    handle.len() == 43
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
/// In-memory capability-state tests.
mod tests {
    use super::*;

    /// Fixed valid handle for deterministic state tests.
    const HANDLE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Build one valid public approval request.
    fn request() -> PublicApprovalRequest {
        PublicApprovalRequest {
            version: 1,
            approval_id: 42,
            nonce: "n".repeat(43),
            request_digest: "d".repeat(43),
            hidden_digest: "h".repeat(43),
            device_id: "phone-1".into(),
            action: "ssh_ca_sign".into(),
            agent_name: "codex".into(),
            category: "ssh-ca".into(),
            target_name: "host".into(),
            expires_at: 2_000,
        }
    }

    /// Build one envelope matching the fixed public request.
    fn envelope() -> PhoneDecisionEnvelope {
        PhoneDecisionEnvelope {
            version: 1,
            approval_id: 42,
            nonce: "n".repeat(43),
            request_digest: "d".repeat(43),
            decision: "approved".into(),
            device_id: "phone-1".into(),
            issued_at: 1_100,
            expires_at: 2_000,
            signature: "signature".into(),
        }
    }

    /// Public retrieval never returns the server capability token.
    #[test]
    fn public_retrieval_contains_metadata_only() {
        let state = ApprovalState::new();
        state
            .insert_with_handle(HANDLE.into(), "server-secret".into(), request(), 1_000)
            .expect("insert fixture");
        let public = state.get_public(HANDLE, 1_000).expect("public request");
        let encoded = serde_json::to_string(&public).expect("encode public request");
        assert!(!encoded.contains("server-secret"));
    }

    /// Exactly one matching decision may be in flight at a time.
    #[test]
    fn decision_reservation_is_one_shot() {
        let state = ApprovalState::new();
        state
            .insert_with_handle(HANDLE.into(), "server-secret".into(), request(), 1_000)
            .expect("insert fixture");
        let capability = state
            .begin_decision(HANDLE, &envelope(), 1_000)
            .expect("first reservation");
        assert_eq!(capability.token, "server-secret");
        assert_eq!(
            state.begin_decision(HANDLE, &envelope(), 1_000),
            Err(StateError::InFlight)
        );
        state.finish_decision(HANDLE, true);
        assert_eq!(
            state.get_public(HANDLE, 1_000),
            Err(StateError::Unavailable)
        );
    }

    /// Expired entries and metadata mutations fail before capability release.
    #[test]
    fn expiry_and_mutation_fail_closed() {
        let state = ApprovalState::new();
        state
            .insert_with_handle(HANDLE.into(), "server-secret".into(), request(), 1_000)
            .expect("insert fixture");
        let mut changed = envelope();
        changed.approval_id = 43;
        assert_eq!(
            state.begin_decision(HANDLE, &changed, 1_000),
            Err(StateError::Mismatch)
        );
        assert_eq!(
            state.get_public(HANDLE, 2_000),
            Err(StateError::Unavailable)
        );
    }

    /// Capacity is enforced after expired entries are reclaimed.
    #[test]
    fn capacity_is_bounded_and_expiry_reclaims_space() {
        let state = ApprovalState::with_capacity(1);
        state
            .insert_with_handle(HANDLE.into(), "first-secret".into(), request(), 1_000)
            .expect("first insert");
        let other_handle = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert_eq!(
            state.insert_with_handle(
                other_handle.into(),
                "second-secret".into(),
                request(),
                1_000
            ),
            Err(StateError::Capacity)
        );
        state
            .insert_with_handle(
                other_handle.into(),
                "second-secret".into(),
                request(),
                2_000,
            )
            .expect("expired entry reclaimed");
    }

    /// A duplicate handle never replaces the original server capability.
    #[test]
    fn collision_does_not_overwrite_live_entry() {
        let state = ApprovalState::new();
        state
            .insert_with_handle(HANDLE.into(), "original-secret".into(), request(), 1_000)
            .expect("first insert");
        assert_eq!(
            state.insert_with_handle(HANDLE.into(), "replacement-secret".into(), request(), 1_000),
            Err(StateError::Collision)
        );
        let capability = state
            .begin_decision(HANDLE, &envelope(), 1_000)
            .expect("reserve original");
        assert_eq!(capability.token, "original-secret");
    }
}
