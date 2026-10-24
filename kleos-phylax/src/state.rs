//! Phylax application state, extending credd's AppState.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use kleos_credd::state::AppState;

use crate::ssh_ca_signer::{CommandSshCaSigner, SshCaSigner};

/// In-memory ECDH challenge store. Maps challenge_id -> (nonce_bytes, created_instant).
/// Entries auto-expire after CHALLENGE_TTL.
pub type ChallengeStore = DashMap<String, (Vec<u8>, std::time::Instant)>;

/// ECDH challenge time-to-live: 60 seconds.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// Default approval request TTL: 15 minutes.
pub const DEFAULT_APPROVAL_TTL_SECS: i64 = 900;

/// Exact-phone approval TTL: 3 minutes.
pub const PHONE_APPROVAL_TTL_SECS: i64 = 180;

/// Default lease TTL: 5 minutes.
pub const DEFAULT_LEASE_TTL_SECS: i64 = 300;

/// Select the shorter expiry whenever exact-phone authorization is mandatory.
pub fn approval_ttl_secs(phone_required: bool) -> i64 {
    if phone_required {
        PHONE_APPROVAL_TTL_SECS
    } else {
        DEFAULT_APPROVAL_TTL_SECS
    }
}

/// Extended state for Phylax, wrapping credd's AppState with Phylax-specific
/// fields. Derefs to AppState so existing credd handlers work unchanged.
#[derive(Clone)]
pub struct PhylaxState {
    /// Base credd application state.
    pub inner: AppState,
    /// In-memory ECDH challenge store (challenge_id -> nonce + creation time).
    pub challenges: Arc<ChallengeStore>,
    /// SSH certificate authority signer used by Phylax SSH CA endpoints.
    pub ssh_ca_signer: Arc<dyn SshCaSigner>,
    /// Whether newly created out-of-band approvals require exact-phone signatures.
    pub phone_approval_required: bool,
}

/// Builds and maintains Phylax's extended application state.
impl PhylaxState {
    /// Create PhylaxState from an existing AppState.
    pub fn from_app_state(inner: AppState) -> Self {
        Self {
            inner,
            challenges: Arc::new(DashMap::new()),
            ssh_ca_signer: Arc::new(CommandSshCaSigner),
            phone_approval_required: phone_approval_required_from_env(),
        }
    }

    /// Override the SSH CA signer, primarily for integration tests.
    pub fn with_ssh_ca_signer(mut self, signer: Arc<dyn SshCaSigner>) -> Self {
        self.ssh_ca_signer = signer;
        self
    }

    /// Override exact-phone enforcement, primarily for deterministic tests.
    pub fn with_phone_approval_required(mut self, required: bool) -> Self {
        self.phone_approval_required = required;
        self
    }

    /// Garbage-collect expired challenges from the in-memory store.
    pub fn gc_challenges(&self) {
        self.challenges
            .retain(|_, (_, created)| created.elapsed() < CHALLENGE_TTL);
    }
}

/// Parse the exact-phone enforcement flag once while constructing app state.
fn phone_approval_required_from_env() -> bool {
    std::env::var("PHYLAX_PHONE_APPROVAL_REQUIRED")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Deref to AppState so credd handlers can extract their state transparently.
impl std::ops::Deref for PhylaxState {
    /// Exposes the wrapped credd state as the deref target.
    type Target = AppState;

    /// Return the wrapped credd application state.
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// FromRef implementation so Axum extractors that need AppState work with PhylaxState.
impl axum::extract::FromRef<PhylaxState> for AppState {
    /// Clone the wrapped credd state for Axum extractors.
    fn from_ref(state: &PhylaxState) -> AppState {
        state.inner.clone()
    }
}

#[cfg(test)]
/// Application-state policy tests.
mod tests {
    use super::*;

    /// Exact-phone mode always selects the shorter authorization window.
    #[test]
    fn exact_phone_uses_short_approval_ttl() {
        assert_eq!(approval_ttl_secs(false), DEFAULT_APPROVAL_TTL_SECS);
        assert_eq!(approval_ttl_secs(true), PHONE_APPROVAL_TTL_SECS);
        const { assert!(PHONE_APPROVAL_TTL_SECS < DEFAULT_APPROVAL_TTL_SECS) };
    }
}
