// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Key provider trait and supporting types for the SSH agent.

use ssh_key::public::PublicKey;
use thiserror::Error;

/// An SSH identity loaded in the agent.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// The public key in OpenSSH wire format.
    pub public_key: PublicKey,
    /// Human-readable comment (typically the key name from the vault).
    pub comment: String,
    /// Whether this key signs without requiring explicit user approval.
    pub auto_sign: bool,
}

/// Errors returned by the sign operation.
#[derive(Debug, Error)]
pub enum SignError {
    /// The key was not found in the loaded set.
    #[error("key not found")]
    KeyNotFound,
    /// The user denied the sign request.
    #[error("sign request denied")]
    Denied,
    /// The sign request timed out waiting for approval.
    #[error("sign request timed out")]
    Timeout,
    /// A cryptographic or key-format error.
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// The agent is locked.
    #[error("agent is locked")]
    Locked,
}

/// Provides cryptographic keys to the SSH agent.
///
/// Implemented by the host application (e.g., Tauri) to bridge vault state
/// into the protocol handler. The trait is object-safe and async.
pub trait KeyProvider: Send + Sync {
    /// Lists all keys currently loaded in the agent.
    fn identities(&self) -> Vec<AgentIdentity>;

    /// Signs data with the key identified by `key_blob`.
    ///
    /// `key_blob` is the public key in SSH wire format (the blob from
    /// the identities list). `data` is the data to sign. `flags` are
    /// the SSH agent protocol sign flags.
    ///
    /// Returns the signature blob on success.
    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SignError>> + Send;

    /// Called when the agent receives an SSH_AGENTC_LOCK message.
    /// The host should lock the vault.
    fn on_lock(&self) -> impl std::future::Future<Output = ()> + Send;
}
