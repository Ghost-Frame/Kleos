//! Engram credential management with encrypted storage and YubiKey support.
//!
//! This crate provides:
//! - Structured secret types (Login, ApiKey, OAuthApp, SshKey, Note, Environment)
//! - AES-256-GCM encryption for secrets at rest
//! - YubiKey HMAC-SHA1 challenge-response for key derivation
//! - Agent keys with permission scoping and revocation
//! - Audit logging for all secret access
//! - Recovery key system for lost YubiKey scenarios

pub mod agent_keys;
pub mod agent_keys_file;
pub mod audit;
pub mod crypto;
pub mod encryption;
pub mod net;
pub mod piv;
pub mod recovery;
pub mod rekey;
pub mod storage;
pub mod types;
pub mod yubikey;

pub use agent_keys::{AgentKey, AgentKeyPermissions};
#[allow(deprecated)]
pub use crypto::{
    decrypt, decrypt_recovery, decrypt_secret, derive_key, derive_key_from_passphrase,
    derive_key_legacy, encrypt, encrypt_recovery, encrypt_secret, generate_hmac_secret,
};
pub use storage::{
    delete_secret, get_secret, list_secrets, store_secret, update_secret, SecretRow,
};
pub use types::{SecretData, SecretType};

use thiserror::Error;

/// Errors returned by credential storage, crypto, and YubiKey operations.
#[derive(Debug, Error)]
pub enum CredError {
    #[error("secret not found: {0}")]
    NotFound(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("yubikey error: {0}")]
    YubiKey(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("agent key revoked: {0}")]
    KeyRevoked(String),
}

/// Crate-wide result alias using [`CredError`].
pub type Result<T> = std::result::Result<T, CredError>;

/// Map SQLite errors into the database error variant.
impl From<rusqlite::Error> for CredError {
    /// Wrap the SQLite error message.
    fn from(e: rusqlite::Error) -> Self {
        CredError::Database(e.to_string())
    }
}
