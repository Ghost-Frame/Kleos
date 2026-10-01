//! At-rest database encryption key resolution.
//!
//! Shared by the `cred` CLI and the credd/phylaxd daemon so both derive a
//! byte-identical SQLCipher key for the same host configuration. The per-secret
//! `master_key` (which encrypts individual `encrypted_data` values) is a
//! separate key; this module only resolves the whole-file SQLCipher key.

use kleos_lib::config::{Config, EncryptionMode};

use crate::crypto::derive_key;

/// Resolve the optional 32-byte at-rest (SQLCipher) key for the configured
/// `EncryptionMode`.
///
/// Returns `Ok(None)` when encryption is disabled, which the caller passes
/// straight to `Database::connect_encrypted` for a plaintext open (backward
/// compatible with hosts that have not opted in).
///
/// `precomputed_response` lets a yubikey-auth caller reuse the slot-2
/// challenge-response it already obtained for the per-secret master key, so a
/// single `cred` invocation performs at most one YubiKey HMAC and does not add
/// device contention.
pub fn resolve_at_rest_key(
    config: &Config,
    precomputed_response: Option<&[u8]>,
) -> anyhow::Result<Option<[u8; 32]>> {
    match config.encryption.mode {
        // No at-rest encryption: open the database in plaintext.
        EncryptionMode::None => Ok(None),
        // YubiKey: derive the SQLCipher key from the slot-2 HMAC response,
        // reusing a precomputed response when the caller already has one.
        EncryptionMode::Yubikey => {
            tracing::info!("at-rest encryption mode: yubikey");
            // The response either comes from the caller (single shared HMAC) or
            // we perform our own challenge-response here.
            let derived = match precomputed_response {
                Some(response) => derive_key(0, b"", Some(response)),
                None => {
                    let challenge = crate::yubikey::get_or_create_challenge()
                        .map_err(|e| anyhow::anyhow!("YubiKey challenge: {e}"))?;
                    let response = crate::yubikey::challenge_response(&challenge)
                        .map_err(|e| anyhow::anyhow!("YubiKey response: {e}"))?;
                    derive_key(0, b"", Some(&response))
                }
            };
            // Copy out of the Zeroizing wrapper into the fixed array the DB layer expects.
            let key: [u8; 32] = *derived;
            Ok(Some(key))
        }
        // Keyfile / Env: defer to the shared kleos_lib resolver (no YubiKey).
        _ => kleos_lib::encryption::resolve_key(config)
            .map_err(|e| anyhow::anyhow!("encryption key: {e}")),
    }
}

// --- Persisted at-rest encryption mode -----------------------------------
//
// `~/.config/cred/encryption-mode` records which at-rest mode the vault was
// encrypted with, so a process started WITHOUT `ENGRAM_ENCRYPTION_MODE` in its
// environment (a long-running agent, or the credd/phylaxd daemon under systemd)
// still opens the vault with the correct key instead of silently opening an
// already-encrypted database as plaintext. Both the `cred` CLI and the daemon
// use these helpers so the behavior cannot drift between them.

/// Resolve the cred config directory (`~/.config/cred`), matching the cred CLI.
fn config_dir() -> std::path::PathBuf {
    directories::ProjectDirs::from("", "", "cred")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| {
            directories::BaseDirs::new()
                .map(|d| d.home_dir().join(".config").join("cred"))
                .unwrap_or_else(|| std::path::PathBuf::from(".").join(".config").join("cred"))
        })
}

/// Path to the persisted encryption-mode marker file.
fn mode_file_path() -> std::path::PathBuf {
    config_dir().join("encryption-mode")
}

/// Serialize an at-rest encryption mode to its persisted on-disk token.
fn mode_to_token(mode: &EncryptionMode) -> &'static str {
    match mode {
        EncryptionMode::None => "none",
        EncryptionMode::Keyfile => "keyfile",
        EncryptionMode::Env => "env",
        EncryptionMode::Yubikey => "yubikey",
    }
}

/// Parse a persisted token back into an encryption mode (case-insensitive,
/// trimmed). Unknown tokens yield `None` so a corrupt file fails closed to the
/// caller's default rather than guessing a mode.
fn mode_from_token(s: &str) -> Option<EncryptionMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "none" => Some(EncryptionMode::None),
        "keyfile" => Some(EncryptionMode::Keyfile),
        "env" => Some(EncryptionMode::Env),
        "yubikey" => Some(EncryptionMode::Yubikey),
        _ => None,
    }
}

/// Read the persisted at-rest encryption mode, if the marker file exists and
/// parses. Returns `None` when absent or unparseable so the caller keeps its
/// own (env-derived or default) mode.
pub fn read_persisted_encryption_mode() -> Option<EncryptionMode> {
    let raw = std::fs::read_to_string(mode_file_path()).ok()?;
    mode_from_token(&raw)
}

/// Persist the at-rest encryption mode so future processes resolve it without
/// `ENGRAM_ENCRYPTION_MODE`. Written atomically (temp file + rename). Idempotent
/// and best-effort: callers persist on every encrypted open so the marker
/// self-heals if it was deleted.
pub fn persist_encryption_mode(mode: &EncryptionMode) -> std::io::Result<()> {
    let path = mode_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}\n", mode_to_token(mode)))?;
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mode serializes to a token that parses back to the same mode.
    #[test]
    fn mode_token_roundtrips() {
        for m in [
            EncryptionMode::None,
            EncryptionMode::Keyfile,
            EncryptionMode::Env,
            EncryptionMode::Yubikey,
        ] {
            assert_eq!(mode_from_token(mode_to_token(&m)), Some(m));
        }
    }

    /// Parsing tolerates surrounding whitespace and any letter case.
    #[test]
    fn mode_token_is_case_insensitive_and_trimmed() {
        assert_eq!(
            mode_from_token("  YubiKey \n"),
            Some(EncryptionMode::Yubikey)
        );
        assert_eq!(mode_from_token("KEYFILE"), Some(EncryptionMode::Keyfile));
    }

    /// Unknown or empty tokens parse to `None` (fail closed, no guessing).
    #[test]
    fn unknown_token_is_none() {
        assert_eq!(mode_from_token("garbage"), None);
        assert_eq!(mode_from_token(""), None);
    }
}
