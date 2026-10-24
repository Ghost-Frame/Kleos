//! At-rest encryption key resolution for SQLCipher.
//!
//! Resolves a 32-byte encryption key from the configured source (keyfile,
//! env var) and returns it for use as `PRAGMA key` on every SQLite
//! connection. Returns `Ok(None)` when encryption is disabled.
//!
//! **YubiKey mode** is intentionally not handled here because engram-cred
//! depends on engram-lib (circular dep). Binaries that need yubikey mode
//! must call `kleos_cred::yubikey` and `kleos_cred::crypto::derive_key`
//! directly, then pass the resulting key to `Database::connect_encrypted`.

use std::path::PathBuf;

use crate::config::{Config, EncryptionMode};
use crate::{EngError, Result};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Size of the encryption key in bytes (AES-256 = 32 bytes).
pub const KEY_SIZE: usize = 32;

/// Resolve the encryption key based on the configured mode.
///
/// Returns `Ok(None)` for `mode = none`, `Ok(Some(key))` for keyfile/env.
/// Fails fast at startup if the key source is misconfigured (missing file,
/// bad permissions, missing env var, wrong length).
///
/// For `mode = yubikey`, returns an error directing the caller to resolve
/// the key at the binary level via engram-cred.
pub fn resolve_key(config: &Config) -> Result<Option<[u8; KEY_SIZE]>> {
    match config.encryption.mode {
        EncryptionMode::None => Ok(None),
        EncryptionMode::Keyfile => resolve_keyfile().map(Some),
        EncryptionMode::Env => resolve_env().map(Some),
        EncryptionMode::Yubikey => Err(EngError::Encryption(
            "yubikey mode must be resolved at the binary level via kleos_cred; \
             call kleos_cred::yubikey::get_or_create_challenge(), \
             challenge_response(), and derive_key() then pass the key to \
             Database::connect_encrypted()"
                .into(),
        )),
        EncryptionMode::Custody => Err(EngError::Encryption(
            "custody mode must be resolved at the binary level via \
             kleos_cred::encryption::resolve_at_rest_key (YubiKey slot 1)"
                .into(),
        )),
    }
}

/// Format a 32-byte key as the SQLCipher `PRAGMA key` value.
///
/// SQLCipher raw key mode requires the value in double quotes:
/// `PRAGMA key = "x'<hex>'"`. The double quotes tell SQLCipher to
/// interpret the hex literal as a raw 256-bit key, bypassing the
/// PBKDF2 derivation pass.
pub fn format_pragma_key(key: &[u8; KEY_SIZE]) -> zeroize::Zeroizing<String> {
    // The returned string embeds the raw key as hex. Wrap it in Zeroizing so
    // the caller's copy is scrubbed on drop, and scrub the hex intermediate
    // here so no unzeroized copy of the key lingers on the heap.
    let mut hex_key = hex::encode(key);
    let pragma = zeroize::Zeroizing::new(format!("\"x'{hex_key}'\""));
    hex_key.zeroize();
    pragma
}

// ---------------------------------------------------------------------------
// mode = keyfile
// ---------------------------------------------------------------------------

/// Read a raw 32-byte key from `$XDG_CONFIG_HOME/engram/dbkey` (or
/// `~/.config/engram/dbkey`). Rejects files with group/world-readable
/// permissions on Unix.
fn resolve_keyfile() -> Result<[u8; KEY_SIZE]> {
    let path = keyfile_path();

    if !path.exists() {
        return Err(EngError::Encryption(format!(
            "keyfile not found: {} -- create a 32-byte key with: \
             head -c 32 /dev/urandom > {} && chmod 600 {}",
            path.display(),
            path.display(),
            path.display(),
        )));
    }

    check_keyfile_permissions(&path)?;

    let mut data = std::fs::read(&path).map_err(|e| {
        EngError::Encryption(format!("failed to read keyfile {}: {}", path.display(), e))
    })?;

    let data_len = data.len();
    if data_len != KEY_SIZE {
        data.zeroize();
        return Err(EngError::Encryption(format!(
            "keyfile {} is {} bytes, expected exactly {} bytes",
            path.display(),
            data_len,
            KEY_SIZE,
        )));
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&data);
    // Scrub the file buffer; the key now lives only in `key`.
    data.zeroize();
    Ok(key)
}

/// Keyfile path: `$XDG_CONFIG_HOME/engram/dbkey` or `~/.config/engram/dbkey`.
fn keyfile_path() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::config_dir().unwrap_or_else(|| PathBuf::from(".config")))
        .join("engram")
        .join("dbkey")
}

/// On Unix, reject keyfiles readable by group or others (mode & 0o077 != 0).
#[cfg(unix)]
fn check_keyfile_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let perms = std::fs::metadata(path)
        .map_err(|e| {
            EngError::Encryption(format!("failed to stat keyfile {}: {}", path.display(), e))
        })?
        .permissions();

    if perms.mode() & 0o077 != 0 {
        return Err(EngError::Encryption(format!(
            "keyfile {} has insecure permissions ({:04o}), run: chmod 600 {}",
            path.display(),
            perms.mode() & 0o7777,
            path.display(),
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
fn check_keyfile_permissions(_path: &PathBuf) -> Result<()> {
    // Windows: no permission check (NTFS ACLs are different).
    Ok(())
}

// ---------------------------------------------------------------------------
// mode = env
// ---------------------------------------------------------------------------

/// Read `ENGRAM_DB_KEY` env var and hex-decode to 32 bytes.
fn resolve_env() -> Result<[u8; KEY_SIZE]> {
    let hex_str = SecretString::new(crate::kleos_env("DB_KEY").map_err(|_| {
        EngError::Encryption(
            "ENGRAM_DB_KEY environment variable not set (encryption.mode = env requires it)".into(),
        )
    })?);

    let mut bytes = hex::decode(hex_str.expose_secret().trim()).map_err(|e| {
        EngError::Encryption(format!(
            "ENGRAM_DB_KEY is not valid hex: {} -- expected 64 hex characters (32 bytes)",
            e
        ))
    })?;

    if bytes.len() != KEY_SIZE {
        return Err(EngError::Encryption(format!(
            "ENGRAM_DB_KEY is {} bytes, expected {} (64 hex chars)",
            bytes.len(),
            KEY_SIZE,
        )));
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionConfig, EncryptionMode};

    fn config_with_mode(mode: EncryptionMode) -> Config {
        Config {
            encryption: EncryptionConfig { mode },
            ..Config::default()
        }
    }

    #[test]
    fn resolve_key_none_returns_none() {
        let config = config_with_mode(EncryptionMode::None);
        let result = resolve_key(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn resolve_key_yubikey_returns_error() {
        let config = config_with_mode(EncryptionMode::Yubikey);
        let result = resolve_key(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("yubikey mode must be resolved"));
    }

    #[test]
    fn resolve_env_missing_var_fails() {
        // Ensure the var is unset for this test.
        std::env::remove_var("ENGRAM_DB_KEY");
        let result = resolve_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not set"));
    }

    #[test]
    fn resolve_env_bad_hex_fails() {
        std::env::set_var("ENGRAM_DB_KEY", "not-hex-at-all");
        let result = resolve_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not valid hex"));
        std::env::remove_var("ENGRAM_DB_KEY");
    }

    #[test]
    fn resolve_env_wrong_length_fails() {
        // 16 bytes = 32 hex chars, but we need 32 bytes = 64 hex chars.
        std::env::set_var("ENGRAM_DB_KEY", "aa".repeat(16));
        let result = resolve_env();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("16 bytes, expected 32"));
        std::env::remove_var("ENGRAM_DB_KEY");
    }

    #[test]
    fn resolve_env_valid_key() {
        let key_hex = "aa".repeat(32); // 64 hex chars = 32 bytes
        std::env::set_var("ENGRAM_DB_KEY", &key_hex);
        let result = resolve_env().unwrap();
        assert_eq!(result, [0xaa; 32]);
        std::env::remove_var("ENGRAM_DB_KEY");
    }

    #[test]
    fn resolve_keyfile_missing_file_fails() {
        // Use a temp dir so XDG_CONFIG_HOME points somewhere with no dbkey file.
        let dir = std::env::temp_dir().join(format!("engram-test-{}", uuid::Uuid::new_v4()));
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        let result = resolve_keyfile();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("keyfile not found"));
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn resolve_keyfile_wrong_size_fails() {
        let dir = std::env::temp_dir().join(format!("engram-test-{}", uuid::Uuid::new_v4()));
        let engram_dir = dir.join("engram");
        std::fs::create_dir_all(&engram_dir).unwrap();
        let path = engram_dir.join("dbkey");
        std::fs::write(&path, vec![0u8; 16]).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::env::set_var("XDG_CONFIG_HOME", &dir);
        let result = resolve_keyfile();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("16 bytes, expected exactly 32"));
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_keyfile_valid() {
        let dir = std::env::temp_dir().join(format!("engram-test-{}", uuid::Uuid::new_v4()));
        let engram_dir = dir.join("engram");
        std::fs::create_dir_all(&engram_dir).unwrap();

        let key_data = [0xbbu8; 32];
        let path = engram_dir.join("dbkey");
        std::fs::write(&path, key_data).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::env::set_var("XDG_CONFIG_HOME", &dir);
        let result = resolve_keyfile().unwrap();
        assert_eq!(result, [0xbb; 32]);
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_keyfile_bad_permissions_fails() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("engram-test-{}", uuid::Uuid::new_v4()));
        let engram_dir = dir.join("engram");
        std::fs::create_dir_all(&engram_dir).unwrap();

        let path = engram_dir.join("dbkey");
        std::fs::write(&path, [0u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &dir);
        let result = resolve_keyfile();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("insecure permissions"));
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_pragma_key_produces_sqlcipher_raw_key() {
        let key = [0xaa; 32];
        let pragma = format_pragma_key(&key);
        assert!(pragma.starts_with("\"x'"));
        assert!(pragma.ends_with("'\""));
        // "x'" + 64 hex + "'"  = 3 + 64 + 2 = 69
        assert_eq!(pragma.len(), 69);
    }
}
