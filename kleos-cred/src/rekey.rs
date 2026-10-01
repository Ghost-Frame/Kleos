//! Master-key rotation for the local cred cache.
//!
//! Re-encrypts every `cred_secrets` row and the optional `bootstrap.enc` blob
//! from one master key to another. The database is opened directly with
//! rusqlite so no Kleos schema migration runs against a live vault, and all
//! row updates happen in a single `BEGIN IMMEDIATE` transaction that is rolled
//! back on any failure. Plaintext never leaves `Zeroizing` buffers and nothing
//! in this module prints or returns secret material.

use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rand::TryRngCore;
use rusqlite::{params, Connection, TransactionBehavior};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::{decrypt, decrypt_recovery, encrypt, encrypt_recovery, KEY_SIZE, NONCE_SIZE};
use crate::{CredError, Result};

/// Magic prefix of the bootstrap blob format (`CBv1`), shared with credd.
pub const BOOTSTRAP_MAGIC: &[u8; 4] = b"CBv1";

/// Outcome of a database rekey pass. Contains counts and identifiers only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyReport {
    /// Rows examined in `cred_secrets`.
    pub rows: usize,
    /// Rows re-encrypted from the old key to the new key.
    pub rotated: usize,
    /// Rows that already decrypted only with the new key and were left unchanged.
    pub already_new: usize,
    /// Whether the new ciphertext was committed (false for dry runs).
    pub committed: bool,
}

/// Outcome of a bootstrap blob rekey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// No blob exists at the path.
    Absent,
    /// The blob decrypts with the old key; nothing was written (dry run).
    Verified,
    /// The blob was rewritten under the new key; the original was preserved at this path.
    Rewrapped { backup: PathBuf },
}

/// Reject a rotation whose old and new keys are identical.
fn ensure_distinct(old_key: &[u8; KEY_SIZE], new_key: &[u8; KEY_SIZE]) -> Result<()> {
    if bool::from(old_key.ct_eq(new_key)) {
        return Err(CredError::InvalidInput(
            "new master key is identical to the current key; nothing to rotate".into(),
        ));
    }
    Ok(())
}

/// Decrypt one row's ciphertext with its stored nonce, returning plaintext bytes.
fn open_row(key: &[u8; KEY_SIZE], ciphertext: &[u8], nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_SIZE {
        return Err(CredError::Decryption(
            "stored nonce has the wrong length".into(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CredError::Decryption(format!("invalid key: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| CredError::Decryption("authentication tag mismatch".into()))
}

/// Encrypt plaintext bytes for one row under a fresh random nonce.
fn seal_row(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CredError::Encryption(format!("invalid key: {e}")))?;
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CredError::Encryption(format!("CSPRNG unavailable: {e}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| CredError::Encryption(format!("encryption failed: {e}")))?;
    Ok((ciphertext, nonce))
}

/// Map a rusqlite error into the crate error type.
fn db_err(error: rusqlite::Error) -> CredError {
    CredError::Database(error.to_string())
}

/// One stored secret row loaded for rotation.
struct SecretRow {
    /// Row primary key.
    id: i64,
    /// Category (service) for error reporting.
    category: String,
    /// Secret name for error reporting.
    name: String,
    /// Current ciphertext.
    ciphertext: Vec<u8>,
    /// Current nonce.
    nonce: Vec<u8>,
}

/// Re-encrypt every `cred_secrets` row from `old_key` to `new_key`.
///
/// Every row must decrypt with `old_key` and its new ciphertext must decrypt
/// back to identical bytes under `new_key` before anything is written. Any
/// failure rolls the whole transaction back and names the failing rows. With
/// `dry_run` the old-key check runs and the transaction is rolled back.
pub fn rekey_database(
    db_path: &Path,
    old_key: &[u8; KEY_SIZE],
    new_key: &[u8; KEY_SIZE],
    dry_run: bool,
) -> Result<RekeyReport> {
    ensure_distinct(old_key, new_key)?;
    let mut conn = Connection::open(db_path).map_err(db_err)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(db_err)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(db_err)?;

    let rows: Vec<SecretRow> = {
        let mut statement = tx
            .prepare(
                "SELECT id, category, name, encrypted_data, nonce FROM cred_secrets ORDER BY id",
            )
            .map_err(db_err)?;
        let mapped = statement
            .query_map([], |row| {
                Ok(SecretRow {
                    id: row.get(0)?,
                    category: row.get(1)?,
                    name: row.get(2)?,
                    ciphertext: row.get(3)?,
                    nonce: row.get(4)?,
                })
            })
            .map_err(db_err)?;
        mapped
            .collect::<std::result::Result<_, _>>()
            .map_err(db_err)?
    };

    let mut failures = Vec::new();
    let mut already_new = 0usize;
    let mut resealed = Vec::with_capacity(rows.len());
    for row in &rows {
        let plaintext = match open_row(old_key, &row.ciphertext, &row.nonce) {
            Ok(plaintext) => plaintext,
            Err(_) if open_row(new_key, &row.ciphertext, &row.nonce).is_ok() => {
                // Written earlier under the target key (mixed vault); keep as is.
                already_new += 1;
                continue;
            }
            Err(_) => {
                failures.push(format!("{}/{}", row.category, row.name));
                continue;
            }
        };
        let (ciphertext, nonce) = seal_row(new_key, &plaintext)?;
        let roundtrip = open_row(new_key, &ciphertext, &nonce)?;
        if !bool::from(roundtrip.as_slice().ct_eq(plaintext.as_slice())) {
            failures.push(format!("{}/{} (verify)", row.category, row.name));
            continue;
        }
        resealed.push((row.id, ciphertext, nonce));
    }

    if !failures.is_empty() {
        return Err(CredError::Decryption(format!(
            "{} of {} rows decrypt with neither the current nor the target key; nothing was changed: {}",
            failures.len(),
            rows.len(),
            failures.join(", ")
        )));
    }

    if dry_run {
        tx.rollback().map_err(db_err)?;
        return Ok(RekeyReport {
            rows: rows.len(),
            rotated: resealed.len(),
            already_new,
            committed: false,
        });
    }

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    for (id, ciphertext, nonce) in &resealed {
        let changed = tx
            .execute(
                "UPDATE cred_secrets SET encrypted_data = ?1, nonce = ?2, updated_at = ?3 WHERE id = ?4",
                params![ciphertext, nonce.as_slice(), now, id],
            )
            .map_err(db_err)?;
        if changed != 1 {
            return Err(CredError::Database(format!(
                "row {id} vanished during rekey; rolled back"
            )));
        }
    }
    tx.commit().map_err(db_err)?;
    Ok(RekeyReport {
        rows: rows.len(),
        rotated: resealed.len(),
        already_new,
        committed: true,
    })
}

/// Count rows that decrypt under `key`, returning (decryptable, total).
pub fn count_decryptable(db_path: &Path, key: &[u8; KEY_SIZE]) -> Result<(usize, usize)> {
    let conn = Connection::open(db_path).map_err(db_err)?;
    let mut statement = conn
        .prepare("SELECT encrypted_data, nonce FROM cred_secrets")
        .map_err(db_err)?;
    let mut rows = statement.query([]).map_err(db_err)?;
    let (mut ok, mut total) = (0usize, 0usize);
    while let Some(row) = rows.next().map_err(db_err)? {
        total += 1;
        let ciphertext: Vec<u8> = row.get(0).map_err(db_err)?;
        let nonce: Vec<u8> = row.get(1).map_err(db_err)?;
        if open_row(key, &ciphertext, &nonce).is_ok() {
            ok += 1;
        }
    }
    Ok((ok, total))
}

/// Write bytes to `path` atomically with mode 0600 via a synced temp file.
fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let io_err =
        |e: std::io::Error| CredError::Encryption(format!("write {}: {e}", path.display()));
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(io_err)?;
        file.write_all(bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
    }
    std::fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

/// Re-wrap the bootstrap blob at `path` from `old_key` to `new_key`.
///
/// The original bytes are preserved at `<path>.pre-rekey` (mode 0600) before
/// the new blob atomically replaces it. A missing blob is not an error.
pub fn rekey_bootstrap(
    path: &Path,
    old_key: &[u8; KEY_SIZE],
    new_key: &[u8; KEY_SIZE],
    dry_run: bool,
) -> Result<BootstrapOutcome> {
    ensure_distinct(old_key, new_key)?;
    let original = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BootstrapOutcome::Absent)
        }
        Err(error) => {
            return Err(CredError::Decryption(format!(
                "read {}: {error}",
                path.display()
            )))
        }
    };
    if original.len() < BOOTSTRAP_MAGIC.len()
        || &original[..BOOTSTRAP_MAGIC.len()] != BOOTSTRAP_MAGIC
    {
        return Err(CredError::Decryption(
            "bootstrap blob has an unexpected format".into(),
        ));
    }
    let plaintext = Zeroizing::new(
        decrypt(old_key, &original[BOOTSTRAP_MAGIC.len()..]).map_err(|_| {
            CredError::Decryption("bootstrap blob does not decrypt with the current key".into())
        })?,
    );
    if dry_run {
        return Ok(BootstrapOutcome::Verified);
    }
    let mut blob = BOOTSTRAP_MAGIC.to_vec();
    blob.extend_from_slice(&encrypt(new_key, &plaintext)?);
    let check = Zeroizing::new(decrypt(new_key, &blob[BOOTSTRAP_MAGIC.len()..])?);
    if !bool::from(check.as_slice().ct_eq(plaintext.as_slice())) {
        return Err(CredError::Encryption(
            "bootstrap re-wrap verification failed".into(),
        ));
    }
    let backup = PathBuf::from(format!("{}.pre-rekey", path.display()));
    if backup.exists() {
        return Err(CredError::InvalidInput(format!(
            "{} already exists; move it aside before rotating again",
            backup.display()
        )));
    }
    write_private_atomic(&backup, &original)?;
    write_private_atomic(path, &blob)?;
    Ok(BootstrapOutcome::Rewrapped { backup })
}

/// Magic prefix of a passphrase-wrapped master-key recovery kit (`CRMK1`).
pub const RECOVERY_KIT_MAGIC: &[u8; 5] = b"CRMK1";

/// Minimum accepted recovery passphrase length in characters.
pub const MIN_RECOVERY_PASSPHRASE_CHARS: usize = 12;

/// Wrap the vault master key under a passphrase (Argon2id + AES-256-GCM).
///
/// The result is `CRMK1 || salt || nonce || ciphertext+tag` and is safe to
/// store offline; it is useless without the passphrase.
pub fn wrap_master_key(passphrase: &str, master_key: &[u8; KEY_SIZE]) -> Result<Vec<u8>> {
    if passphrase.chars().count() < MIN_RECOVERY_PASSPHRASE_CHARS {
        return Err(CredError::InvalidInput(format!(
            "recovery passphrase must be at least {MIN_RECOVERY_PASSPHRASE_CHARS} characters"
        )));
    }
    let mut blob = RECOVERY_KIT_MAGIC.to_vec();
    blob.extend_from_slice(&encrypt_recovery(passphrase, master_key)?);
    Ok(blob)
}

/// Recover the vault master key from a recovery kit and its passphrase.
pub fn unwrap_master_key(passphrase: &str, blob: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    if blob.len() < RECOVERY_KIT_MAGIC.len()
        || &blob[..RECOVERY_KIT_MAGIC.len()] != RECOVERY_KIT_MAGIC
    {
        return Err(CredError::InvalidInput(
            "not a cred master-key recovery kit".into(),
        ));
    }
    let plaintext = Zeroizing::new(
        decrypt_recovery(passphrase, &blob[RECOVERY_KIT_MAGIC.len()..]).map_err(|_| {
            CredError::Decryption("wrong passphrase or corrupted recovery kit".into())
        })?,
    );
    if plaintext.len() != KEY_SIZE {
        return Err(CredError::Decryption(
            "recovery kit holds a key of the wrong size".into(),
        ));
    }
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Return whether two master keys are equal, in constant time.
pub fn keys_match(left: &[u8; KEY_SIZE], right: &[u8; KEY_SIZE]) -> bool {
    bool::from(left.ct_eq(right))
}

/// Write `bytes` to a new private (0600) file, refusing to overwrite anything.
pub fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let io_err =
        |e: std::io::Error| CredError::InvalidInput(format!("write {}: {e}", path.display()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_err)?;
    file.write_all(bytes).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    Ok(())
}

/// Outcome of rotating a whole vault file to new database and secret keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRekeyReport {
    /// Rows in `cred_secrets`.
    pub rows: usize,
    /// Rows re-encrypted from the old secret key.
    pub rotated: usize,
    /// Rows already under the new secret key.
    pub already_new: usize,
    /// Where the original vault file was preserved, when the swap happened.
    pub backup: Option<PathBuf>,
}

/// Build the SQLCipher key clause for a raw 32-byte key, or plaintext when `None`.
fn sqlcipher_key_clause(key: Option<&[u8; KEY_SIZE]>) -> Zeroizing<String> {
    match key {
        Some(key) => Zeroizing::new(format!("\"x'{}'\"", hex::encode(key))),
        None => Zeroizing::new("''".to_string()),
    }
}

/// Open a vault file, applying the at-rest key when one is given, and prove it is readable.
pub fn open_vault(path: &Path, at_rest: Option<&[u8; KEY_SIZE]>) -> Result<Connection> {
    let conn = Connection::open(path).map_err(db_err)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(db_err)?;
    if at_rest.is_some() {
        let pragma = Zeroizing::new(format!(
            "PRAGMA key = {};",
            sqlcipher_key_clause(at_rest).as_str()
        ));
        conn.execute_batch(&pragma).map_err(db_err)?;
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map_err(|_| {
        CredError::Decryption(format!(
            "{} does not open with the given at-rest key",
            path.display()
        ))
    })?;
    Ok(conn)
}

/// Re-encrypt every row of `table` (`cred_secrets` or `schema.cred_secrets`) in place.
///
/// Returns (rows, rotated, already_new). Any row readable by neither key, or
/// whose new ciphertext fails to round-trip, aborts with an error naming it.
fn rotate_table(
    conn: &Connection,
    table: &str,
    old_key: &[u8; KEY_SIZE],
    new_key: &[u8; KEY_SIZE],
) -> Result<(usize, usize, usize)> {
    let rows: Vec<SecretRow> = {
        let mut statement = conn
            .prepare(&format!(
                "SELECT id, category, name, encrypted_data, nonce FROM {table} ORDER BY id"
            ))
            .map_err(db_err)?;
        let mapped = statement
            .query_map([], |row| {
                Ok(SecretRow {
                    id: row.get(0)?,
                    category: row.get(1)?,
                    name: row.get(2)?,
                    ciphertext: row.get(3)?,
                    nonce: row.get(4)?,
                })
            })
            .map_err(db_err)?;
        mapped
            .collect::<std::result::Result<_, _>>()
            .map_err(db_err)?
    };
    let mut failures = Vec::new();
    let mut already_new = 0usize;
    let mut resealed = Vec::with_capacity(rows.len());
    for row in &rows {
        let plaintext = match open_row(old_key, &row.ciphertext, &row.nonce) {
            Ok(plaintext) => plaintext,
            Err(_) if open_row(new_key, &row.ciphertext, &row.nonce).is_ok() => {
                already_new += 1;
                continue;
            }
            Err(_) => {
                failures.push(format!("{}/{}", row.category, row.name));
                continue;
            }
        };
        let (ciphertext, nonce) = seal_row(new_key, &plaintext)?;
        let roundtrip = open_row(new_key, &ciphertext, &nonce)?;
        if !bool::from(roundtrip.as_slice().ct_eq(plaintext.as_slice())) {
            failures.push(format!("{}/{} (verify)", row.category, row.name));
            continue;
        }
        resealed.push((row.id, ciphertext, nonce));
    }
    if !failures.is_empty() {
        return Err(CredError::Decryption(format!(
            "{} of {} rows decrypt with neither key; nothing was changed: {}",
            failures.len(),
            rows.len(),
            failures.join(", ")
        )));
    }
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    for (id, ciphertext, nonce) in &resealed {
        let changed = conn
            .execute(
                &format!("UPDATE {table} SET encrypted_data = ?1, nonce = ?2, updated_at = ?3 WHERE id = ?4"),
                params![ciphertext, nonce.as_slice(), now, id],
            )
            .map_err(db_err)?;
        if changed != 1 {
            return Err(CredError::Database(format!(
                "row {id} vanished during rekey"
            )));
        }
    }
    Ok((rows.len(), resealed.len(), already_new))
}

/// Count `cred_secrets` rows that decrypt under `key` in a vault opened with `at_rest`.
pub fn count_decryptable_in(
    db_path: &Path,
    at_rest: Option<&[u8; KEY_SIZE]>,
    key: &[u8; KEY_SIZE],
) -> Result<(usize, usize)> {
    let conn = open_vault(db_path, at_rest)?;
    let mut statement = conn
        .prepare("SELECT encrypted_data, nonce FROM cred_secrets")
        .map_err(db_err)?;
    let mut rows = statement.query([]).map_err(db_err)?;
    let (mut ok, mut total) = (0usize, 0usize);
    while let Some(row) = rows.next().map_err(db_err)? {
        total += 1;
        let ciphertext: Vec<u8> = row.get(0).map_err(db_err)?;
        let nonce: Vec<u8> = row.get(1).map_err(db_err)?;
        if open_row(key, &ciphertext, &nonce).is_ok() {
            ok += 1;
        }
    }
    Ok((ok, total))
}

/// Rotate a whole vault file to a new at-rest key and a new secret key.
///
/// The original file is only read: everything is exported into
/// `<db>.rekeying` under `new_at_rest`, rows are re-encrypted inside that
/// copy, and the copy is verified before it replaces the original. The
/// original (plus its checkpointed WAL/SHM) is kept at `<db>.pre-rekey`.
/// With `dry_run` the verified copy is discarded and nothing changes.
pub fn rekey_vault_file(
    db_path: &Path,
    old_at_rest: Option<&[u8; KEY_SIZE]>,
    new_at_rest: Option<&[u8; KEY_SIZE]>,
    old_key: &[u8; KEY_SIZE],
    new_key: &[u8; KEY_SIZE],
    dry_run: bool,
) -> Result<VaultRekeyReport> {
    ensure_distinct(old_key, new_key)?;
    let tmp = PathBuf::from(format!("{}.rekeying", db_path.display()));
    let backup = PathBuf::from(format!("{}.pre-rekey", db_path.display()));
    if tmp.exists() || (!dry_run && backup.exists()) {
        return Err(CredError::InvalidInput(format!(
            "{} or {} already exists; move it aside first",
            tmp.display(),
            backup.display()
        )));
    }
    let (rows, rotated, already_new) = {
        let conn = open_vault(db_path, old_at_rest)?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .map_err(db_err)?;
        let attach = Zeroizing::new(format!(
            "ATTACH DATABASE '{}' AS rekeyed KEY {};",
            tmp.display().to_string().replace('\'', "''"),
            sqlcipher_key_clause(new_at_rest).as_str()
        ));
        conn.execute_batch(&attach).map_err(db_err)?;
        let result = (|| {
            conn.query_row("SELECT sqlcipher_export('rekeyed')", [], |_| Ok(()))
                .map_err(db_err)?;
            conn.execute_batch("BEGIN IMMEDIATE").map_err(db_err)?;
            match rotate_table(&conn, "rekeyed.cred_secrets", old_key, new_key) {
                Ok(counts) => {
                    conn.execute_batch("COMMIT").map_err(db_err)?;
                    Ok(counts)
                }
                Err(error) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(error)
                }
            }
        })();
        let _ = conn.execute_batch("DETACH DATABASE rekeyed");
        match result {
            Ok(counts) => counts,
            Err(error) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(error);
            }
        }
    };
    let (ok, total) = count_decryptable_in(&tmp, new_at_rest, new_key)?;
    if ok != total || total != rows {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredError::Encryption(format!(
            "rekeyed copy failed verification ({ok}/{total} of {rows}); original untouched"
        )));
    }
    if dry_run {
        std::fs::remove_file(&tmp)
            .map_err(|e| CredError::Database(format!("remove {}: {e}", tmp.display())))?;
        return Ok(VaultRekeyReport {
            rows,
            rotated,
            already_new,
            backup: None,
        });
    }
    let io_err = |e: std::io::Error| CredError::Database(format!("swap vault files: {e}"));
    std::fs::rename(db_path, &backup).map_err(io_err)?;
    for suffix in ["-wal", "-shm"] {
        let side = PathBuf::from(format!("{}{suffix}", db_path.display()));
        if side.exists() {
            std::fs::rename(&side, format!("{}{suffix}", backup.display())).map_err(io_err)?;
        }
    }
    if let Err(error) = std::fs::rename(&tmp, db_path) {
        let _ = std::fs::rename(&backup, db_path);
        return Err(io_err(error));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(VaultRekeyReport {
        rows,
        rotated,
        already_new,
        backup: Some(backup),
    })
}

/// Replace the challenge file at `path` with `challenge`, keeping the old one at `<path>.pre-rekey`.
pub fn install_challenge(path: &Path, challenge: &[u8]) -> Result<PathBuf> {
    let backup = PathBuf::from(format!("{}.pre-rekey", path.display()));
    let original = std::fs::read(path)
        .map_err(|e| CredError::YubiKey(format!("read {}: {e}", path.display())))?;
    write_new_private_file(&backup, &original)?;
    write_private_atomic(path, challenge)?;
    Ok(backup)
}

/// Outcome of merging another vault (or central entries) into this one. Names only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Secrets copied in because this vault lacked them.
    pub imported: Vec<String>,
    /// Secrets present in both with identical values.
    pub identical: usize,
    /// Secrets present in both whose values differ (left unchanged here).
    pub differing: Vec<String>,
    /// Source secrets that did not decrypt with the key and were skipped.
    pub undecryptable: Vec<String>,
}

/// One full row read from a vault for merging.
struct FullRow {
    /// Category/service.
    category: String,
    /// Secret name.
    name: String,
    /// Stored secret type label.
    secret_type: String,
    /// Ciphertext.
    ciphertext: Vec<u8>,
    /// Nonce.
    nonce: Vec<u8>,
    /// Creation timestamp.
    created_at: String,
    /// Update timestamp.
    updated_at: String,
}

/// Read every user-1 secret row from `table`.
fn read_full_rows(conn: &Connection, table: &str) -> Result<Vec<FullRow>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT category, name, secret_type, encrypted_data, nonce, created_at, updated_at
             FROM {table} WHERE user_id = 1 ORDER BY id"
        ))
        .map_err(db_err)?;
    let rows = statement
        .query_map([], |row| {
            Ok(FullRow {
                category: row.get(0)?,
                name: row.get(1)?,
                secret_type: row.get(2)?,
                ciphertext: row.get(3)?,
                nonce: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .map_err(db_err)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_err)?;
    Ok(rows)
}

/// Merge another vault file that uses the same secret key into this one.
///
/// Missing secrets are copied verbatim (ciphertext unchanged, after proving it
/// decrypts with `key`). Secrets in both are compared by value in constant
/// time and never overwritten; differing names are reported for the operator.
pub fn merge_vault(
    local_path: &Path,
    local_at_rest: Option<&[u8; KEY_SIZE]>,
    other_path: &Path,
    other_at_rest: Option<&[u8; KEY_SIZE]>,
    key: &[u8; KEY_SIZE],
    dry_run: bool,
) -> Result<MergeReport> {
    let conn = open_vault(local_path, local_at_rest)?;
    let attach = Zeroizing::new(format!(
        "ATTACH DATABASE '{}' AS other KEY {};",
        other_path.display().to_string().replace('\'', "''"),
        sqlcipher_key_clause(other_at_rest).as_str()
    ));
    conn.execute_batch(&attach).map_err(db_err)?;
    let result = (|| {
        let local: std::collections::HashMap<(String, String), FullRow> =
            read_full_rows(&conn, "main.cred_secrets")?
                .into_iter()
                .map(|row| ((row.category.clone(), row.name.clone()), row))
                .collect();
        let other = read_full_rows(&conn, "other.cred_secrets").map_err(|_| {
            CredError::Decryption(
                "the other vault does not open with this host's at-rest key".into(),
            )
        })?;
        let mut report = MergeReport::default();
        conn.execute_batch("BEGIN IMMEDIATE").map_err(db_err)?;
        for row in &other {
            let label = format!("{}/{}", row.category, row.name);
            let Ok(other_plain) = open_row(key, &row.ciphertext, &row.nonce) else {
                report.undecryptable.push(label);
                continue;
            };
            match local.get(&(row.category.clone(), row.name.clone())) {
                Some(mine) => match open_row(key, &mine.ciphertext, &mine.nonce) {
                    Ok(mine_plain)
                        if bool::from(mine_plain.as_slice().ct_eq(other_plain.as_slice())) =>
                    {
                        report.identical += 1
                    }
                    _ => report.differing.push(label),
                },
                None => {
                    conn.execute(
                        "INSERT INTO main.cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
                         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![row.name, row.category, row.secret_type, row.ciphertext, row.nonce, row.created_at, row.updated_at],
                    )
                    .map_err(db_err)?;
                    report.imported.push(label);
                }
            }
        }
        conn.execute_batch(if dry_run { "ROLLBACK" } else { "COMMIT" })
            .map_err(db_err)?;
        Ok(report)
    })();
    if result.is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    let _ = conn.execute_batch("DETACH DATABASE other");
    result
}

/// Import central v3 entries that decrypt with `source_key` and are missing locally.
///
/// Each value is re-encrypted under `local_key`; the secret type comes from
/// the decrypted record's `type` tag. Existing local names are never touched.
pub fn import_v3_entries(
    local_path: &Path,
    local_at_rest: Option<&[u8; KEY_SIZE]>,
    local_key: &[u8; KEY_SIZE],
    entries: &[V3Entry],
    source_key: &[u8; KEY_SIZE],
    dry_run: bool,
) -> Result<MergeReport> {
    let conn = open_vault(local_path, local_at_rest)?;
    let mut existing: std::collections::HashSet<(String, String)> =
        read_full_rows(&conn, "main.cred_secrets")?
            .into_iter()
            .map(|row| (row.category, row.name))
            .collect();
    let mut report = MergeReport::default();
    conn.execute_batch("BEGIN IMMEDIATE").map_err(db_err)?;
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    for entry in entries {
        let label = format!("{}/{}", entry.category, entry.name);
        let Ok(plaintext) = decrypt(source_key, &entry.blob).map(Zeroizing::new) else {
            report.undecryptable.push(label);
            continue;
        };
        if existing.contains(&(entry.category.clone(), entry.name.clone())) {
            report.identical += 1;
            continue;
        }
        let secret_type = serde_json::from_slice::<serde_json::Value>(&plaintext)
            .ok()
            .and_then(|value| {
                value
                    .get("type")
                    .and_then(|t| t.as_str())
                    .map(str::to_string)
            })
            .ok_or_else(|| {
                CredError::Decryption(format!("{label} is not a recognizable secret record"))
            })?;
        let (ciphertext, nonce) = seal_row(local_key, &plaintext)?;
        conn.execute(
            "INSERT INTO main.cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![entry.name, entry.category, secret_type, ciphertext, nonce.as_slice(), now],
        )
        .map_err(db_err)?;
        existing.insert((entry.category.clone(), entry.name.clone()));
        report.imported.push(label);
    }
    conn.execute_batch(if dry_run { "ROLLBACK" } else { "COMMIT" })
        .map_err(db_err)?;
    Ok(report)
}

/// Whether a category or name is safe inside the `[CRED:v3] cat/name = hex` format.
///
/// Mirrors phylaxd's `kleos_sync::is_safe_ident`: no `/`, so it cannot collide.
pub fn is_v3_safe_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Whether a name is safe in the v3 format: the category alphabet plus inner `/`.
///
/// Mirrors phylaxd's `kleos_sync::is_safe_v3_name`. Only the category must stay
/// slash-free; a slash inside the name cannot collide with another entry.
pub fn is_v3_safe_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.ends_with('/')
        && !s.contains("//")
        && s.split('/').all(is_v3_safe_ident)
}

/// Build central v3 contents for every local secret, re-encrypted under `key`.
///
/// Returns (contents, skipped) where skipped lists names unsafe for the v3
/// format or not decryptable with `key`. Contents are ciphertext only.
pub fn export_v3_contents(
    db_path: &Path,
    at_rest: Option<&[u8; KEY_SIZE]>,
    key: &[u8; KEY_SIZE],
) -> Result<(Vec<String>, Vec<String>)> {
    let conn = open_vault(db_path, at_rest)?;
    let mut contents = Vec::new();
    let mut skipped = Vec::new();
    for row in read_full_rows(&conn, "main.cred_secrets")? {
        let label = format!("{}/{}", row.category, row.name);
        if !is_v3_safe_name(&row.category) || !is_v3_safe_name(&row.name) {
            skipped.push(format!("{label} (name not v3-safe)"));
            continue;
        }
        let Ok(plaintext) = open_row(key, &row.ciphertext, &row.nonce) else {
            skipped.push(format!("{label} (does not decrypt)"));
            continue;
        };
        let blob = encrypt(key, &plaintext)?;
        contents.push(format!(
            "{V3_PREFIX}{}/{} = {}",
            row.category.replace('/', "%2F"),
            row.name,
            hex::encode(blob)
        ));
    }
    Ok((contents, skipped))
}

/// Content prefix of central-vault (CRED:v3) Kleos memories.
pub const V3_PREFIX: &str = "[CRED:v3] ";

/// One central-vault entry parsed from a Kleos memory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Entry {
    /// Kleos memory id of the entry, when the listing includes it.
    pub id: Option<i64>,
    /// Service/category of the secret.
    pub category: String,
    /// Secret name.
    pub name: String,
    /// Encrypted payload: nonce || ciphertext+tag.
    pub blob: Vec<u8>,
}

/// Parse CRED:v3 entries from a Kleos `/list` JSON response (array or `{results: [...]}`).
///
/// Memories that are not well-formed v3 entries are skipped and counted.
pub fn parse_v3_listing(json: &serde_json::Value) -> (Vec<V3Entry>, usize) {
    let items = json
        .as_array()
        .or_else(|| json.get("results").and_then(|r| r.as_array()))
        .cloned()
        .unwrap_or_default();
    let mut entries = Vec::new();
    let mut malformed = 0usize;
    for item in items {
        let content = item.get("content").and_then(|c| c.as_str()).unwrap_or("");
        let parsed = content
            .strip_prefix(V3_PREFIX)
            .and_then(|rest| rest.split_once(" = "))
            .and_then(|(path, hex_data)| {
                let (category, name) = path.split_once('/')?;
                let blob = hex::decode(hex_data.trim()).ok()?;
                Some(V3Entry {
                    id: item.get("id").and_then(|v| v.as_i64()),
                    // Categories with `/` are stored escaped as `%2F` (phylaxd encode_v3_category).
                    category: category.replace("%2F", "/"),
                    name: name.to_string(),
                    blob,
                })
            });
        match parsed {
            Some(entry) => entries.push(entry),
            None => malformed += 1,
        }
    }
    (entries, malformed)
}

/// Return whether a central-vault blob authenticates under `key`.
pub fn v3_opens_with(key: &[u8; KEY_SIZE], blob: &[u8]) -> bool {
    decrypt(key, blob).is_ok()
}

/// Unit tests for database and bootstrap rotation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_secret;
    use crate::types::SecretData;

    /// Build a fixture database containing `count` secrets encrypted under `key`.
    fn fixture(dir: &Path, key: &[u8; KEY_SIZE], count: usize) -> PathBuf {
        let path = dir.join("cred.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cred_secrets (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
             category TEXT NOT NULL, secret_type TEXT NOT NULL, encrypted_data BLOB NOT NULL, nonce BLOB NOT NULL,
             created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(user_id, category, name));",
        )
        .unwrap();
        for index in 0..count {
            let data = SecretData::Note {
                content: format!("secret-{index}"),
            };
            let (ciphertext, nonce) = encrypt_secret(key, &data).unwrap();
            conn.execute(
                "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
                 VALUES (1, ?1, 'svc', 'note', ?2, ?3, 'now', 'now')",
                params![format!("k{index}"), ciphertext, nonce.as_slice()],
            )
            .unwrap();
        }
        path
    }

    /// Distinct deterministic test keys.
    const OLD: [u8; KEY_SIZE] = [7u8; KEY_SIZE];
    /// Rotation target key.
    const NEW: [u8; KEY_SIZE] = [9u8; KEY_SIZE];

    /// Every row moves to the new key and none remain readable with the old key.
    #[test]
    fn rotates_all_rows_and_old_key_stops_working() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 5);
        let report = rekey_database(&db, &OLD, &NEW, false).unwrap();
        assert_eq!(
            report,
            RekeyReport {
                rows: 5,
                rotated: 5,
                already_new: 0,
                committed: true
            }
        );
        assert_eq!(count_decryptable(&db, &NEW).unwrap(), (5, 5));
        assert_eq!(count_decryptable(&db, &OLD).unwrap(), (0, 5));
    }

    /// A dry run verifies decryptability without writing.
    #[test]
    fn dry_run_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 3);
        let report = rekey_database(&db, &OLD, &NEW, true).unwrap();
        assert!(!report.committed);
        assert_eq!(count_decryptable(&db, &OLD).unwrap(), (3, 3));
        assert_eq!(count_decryptable(&db, &NEW).unwrap(), (0, 3));
    }

    /// A row readable by neither key aborts the whole transaction without leaking plaintext.
    #[test]
    fn one_undecryptable_row_aborts_everything() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 3);
        let conn = Connection::open(&db).unwrap();
        let (ciphertext, nonce) = encrypt_secret(
            &[1u8; KEY_SIZE],
            &SecretData::Note {
                content: "x".into(),
            },
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
             VALUES (1, 'foreign', 'svc', 'note', ?1, ?2, 'now', 'now')",
            params![ciphertext, nonce.as_slice()],
        )
        .unwrap();
        let error = rekey_database(&db, &OLD, &NEW, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("svc/foreign"), "{error}");
        assert!(
            !error.contains("secret-"),
            "error must not contain plaintext: {error}"
        );
        assert_eq!(count_decryptable(&db, &OLD).unwrap(), (3, 4));
    }

    /// Rows already under the target key are counted and left unchanged.
    #[test]
    fn rows_already_under_the_target_key_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 2);
        let conn = Connection::open(&db).unwrap();
        let (ciphertext, nonce) = encrypt_secret(
            &NEW,
            &SecretData::Note {
                content: "y".into(),
            },
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
             VALUES (1, 'mixed', 'svc', 'note', ?1, ?2, 'now', 'now')",
            params![ciphertext, nonce.as_slice()],
        )
        .unwrap();
        let dry = rekey_database(&db, &OLD, &NEW, true).unwrap();
        assert_eq!((dry.rotated, dry.already_new), (2, 1));
        let report = rekey_database(&db, &OLD, &NEW, false).unwrap();
        assert_eq!((report.rows, report.rotated, report.already_new), (3, 2, 1));
        assert_eq!(count_decryptable(&db, &NEW).unwrap(), (3, 3));
        assert_eq!(count_decryptable(&db, &OLD).unwrap(), (0, 3));
    }

    /// A recovery kit round-trips the exact key and rejects wrong passphrases, tampering, and short passphrases.
    #[test]
    fn recovery_kit_roundtrip_and_failures() {
        let blob = wrap_master_key("correct horse battery", &OLD).unwrap();
        assert_eq!(&blob[..5], RECOVERY_KIT_MAGIC);
        assert!(keys_match(
            &unwrap_master_key("correct horse battery", &blob).unwrap(),
            &OLD
        ));
        assert!(unwrap_master_key("wrong horse battery!", &blob).is_err());
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unwrap_master_key("correct horse battery", &tampered).is_err());
        assert!(unwrap_master_key("correct horse battery", &blob[5..]).is_err());
        assert!(wrap_master_key("short", &OLD).is_err());
        assert!(!keys_match(&OLD, &NEW));
    }

    /// New private files are 0600 and never overwrite existing paths.
    #[test]
    fn new_private_file_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kit");
        write_new_private_file(&path, b"x").unwrap();
        assert!(write_new_private_file(&path, b"y").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// v3 listings parse into entries and only the right key opens them.
    #[test]
    fn v3_listing_parses_and_checks_keys() {
        let blob = encrypt(&OLD, b"{\"type\":\"note\"}").unwrap();
        let listing = serde_json::json!({"results": [
            {"content": format!("{}svc/one = {}", V3_PREFIX, hex::encode(&blob))},
            {"content": "not a credential"},
            {"content": format!("{}broken", V3_PREFIX)},
        ]});
        let (entries, malformed) = parse_v3_listing(&listing);
        assert_eq!(malformed, 2);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (entries[0].category.as_str(), entries[0].name.as_str()),
            ("svc", "one")
        );
        assert!(v3_opens_with(&OLD, &entries[0].blob));
        assert!(!v3_opens_with(&NEW, &entries[0].blob));
    }

    /// A whole vault file is re-keyed at rest and per secret, with the original preserved.
    #[test]
    fn vault_file_rekey_at_rest_and_rows() {
        let dir = tempfile::tempdir().unwrap();
        let plain = fixture(dir.path(), &OLD, 4);
        let encrypted = dir.path().join("vault.db");
        {
            let conn = Connection::open(&plain).unwrap();
            conn.execute_batch(&format!(
                "ATTACH DATABASE '{}' AS enc KEY {}; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;",
                encrypted.display(),
                sqlcipher_key_clause(Some(&[3u8; KEY_SIZE])).as_str()
            ))
            .unwrap();
        }
        let old_at_rest = [3u8; KEY_SIZE];
        let new_at_rest = [4u8; KEY_SIZE];
        assert!(
            open_vault(&encrypted, None).is_err(),
            "encrypted vault must not open without a key"
        );

        let dry = rekey_vault_file(
            &encrypted,
            Some(&old_at_rest),
            Some(&new_at_rest),
            &OLD,
            &NEW,
            true,
        )
        .unwrap();
        assert_eq!((dry.rows, dry.rotated, dry.backup.clone()), (4, 4, None));
        assert_eq!(
            count_decryptable_in(&encrypted, Some(&old_at_rest), &OLD).unwrap(),
            (4, 4)
        );
        assert!(!PathBuf::from(format!("{}.rekeying", encrypted.display())).exists());

        let report = rekey_vault_file(
            &encrypted,
            Some(&old_at_rest),
            Some(&new_at_rest),
            &OLD,
            &NEW,
            false,
        )
        .unwrap();
        let backup = report.backup.unwrap();
        assert!(open_vault(&encrypted, Some(&old_at_rest)).is_err());
        assert_eq!(
            count_decryptable_in(&encrypted, Some(&new_at_rest), &NEW).unwrap(),
            (4, 4)
        );
        assert_eq!(
            count_decryptable_in(&backup, Some(&old_at_rest), &OLD).unwrap(),
            (4, 4)
        );
        assert!(
            rekey_vault_file(
                &encrypted,
                Some(&new_at_rest),
                Some(&old_at_rest),
                &NEW,
                &OLD,
                false
            )
            .is_err(),
            "second rotation must not overwrite the preserved original"
        );
    }

    /// Installing a challenge keeps the previous one and never clobbers that backup.
    #[test]
    fn challenge_install_keeps_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("challenge");
        std::fs::write(&path, [1u8; 32]).unwrap();
        let backup = install_challenge(&path, &[2u8; 32]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![2u8; 32]);
        assert_eq!(std::fs::read(&backup).unwrap(), vec![1u8; 32]);
        assert!(install_challenge(&path, &[3u8; 32]).is_err());
    }

    /// Merging copies missing rows, reports differing values, and never overwrites.
    #[test]
    fn merge_copies_missing_and_flags_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let a_dir = dir.path().join("a");
        let b_dir = dir.path().join("b");
        std::fs::create_dir_all(&a_dir).unwrap();
        std::fs::create_dir_all(&b_dir).unwrap();
        let a = fixture(&a_dir, &OLD, 2); // svc/k0, svc/k1
        let b = fixture(&b_dir, &OLD, 3); // svc/k0, svc/k1, svc/k2
        {
            let conn = Connection::open(&b).unwrap();
            let (ct, nonce) = encrypt_secret(
                &OLD,
                &SecretData::Note {
                    content: "changed".into(),
                },
            )
            .unwrap();
            conn.execute(
                "UPDATE cred_secrets SET encrypted_data = ?1, nonce = ?2 WHERE name = 'k1'",
                params![ct, nonce.as_slice()],
            )
            .unwrap();
        }
        let dry = merge_vault(&a, None, &b, None, &OLD, true).unwrap();
        assert_eq!(dry.imported, vec!["svc/k2".to_string()]);
        assert_eq!(count_decryptable_in(&a, None, &OLD).unwrap(), (2, 2));
        let report = merge_vault(&a, None, &b, None, &OLD, false).unwrap();
        assert_eq!(
            (
                report.imported.len(),
                report.identical,
                report.differing.clone()
            ),
            (1, 1, vec!["svc/k1".to_string()])
        );
        assert_eq!(count_decryptable_in(&a, None, &OLD).unwrap(), (3, 3));
    }

    /// Central entries are imported only when missing and re-encrypted under the local key.
    #[test]
    fn v3_import_reencrypts_missing_only() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &NEW, 1); // svc/k0 under NEW
        let record = serde_json::to_vec(&SecretData::Note {
            content: "central".into(),
        })
        .unwrap();
        let entries = vec![
            V3Entry {
                id: None,
                category: "svc".into(),
                name: "k0".into(),
                blob: encrypt(&OLD, &record).unwrap(),
            },
            V3Entry {
                id: None,
                category: "git".into(),
                name: "push".into(),
                blob: encrypt(&OLD, &record).unwrap(),
            },
            V3Entry {
                id: None,
                category: "x".into(),
                name: "locked".into(),
                blob: encrypt(&[5u8; KEY_SIZE], &record).unwrap(),
            },
        ];
        let report = import_v3_entries(&db, None, &NEW, &entries, &OLD, false).unwrap();
        assert_eq!(report.imported, vec!["git/push".to_string()]);
        assert_eq!(report.identical, 1);
        assert_eq!(report.undecryptable, vec!["x/locked".to_string()]);
        assert_eq!(count_decryptable_in(&db, None, &NEW).unwrap(), (2, 2));
    }

    /// Export produces parseable v3 contents that open with the key and skips unsafe names.
    #[test]
    fn v3_export_roundtrips_through_parser() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 2);
        {
            let conn = Connection::open(&db).unwrap();
            let (ct, nonce) = encrypt_secret(
                &OLD,
                &SecretData::Note {
                    content: "x".into(),
                },
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
                 VALUES (1, 'bot api-key', 'telegram', 'note', ?1, ?2, 'now', 'now')",
                params![ct, nonce.as_slice()],
            )
            .unwrap();
        }
        let (contents, skipped) = export_v3_contents(&db, None, &OLD).unwrap();
        assert_eq!(contents.len(), 2);
        assert_eq!(
            skipped,
            vec!["telegram/bot api-key (name not v3-safe)".to_string()]
        );
        assert!(is_v3_safe_name("bot/api-key") && !is_v3_safe_name("a//b"));
        let listing = serde_json::json!(contents
            .iter()
            .map(|c| serde_json::json!({"content": c}))
            .collect::<Vec<_>>());
        let (entries, malformed) = parse_v3_listing(&listing);
        assert_eq!((entries.len(), malformed), (2, 0));
        assert!(entries.iter().all(|e| v3_opens_with(&OLD, &e.blob)));
    }

    /// A slashed service (category) is escaped on export and restored by the parser.
    #[test]
    fn v3_slashed_category_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 0);
        {
            let conn = Connection::open(&db).unwrap();
            let (ct, nonce) = encrypt_secret(
                &OLD,
                &SecretData::Note {
                    content: "z".into(),
                },
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
                 VALUES (1, 'api-token', 'cloudflare/zone', 'note', ?1, ?2, 'now', 'now')",
                params![ct, nonce.as_slice()],
            )
            .unwrap();
        }
        let (contents, skipped) = export_v3_contents(&db, None, &OLD).unwrap();
        assert!(skipped.is_empty());
        assert!(contents[0].starts_with("[CRED:v3] cloudflare%2Fzone/api-token = "));
        let listing = serde_json::json!([{"content": contents[0]}]);
        let (entries, _) = parse_v3_listing(&listing);
        assert_eq!(
            (entries[0].category.as_str(), entries[0].name.as_str()),
            ("cloudflare/zone", "api-token")
        );
    }

    /// Rotating to the same key is refused.
    #[test]
    fn refuses_identical_keys() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &OLD, 1);
        assert!(rekey_database(&db, &OLD, &OLD, false).is_err());
    }

    /// The bootstrap blob is re-wrapped atomically with a private backup that is never clobbered.
    #[test]
    fn bootstrap_is_rewrapped_with_private_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.enc");
        let mut blob = BOOTSTRAP_MAGIC.to_vec();
        blob.extend_from_slice(&encrypt(&OLD, b"bearer-token").unwrap());
        std::fs::write(&path, &blob).unwrap();

        assert_eq!(
            rekey_bootstrap(&path, &OLD, &NEW, true).unwrap(),
            BootstrapOutcome::Verified
        );
        let outcome = rekey_bootstrap(&path, &OLD, &NEW, false).unwrap();
        let BootstrapOutcome::Rewrapped { backup } = outcome else {
            panic!("expected rewrap")
        };
        let rewritten = std::fs::read(&path).unwrap();
        assert_eq!(decrypt(&NEW, &rewritten[4..]).unwrap(), b"bearer-token");
        assert_eq!(std::fs::read(&backup).unwrap(), blob);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            rekey_bootstrap(&path, &NEW, &OLD, false).is_err(),
            "second run must not clobber the backup"
        );
        assert_eq!(
            rekey_bootstrap(&dir.path().join("missing"), &OLD, &NEW, false).unwrap(),
            BootstrapOutcome::Absent
        );
    }
}
