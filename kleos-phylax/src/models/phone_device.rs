//! Persistent public material for StrongBox-backed approval devices.

use kleos_cred::{CredError, Result};
use kleos_lib::db::Database;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use rusqlite::params;

/// An enrolled exact-phone public key and its revocation state.
#[derive(Debug, Clone)]
pub struct PhoneDevice {
    /// Database row identifier.
    pub id: i64,
    /// Random server-assigned identifier bound into every signature.
    pub device_id: String,
    /// Owner user identifier.
    pub user_id: i64,
    /// Operator-readable phone label.
    pub label: String,
    /// DER SubjectPublicKeyInfo for a P-256 signing key.
    pub public_key_der: Vec<u8>,
    /// SHA-256 fingerprint of validated attestation evidence.
    pub attestation_sha256: String,
    /// UTC enrollment timestamp.
    pub created_at: String,
    /// UTC revocation timestamp, if revoked.
    pub revoked_at: Option<String>,
}

/// Persist public material only after an enrollment verifier accepts attestation.
pub async fn enroll_verified_device(
    db: &Database,
    user_id: i64,
    label: &str,
    public_key_der: &[u8],
    attestation_sha256: &str,
) -> Result<PhoneDevice> {
    VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|_| CredError::InvalidInput("phone public key must be P-256 SPKI".into()))?;
    if label.trim().is_empty() || label.len() > 128 {
        return Err(CredError::InvalidInput("invalid phone label".into()));
    }
    if attestation_sha256.len() != 64
        || !attestation_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CredError::InvalidInput(
            "invalid attestation fingerprint".into(),
        ));
    }

    let device_id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let stored_device_id = device_id.clone();
    let stored_label = label.to_string();
    let stored_public_key = public_key_der.to_vec();
    let stored_attestation = attestation_sha256.to_ascii_lowercase();
    let stored_created_at = created_at.clone();
    let id = db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO phylax_phone_devices
                 (device_id, user_id, label, public_key_der, attestation_sha256, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    stored_device_id,
                    user_id,
                    stored_label,
                    stored_public_key,
                    stored_attestation,
                    stored_created_at
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    Ok(PhoneDevice {
        id,
        device_id,
        user_id,
        label: label.to_string(),
        public_key_der: public_key_der.to_vec(),
        attestation_sha256: attestation_sha256.to_ascii_lowercase(),
        created_at,
        revoked_at: None,
    })
}

/// Load an active phone device belonging to one approval owner.
pub async fn get_active_device(
    db: &Database,
    user_id: i64,
    device_id: &str,
) -> Result<PhoneDevice> {
    let requested_device = device_id.to_string();
    db.read(move |conn| {
        Ok(conn.query_row(
            "SELECT id, device_id, user_id, label, public_key_der,
                    attestation_sha256, created_at, revoked_at
             FROM phylax_phone_devices
             WHERE user_id = ?1 AND device_id = ?2 AND revoked_at IS NULL",
            params![user_id, requested_device],
            row_to_device,
        )?)
    })
    .await
    .map_err(|_| CredError::PermissionDenied("phone device rejected".into()))
}

/// Load the sole active phone for a user and reject missing or ambiguous enrollment.
pub async fn get_only_active_device(db: &Database, user_id: i64) -> Result<PhoneDevice> {
    let devices = db
        .read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT id, device_id, user_id, label, public_key_der,
                        attestation_sha256, created_at, revoked_at
                 FROM phylax_phone_devices
                 WHERE user_id = ?1 AND revoked_at IS NULL
                 ORDER BY id LIMIT 2",
            )?;
            let rows = statement.query_map(params![user_id], row_to_device)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    if devices.len() != 1 {
        return Err(CredError::PermissionDenied(
            "exactly one active phone enrollment required".into(),
        ));
    }
    devices
        .into_iter()
        .next()
        .ok_or_else(|| CredError::PermissionDenied("phone device rejected".into()))
}

/// Revoke one phone device owned by a user without deleting audit evidence.
pub async fn revoke_device(db: &Database, user_id: i64, device_id: &str) -> Result<()> {
    let requested_device = device_id.to_string();
    let revoked_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let affected = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE phylax_phone_devices SET revoked_at = ?1
                 WHERE user_id = ?2 AND device_id = ?3 AND revoked_at IS NULL",
                params![revoked_at, user_id, requested_device],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    if affected != 1 {
        return Err(CredError::NotFound("active phone device not found".into()));
    }
    Ok(())
}

/// Parse one phone-device database row.
fn row_to_device(row: &rusqlite::Row<'_>) -> rusqlite::Result<PhoneDevice> {
    Ok(PhoneDevice {
        id: row.get(0)?,
        device_id: row.get(1)?,
        user_id: row.get(2)?,
        label: row.get(3)?,
        public_key_der: row.get(4)?,
        attestation_sha256: row.get(5)?,
        created_at: row.get(6)?,
        revoked_at: row.get(7)?,
    })
}
