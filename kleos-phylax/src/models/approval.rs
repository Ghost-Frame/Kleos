//! Approval request model and DB operations.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kleos_cred::{CredError, Result};
use kleos_lib::db::Database;
use rand::rngs::OsRng;
use rand::TryRngCore;
use rusqlite::params;

use super::phone_approval::{
    hidden_digest, request_digest, verify_envelope, DisplayedApproval, ExpectedPhoneDecision,
    PhoneDecision, PhoneDecisionEnvelope,
};
use super::phone_device;

/// Approval status values stored as integers in the DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ApprovalStatus {
    /// Waiting for operator decision.
    Pending = 0,
    /// Operator approved the request.
    Approved = 1,
    /// Operator denied the request.
    Denied = 2,
    /// Request expired without a decision.
    Expired = 3,
}

/// Stored approval-status conversions.
impl ApprovalStatus {
    /// Parse from integer stored in DB. Returns None for unknown values.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Pending),
            1 => Some(Self::Approved),
            2 => Some(Self::Denied),
            3 => Some(Self::Expired),
            _ => None,
        }
    }
}

/// An approval request for a policy-gated secret.
#[derive(Debug, Clone)]
pub struct Approval {
    /// Row ID.
    pub id: i64,
    /// Owner user ID.
    pub user_id: i64,
    /// Agent that requested access.
    pub agent_name: String,
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub secret_name: String,
    /// Resolve mode requested (text, proxy, raw).
    pub resolve_mode: String,
    /// Current approval status.
    pub status: ApprovalStatus,
    /// Who approved or denied (operator name).
    pub decided_by: Option<String>,
    /// Operator-provided reason for decision.
    pub reason: Option<String>,
    /// Lease ID if a lease was minted from this approval.
    pub lease_id: Option<i64>,
    /// Correlation ID linking related operations.
    pub correlation_id: Option<String>,
    /// When the request was created.
    pub created_at: String,
    /// When the decision was made.
    pub decided_at: Option<String>,
    /// When the request expires if not decided.
    pub expires_at: String,
}

/// Public request binding delivered to the phone through an untrusted relay.
#[derive(Debug, Clone)]
pub struct PhoneApprovalBinding {
    /// Sole active server-enrolled phone selected for this request.
    pub device_id: String,
    /// Base64url-encoded 32-byte one-time server nonce.
    pub nonce: String,
    /// Base64url-encoded digest of immutable approval metadata.
    pub request_digest: String,
    /// Base64url-encoded digest of the request fields the phone does not display.
    pub hidden_digest: String,
    /// Exact server request expiry as Unix seconds.
    pub expires_at: i64,
}

/// Private database fields required to authenticate one phone decision.
struct PhoneApprovalState {
    /// Argon2 hash of the relay's one-time decision capability.
    token_hash: Option<String>,
    /// Server-created one-time nonce bound to this approval.
    nonce: Option<Vec<u8>>,
    /// Digest of the immutable operation metadata reviewed by the phone.
    request_digest: Option<Vec<u8>>,
    /// Enrolled device selected when the approval was created.
    device_id: Option<String>,
    /// Whether this approval requires the exact-phone protocol.
    phone_required: i64,
}

/// Serializable approval for JSON responses.
impl Approval {
    /// Convert to a serde_json::Value for API responses.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "agent_name": self.agent_name,
            "category": self.category,
            "secret_name": self.secret_name,
            "resolve_mode": self.resolve_mode,
            "status": self.status as i32,
            "decided_by": self.decided_by,
            "reason": self.reason,
            "lease_id": self.lease_id,
            "correlation_id": self.correlation_id,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "expires_at": self.expires_at,
        })
    }
}

/// Create a pending approval request, generating a single-use capability token
/// whose SHA-256 hash is stored on the row. Returns the approval and the raw
/// token, to be handed to an out-of-band notifier exactly once. The raw token
/// is never persisted and never returned again.
#[allow(clippy::too_many_arguments)]
pub async fn create_approval_with_token(
    db: &Database,
    user_id: i64,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    resolve_mode: &str,
    correlation_id: Option<&str>,
    expires_at: &str,
) -> Result<(Approval, String)> {
    let token = crate::approval_token::generate();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let agent = agent_name.to_string();
    let cat = category.to_string();
    let sec = secret_name.to_string();
    let mode = resolve_mode.to_string();
    let corr = correlation_id.map(|s| s.to_string());
    let exp = expires_at.to_string();
    let now2 = now.clone();
    let hash = token.hash_hex.clone();

    let id = db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO phylax_approvals
                 (user_id, agent_name, category, secret_name, resolve_mode,
                  status, correlation_id, created_at, expires_at, decide_token_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9)",
                params![user_id, agent, cat, sec, mode, corr, now2, exp, hash],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    let approval = Approval {
        id,
        user_id,
        agent_name: agent_name.to_string(),
        category: category.to_string(),
        secret_name: secret_name.to_string(),
        resolve_mode: resolve_mode.to_string(),
        status: ApprovalStatus::Pending,
        decided_by: None,
        reason: None,
        lease_id: None,
        correlation_id: correlation_id.map(|s| s.to_string()),
        created_at: now,
        decided_at: None,
        expires_at: expires_at.to_string(),
    };
    Ok((approval, token.raw))
}

/// Create a pending approval request. Thin wrapper over
/// [`create_approval_with_token`] that discards the capability token, for call
/// sites that decide approvals only through the authenticated master path.
#[allow(clippy::too_many_arguments)]
pub async fn create_approval(
    db: &Database,
    user_id: i64,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    resolve_mode: &str,
    correlation_id: Option<&str>,
    expires_at: &str,
) -> Result<Approval> {
    let (approval, _token) = create_approval_with_token(
        db,
        user_id,
        agent_name,
        category,
        secret_name,
        resolve_mode,
        correlation_id,
        expires_at,
    )
    .await?;
    Ok(approval)
}

/// Bind a pending approval to the exact server-observed operation bytes.
pub async fn set_operation_digest(
    db: &Database,
    approval_id: i64,
    digest: &[u8; 32],
) -> Result<()> {
    let stored_digest = digest.to_vec();
    let affected = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE phylax_approvals SET operation_digest = ?1
                 WHERE id = ?2 AND status = 0 AND operation_digest IS NULL",
                params![stored_digest, approval_id],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    if affected != 1 {
        return Err(CredError::PermissionDenied(
            "approval operation binding rejected".into(),
        ));
    }
    Ok(())
}

/// Load and validate the optional exact-operation digest for an approval.
pub async fn get_operation_digest(db: &Database, approval_id: i64) -> Result<Option<[u8; 32]>> {
    let value: Option<Vec<u8>> = db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT operation_digest FROM phylax_approvals WHERE id = ?1",
                params![approval_id],
                |row| row.get(0),
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    value
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| CredError::Database("invalid approval operation digest".into()))
        })
        .transpose()
}

/// Get an approval by ID.
pub async fn get_approval(db: &Database, id: i64) -> Result<Approval> {
    db.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, user_id, agent_name, category, secret_name, resolve_mode,
                    status, decided_by, reason, lease_id, correlation_id,
                    created_at, decided_at, expires_at
             FROM phylax_approvals WHERE id = ?1",
        )?;
        let approval = stmt.query_row(params![id], row_to_approval)?;
        Ok(approval)
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// List approvals, optionally filtered by status.
pub async fn list_approvals(
    db: &Database,
    user_id: i64,
    status: Option<ApprovalStatus>,
    limit: i64,
) -> Result<Vec<Approval>> {
    db.read(move |conn| {
        let approvals = match status {
            Some(s) => {
                let mut stmt = conn.prepare(
                    "SELECT id, user_id, agent_name, category, secret_name, resolve_mode,
                            status, decided_by, reason, lease_id, correlation_id,
                            created_at, decided_at, expires_at
                     FROM phylax_approvals
                     WHERE user_id = ?1 AND status = ?2
                     ORDER BY created_at DESC LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![user_id, s as i32, limit], row_to_approval)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, user_id, agent_name, category, secret_name, resolve_mode,
                            status, decided_by, reason, lease_id, correlation_id,
                            created_at, decided_at, expires_at
                     FROM phylax_approvals
                     WHERE user_id = ?1
                     ORDER BY created_at DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![user_id, limit], row_to_approval)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            }
        };
        Ok(approvals)
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Approve or deny a pending request. Only affects rows with status=0 (pending).
pub async fn decide_approval(
    db: &Database,
    id: i64,
    decision: ApprovalStatus,
    decided_by: &str,
    reason: Option<&str>,
) -> Result<()> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let by = decided_by.to_string();
    let rsn = reason.map(|s| s.to_string());

    let affected = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE phylax_approvals
                 SET status = ?1, decided_by = ?2, reason = ?3, decided_at = ?4
                 WHERE id = ?5 AND status = 0",
                params![decision as i32, by, rsn, now, id],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    if affected == 0 {
        return Err(CredError::NotFound(
            "approval not found or already decided".into(),
        ));
    }
    Ok(())
}

/// Decide a pending approval using a presented single-use capability token.
///
/// Verifies the token against the stored hash, that the approval is still
/// pending and unexpired, then atomically records the decision and clears the
/// token hash so it cannot be replayed. Returns the resulting status. The token
/// hash is fetched directly and never travels in the `Approval` struct.
pub async fn decide_with_token(
    db: &Database,
    id: i64,
    presented_token: &str,
    approved: bool,
) -> Result<ApprovalStatus> {
    if phone_required(db, id).await? {
        return Err(CredError::PermissionDenied(
            "phone signature required".into(),
        ));
    }
    let a = get_approval(db, id).await?;
    if !matches!(a.status, ApprovalStatus::Pending) {
        return Ok(a.status); // already decided
    }
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if a.expires_at.as_str() < now.as_str() {
        return Ok(ApprovalStatus::Expired);
    }

    let stored: Option<String> = db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT decide_token_hash FROM phylax_approvals WHERE id = ?1",
                params![id],
                |r| r.get::<_, Option<String>>(0),
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    let stored = stored.ok_or_else(|| CredError::PermissionDenied("no decision token".into()))?;
    if !crate::approval_token::verify(presented_token, &stored) {
        return Err(CredError::PermissionDenied("invalid decision token".into()));
    }

    let new_status = if approved {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Denied
    };
    let decided_at = now.clone();
    let updated = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE phylax_approvals
                 SET status = ?1, decided_by = 'out-of-band', decided_at = ?2,
                     decide_token_hash = NULL
                 WHERE id = ?3 AND status = 0",
                params![new_status as i32, decided_at, id],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    if updated == 0 {
        // Lost a race against another decider; report the current status.
        return Ok(get_approval(db, id).await?.status);
    }
    Ok(new_status)
}

/// Bind one pending approval to a fresh nonce and immutable request digest.
pub async fn bind_phone_approval(
    db: &Database,
    approval: &Approval,
) -> Result<PhoneApprovalBinding> {
    if !matches!(approval.status, ApprovalStatus::Pending) {
        return Err(CredError::InvalidInput("approval is not pending".into()));
    }
    let device = phone_device::get_only_active_device(db, approval.user_id).await?;
    let operation_digest = get_operation_digest(db, approval.id).await?;
    let created_at = parse_db_timestamp(&approval.created_at)?;
    let expires_at = parse_db_timestamp(&approval.expires_at)?;
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CredError::Encryption("OS CSPRNG unavailable".into()))?;
    let hidden = hidden_digest(
        approval.user_id,
        approval.correlation_id.as_deref().unwrap_or(""),
        operation_digest.as_ref(),
        created_at,
    )
    .map_err(|_| CredError::InvalidInput("approval metadata exceeds canonical limits".into()))?;
    let digest = request_digest(
        &DisplayedApproval {
            approval_id: approval.id,
            agent_name: &approval.agent_name,
            category: &approval.category,
            secret_name: &approval.secret_name,
            resolve_mode: &approval.resolve_mode,
            expires_at,
        },
        &hidden,
    )
    .map_err(|_| CredError::InvalidInput("approval metadata exceeds canonical limits".into()))?;
    let stored_nonce = nonce.to_vec();
    let stored_digest = digest.to_vec();
    let stored_device_id = device.device_id.clone();
    let approval_id = approval.id;
    let affected = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE phylax_approvals
                 SET phone_nonce = ?1, phone_request_digest = ?2,
                     phone_device_id = ?3, phone_required = 1
                 WHERE id = ?4 AND status = 0 AND phone_required = 0",
                params![stored_nonce, stored_digest, stored_device_id, approval_id],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    if affected != 1 {
        return Err(CredError::PermissionDenied(
            "approval phone binding rejected".into(),
        ));
    }

    Ok(PhoneApprovalBinding {
        device_id: device.device_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        request_digest: URL_SAFE_NO_PAD.encode(digest),
        hidden_digest: URL_SAFE_NO_PAD.encode(hidden),
        expires_at,
    })
}

/// Verify and atomically consume a phone-signed approval decision.
pub async fn decide_with_phone(
    db: &Database,
    id: i64,
    presented_token: &str,
    envelope: &PhoneDecisionEnvelope,
) -> Result<ApprovalStatus> {
    let approval = get_approval(db, id).await?;
    if !matches!(approval.status, ApprovalStatus::Pending) {
        return Err(CredError::PermissionDenied("decision rejected".into()));
    }
    let state = db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT decide_token_hash, phone_nonce, phone_request_digest,
                        phone_device_id, phone_required
                 FROM phylax_approvals WHERE id = ?1",
                params![id],
                |row| {
                    Ok(PhoneApprovalState {
                        token_hash: row.get(0)?,
                        nonce: row.get(1)?,
                        request_digest: row.get(2)?,
                        device_id: row.get(3)?,
                        phone_required: row.get(4)?,
                    })
                },
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    let stored_hash = state
        .token_hash
        .filter(|_| state.phone_required == 1)
        .ok_or_else(|| CredError::PermissionDenied("decision rejected".into()))?;
    let stored_device_id = state
        .device_id
        .filter(|value| value == &envelope.device_id)
        .ok_or_else(|| CredError::PermissionDenied("decision rejected".into()))?;
    let device = phone_device::get_active_device(db, approval.user_id, &stored_device_id).await?;
    if !crate::approval_token::verify(presented_token, &stored_hash) {
        return Err(CredError::PermissionDenied("decision rejected".into()));
    }
    let nonce_vec = state
        .nonce
        .ok_or_else(|| CredError::PermissionDenied("decision rejected".into()))?;
    let digest_vec = state
        .request_digest
        .ok_or_else(|| CredError::PermissionDenied("decision rejected".into()))?;
    let nonce: [u8; 32] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| CredError::PermissionDenied("decision rejected".into()))?;
    let digest: [u8; 32] = digest_vec
        .as_slice()
        .try_into()
        .map_err(|_| CredError::PermissionDenied("decision rejected".into()))?;
    let expires_at = parse_db_timestamp(&approval.expires_at)?;
    let expected = ExpectedPhoneDecision {
        approval_id: id,
        nonce: &nonce,
        request_digest: &digest,
        device_id: &device.device_id,
        expires_at,
        now: chrono::Utc::now().timestamp(),
        max_clock_skew_seconds: 60,
    };
    let decision = verify_envelope(envelope, &device.public_key_der, &expected)
        .map_err(|_| CredError::PermissionDenied("decision rejected".into()))?;
    let new_status = match decision {
        PhoneDecision::Approved => ApprovalStatus::Approved,
        PhoneDecision::Denied => ApprovalStatus::Denied,
    };
    let decided_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let decided_by = format!("phone:{}", device.device_id);
    let device_id = device.device_id;
    let updated = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE phylax_approvals
                 SET status = ?1, decided_by = ?2, decided_at = ?3,
                     decide_token_hash = NULL, phone_nonce = NULL,
                     phone_consumed_at = ?3
                 WHERE id = ?4 AND status = 0 AND phone_required = 1
                   AND decide_token_hash = ?5 AND phone_nonce = ?6
                   AND phone_request_digest = ?7 AND phone_device_id = ?9
                   AND EXISTS (
                     SELECT 1 FROM phylax_phone_devices
                     WHERE user_id = ?8 AND device_id = ?9 AND revoked_at IS NULL
                   )",
                params![
                    new_status as i32,
                    decided_by,
                    decided_at,
                    id,
                    stored_hash,
                    nonce_vec,
                    digest_vec,
                    approval.user_id,
                    device_id,
                ],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;
    if updated != 1 {
        return Err(CredError::PermissionDenied("decision rejected".into()));
    }
    Ok(new_status)
}

/// Return whether a pending or historical approval was bound to a phone.
pub async fn phone_required(db: &Database, id: i64) -> Result<bool> {
    db.read(move |conn| {
        Ok(conn.query_row(
            "SELECT phone_required FROM phylax_approvals WHERE id = ?1",
            params![id],
            |row| row.get::<_, i64>(0),
        )?)
    })
    .await
    .map(|value| value == 1)
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Parse the database's canonical UTC timestamp into Unix seconds.
fn parse_db_timestamp(value: &str) -> Result<i64> {
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .map(|time| time.and_utc().timestamp())
        .map_err(|_| CredError::Database("invalid approval timestamp".into()))
}

/// Link a lease ID to an approval after minting.
pub async fn set_approval_lease(db: &Database, approval_id: i64, lease_id: i64) -> Result<()> {
    db.write(move |conn| {
        conn.execute(
            "UPDATE phylax_approvals SET lease_id = ?1 WHERE id = ?2",
            params![lease_id, approval_id],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Expire all pending approvals past their expires_at.
pub async fn expire_stale_approvals(db: &Database) -> Result<usize> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    db.write(move |conn| {
        Ok(conn.execute(
            "UPDATE phylax_approvals SET status = 3
             WHERE status = 0 AND expires_at < ?1",
            params![now],
        )?)
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Parse a database row into an Approval struct.
fn row_to_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<Approval> {
    Ok(Approval {
        id: row.get(0)?,
        user_id: row.get(1)?,
        agent_name: row.get(2)?,
        category: row.get(3)?,
        secret_name: row.get(4)?,
        resolve_mode: row.get(5)?,
        status: ApprovalStatus::from_i32(row.get(6)?).unwrap_or(ApprovalStatus::Pending),
        decided_by: row.get(7)?,
        reason: row.get(8)?,
        lease_id: row.get(9)?,
        correlation_id: row.get(10)?,
        created_at: row.get(11)?,
        decided_at: row.get(12)?,
        expires_at: row.get(13)?,
    })
}
