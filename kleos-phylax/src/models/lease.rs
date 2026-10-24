//! Single-use lease model and atomic redemption.

use kleos_cred::{CredError, Result};
use kleos_lib::db::Database;
use rusqlite::params;

/// A single-use credential lease bound to an approval.
#[derive(Debug, Clone)]
pub struct Lease {
    /// Row ID.
    pub id: i64,
    /// Owner user ID.
    pub user_id: i64,
    /// Approval that authorized this lease.
    pub approval_id: i64,
    /// Agent the lease was issued to.
    pub agent_name: String,
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub secret_name: String,
    /// Unique lease token (UUID).
    pub jti: String,
    /// Correlation ID linking related operations.
    pub correlation_id: Option<String>,
    /// When the lease was created.
    pub created_at: String,
    /// When the lease expires.
    pub expires_at: String,
    /// When the lease was redeemed (None if unused).
    pub used_at: Option<String>,
}

/// Serializable lease for JSON responses.
impl Lease {
    /// Convert to a serde_json::Value for API responses.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "approval_id": self.approval_id,
            "agent_name": self.agent_name,
            "category": self.category,
            "secret_name": self.secret_name,
            "jti": self.jti,
            "correlation_id": self.correlation_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "used_at": self.used_at,
        })
    }
}

/// Mint a new lease tied to an approved approval.
#[allow(clippy::too_many_arguments)]
pub async fn mint_lease(
    db: &Database,
    user_id: i64,
    approval_id: i64,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    correlation_id: Option<&str>,
    ttl_seconds: i64,
) -> Result<Lease> {
    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let expires = (now + chrono::Duration::seconds(ttl_seconds))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let jti = uuid::Uuid::new_v4().to_string();

    let agent = agent_name.to_string();
    let cat = category.to_string();
    let sec = secret_name.to_string();
    let corr = correlation_id.map(|s| s.to_string());
    let jti2 = jti.clone();
    let created2 = created.clone();
    let expires2 = expires.clone();

    let id = db
        .write(move |conn| {
            let affected = conn.execute(
                "INSERT INTO phylax_leases
                 (user_id, approval_id, agent_name, category, secret_name,
                  jti, correlation_id, created_at, expires_at)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
                 WHERE EXISTS (
                     SELECT 1 FROM phylax_approvals
                     WHERE id = ?2 AND user_id = ?1 AND status = 1
                       AND operation_digest IS NOT NULL
                 )
                   AND NOT EXISTS (
                     SELECT 1 FROM phylax_leases WHERE approval_id = ?2
                 )",
                params![
                    user_id,
                    approval_id,
                    agent,
                    cat,
                    sec,
                    jti2,
                    corr,
                    created2,
                    expires2
                ],
            )?;
            if affected != 1 {
                return Err(kleos_lib::EngError::Forbidden(
                    "approval cannot issue another operation lease".into(),
                ));
            }
            Ok(conn.last_insert_rowid())
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    Ok(Lease {
        id,
        user_id,
        approval_id,
        agent_name: agent_name.to_string(),
        category: category.to_string(),
        secret_name: secret_name.to_string(),
        jti,
        correlation_id: correlation_id.map(|s| s.to_string()),
        created_at: created,
        expires_at: expires,
        used_at: None,
    })
}

/// Atomically redeem a lease. Returns the lease if successful.
///
/// Scoped to `user_id`: a lease can only be redeemed (or even probed for its
/// failure reason) by its owner, so one caller cannot burn or enumerate
/// another's leases by guessing the jti.
///
/// Fails with CredError::NotFound if lease doesn't exist for this owner.
/// Fails with CredError::InvalidInput if lease is already used or expired.
pub async fn redeem_lease(db: &Database, jti: &str, user_id: i64) -> Result<Lease> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let jti_owned = jti.to_string();
    let now2 = now.clone();
    let jti3 = jti_owned.clone();
    let jti4 = jti_owned.clone();

    db.write(move |conn| {
        // Atomic: only succeeds if used_at IS NULL and not expired.
        let affected = conn.execute(
            "UPDATE phylax_leases SET used_at = ?1
             WHERE jti = ?2 AND user_id = ?3 AND used_at IS NULL AND expires_at > ?1",
            params![now2, jti_owned, user_id],
        )?;

        if affected == 0 {
            // Determine why: not found, already used, or expired.
            let mut stmt = conn.prepare(
                "SELECT id, user_id, approval_id, agent_name, category, secret_name,
                        jti, correlation_id, created_at, expires_at, used_at
                 FROM phylax_leases WHERE jti = ?1 AND user_id = ?2",
            )?;
            let lease = stmt.query_row(params![jti3, user_id], row_to_lease).ok();
            return match lease {
                None => Err(kleos_lib::EngError::NotFound("lease not found".into())),
                Some(l) if l.used_at.is_some() => Err(kleos_lib::EngError::Conflict(
                    "lease already redeemed".into(),
                )),
                Some(_) => Err(kleos_lib::EngError::InvalidInput("lease expired".into())),
            };
        }

        // Re-read to get the full row with used_at set.
        let mut stmt = conn.prepare(
            "SELECT id, user_id, approval_id, agent_name, category, secret_name,
                    jti, correlation_id, created_at, expires_at, used_at
             FROM phylax_leases WHERE jti = ?1 AND user_id = ?2",
        )?;
        let lease = stmt.query_row(params![jti4, user_id], row_to_lease)?;
        Ok(lease)
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Atomically redeem a lease only when it matches the retried resolve operation.
#[allow(clippy::too_many_arguments)]
pub async fn redeem_lease_for_operation(
    db: &Database,
    jti: &str,
    user_id: i64,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    resolve_mode: &str,
    operation_digest: &[u8; 32],
) -> Result<Lease> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let jti_owned = jti.to_string();
    let agent = agent_name.to_string();
    let category = category.to_string();
    let secret_name = secret_name.to_string();
    let resolve_mode = resolve_mode.to_string();
    let operation_digest = operation_digest.to_vec();
    let now_for_update = now.clone();
    let jti_for_read = jti_owned.clone();

    db.write(move |conn| {
        let affected = conn.execute(
            "UPDATE phylax_leases SET used_at = ?1
             WHERE jti = ?2 AND user_id = ?3 AND agent_name = ?4
               AND category = ?5 AND secret_name = ?6
               AND used_at IS NULL AND expires_at > ?1
               AND EXISTS (
                   SELECT 1 FROM phylax_approvals a
                   WHERE a.id = phylax_leases.approval_id
                     AND a.user_id = ?3 AND a.agent_name = ?4
                     AND a.category = ?5 AND a.secret_name = ?6
                     AND a.resolve_mode = ?7 AND a.status = 1
                     AND a.operation_digest = ?8
               )",
            params![
                now_for_update,
                jti_owned,
                user_id,
                agent,
                category,
                secret_name,
                resolve_mode,
                operation_digest
            ],
        )?;
        if affected != 1 {
            return Err(kleos_lib::EngError::Forbidden(
                "lease is invalid, expired, consumed, or bound to another operation".into(),
            ));
        }

        let mut stmt = conn.prepare(
            "SELECT id, user_id, approval_id, agent_name, category, secret_name,
                    jti, correlation_id, created_at, expires_at, used_at
             FROM phylax_leases WHERE jti = ?1 AND user_id = ?2",
        )?;
        Ok(stmt.query_row(params![jti_for_read, user_id], row_to_lease)?)
    })
    .await
    .map_err(|_| CredError::PermissionDenied("lease rejected".into()))
}

/// Return the active lease issued for one approved request and agent.
pub async fn get_active_lease_for_approval(
    db: &Database,
    approval_id: i64,
    user_id: i64,
    agent_name: &str,
) -> Result<Option<Lease>> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let agent = agent_name.to_string();
    db.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, user_id, approval_id, agent_name, category, secret_name,
                    jti, correlation_id, created_at, expires_at, used_at
             FROM phylax_leases
             WHERE approval_id = ?1 AND user_id = ?2 AND agent_name = ?3
               AND used_at IS NULL AND expires_at > ?4
             LIMIT 1",
        )?;
        Ok(stmt
            .query_row(params![approval_id, user_id, agent, now], row_to_lease)
            .ok())
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// List active (unused, unexpired) leases for a user, optionally filtered by agent.
pub async fn list_active_leases(
    db: &Database,
    user_id: i64,
    agent_name: Option<&str>,
    limit: i64,
) -> Result<Vec<Lease>> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let agent = agent_name.map(|s| s.to_string());

    db.read(move |conn| {
        let leases = match &agent {
            Some(name) => {
                let mut stmt = conn.prepare(
                    "SELECT id, user_id, approval_id, agent_name, category, secret_name,
                            jti, correlation_id, created_at, expires_at, used_at
                     FROM phylax_leases
                     WHERE user_id = ?1 AND agent_name = ?2
                       AND used_at IS NULL AND expires_at > ?3
                     ORDER BY created_at DESC LIMIT ?4",
                )?;
                let rows = stmt.query_map(params![user_id, name, now, limit], row_to_lease)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, user_id, approval_id, agent_name, category, secret_name,
                            jti, correlation_id, created_at, expires_at, used_at
                     FROM phylax_leases
                     WHERE user_id = ?1 AND used_at IS NULL AND expires_at > ?2
                     ORDER BY created_at DESC LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![user_id, now, limit], row_to_lease)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            }
        };
        Ok(leases)
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Parse a database row into a Lease struct.
fn row_to_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<Lease> {
    Ok(Lease {
        id: row.get(0)?,
        user_id: row.get(1)?,
        approval_id: row.get(2)?,
        agent_name: row.get(3)?,
        category: row.get(4)?,
        secret_name: row.get(5)?,
        jti: row.get(6)?,
        correlation_id: row.get(7)?,
        created_at: row.get(8)?,
        expires_at: row.get(9)?,
        used_at: row.get(10)?,
    })
}
