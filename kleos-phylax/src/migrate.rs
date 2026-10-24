//! Phylax table migration -- ensures phylax_* tables exist.
//!
//! This is a standalone idempotent migration for use by phylaxd at startup.
//! The same tables are also created by kleos-lib migration 82, but this
//! function provides a fallback for databases that don't use the full
//! kleos-lib migration chain.

use kleos_cred::CredError;
use rusqlite::params;

/// Ensure all Phylax tables exist. Idempotent (IF NOT EXISTS on all statements).
pub fn ensure_tables(conn: &rusqlite::Connection) -> Result<(), CredError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS phylax_approvals (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            agent_name TEXT NOT NULL,
            category TEXT NOT NULL,
            secret_name TEXT NOT NULL,
            resolve_mode TEXT NOT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            decided_by TEXT,
            reason TEXT,
            lease_id INTEGER,
            correlation_id TEXT,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_phylax_approvals_pending
            ON phylax_approvals(status) WHERE status = 0;
        CREATE INDEX IF NOT EXISTS idx_phylax_approvals_agent
            ON phylax_approvals(agent_name, status);

        CREATE TABLE IF NOT EXISTS phylax_leases (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            approval_id INTEGER NOT NULL,
            agent_name TEXT NOT NULL,
            category TEXT NOT NULL,
            secret_name TEXT NOT NULL,
            jti TEXT NOT NULL UNIQUE,
            correlation_id TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_phylax_leases_active
            ON phylax_leases(agent_name) WHERE used_at IS NULL;

        CREATE TABLE IF NOT EXISTS phylax_access_policies (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            namespace TEXT NOT NULL,
            category TEXT,
            secret_name TEXT,
            require_approval INTEGER NOT NULL DEFAULT 1,
            allowed_modes TEXT NOT NULL DEFAULT '[\"text\",\"proxy\",\"raw\"]',
            created_at TEXT NOT NULL,
            UNIQUE(user_id, namespace, category, secret_name)
        );

        CREATE TABLE IF NOT EXISTS phylax_piv_pubkeys (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            agent_name TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_phylax_piv_active
            ON phylax_piv_pubkeys(agent_name) WHERE revoked_at IS NULL;

        CREATE TABLE IF NOT EXISTS phylax_phone_devices (
            id INTEGER PRIMARY KEY,
            device_id TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            public_key_der BLOB NOT NULL,
            attestation_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_phylax_phone_devices_active
            ON phylax_phone_devices(user_id, device_id) WHERE revoked_at IS NULL;

        CREATE TABLE IF NOT EXISTS phylax_ssh_settings (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            secret_name TEXT NOT NULL,
            auto_sign INTEGER NOT NULL DEFAULT 0,
            auto_load INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, category, secret_name)
        );",
    )
    .map_err(|e| CredError::Database(e.to_string()))?;

    // Additive: single-use capability-token hash for out-of-band approval
    // decisions (SQLite has no ADD COLUMN IF NOT EXISTS, so guard it).
    let has_decide_token: bool = conn
        .prepare(
            "SELECT 1 FROM pragma_table_info('phylax_approvals') WHERE name='decide_token_hash'",
        )
        .and_then(|mut s| s.query_row([], |_| Ok(())))
        .is_ok();
    if !has_decide_token {
        conn.execute(
            "ALTER TABLE phylax_approvals ADD COLUMN decide_token_hash TEXT",
            [],
        )
        .map_err(|e| CredError::Database(e.to_string()))?;
    }

    ensure_column(conn, "phylax_approvals", "phone_nonce", "BLOB")?;
    ensure_column(conn, "phylax_approvals", "phone_request_digest", "BLOB")?;
    ensure_column(conn, "phylax_approvals", "phone_device_id", "TEXT")?;
    ensure_column(
        conn,
        "phylax_approvals",
        "phone_required",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(conn, "phylax_approvals", "phone_consumed_at", "TEXT")?;
    ensure_column(conn, "phylax_approvals", "operation_digest", "BLOB")?;

    // Additive: per-policy exec argv[0] allowlist (kleos-lib migration 86).
    let has_exec_allowlist: bool = conn
        .prepare(
            "SELECT 1 FROM pragma_table_info('phylax_access_policies') WHERE name='exec_allowlist'",
        )
        .and_then(|mut s| s.query_row([], |_| Ok(())))
        .is_ok();
    if !has_exec_allowlist {
        conn.execute(
            "ALTER TABLE phylax_access_policies ADD COLUMN exec_allowlist TEXT",
            [],
        )
        .map_err(|e| CredError::Database(e.to_string()))?;
    }

    ensure_cred_audit_column(conn, "operator_id", "TEXT")?;
    ensure_cred_audit_column(conn, "source_ip", "TEXT")?;
    ensure_cred_audit_column(conn, "policy_id", "INTEGER")?;
    ensure_cred_audit_column(conn, "session_id", "TEXT")?;

    Ok(())
}

/// Add a missing column to an existing Phylax table.
fn ensure_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), CredError> {
    let exists: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
            params![column],
            |row| row.get(0),
        )
        .map_err(|e| CredError::Database(e.to_string()))?;
    if exists == 0 {
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        conn.execute(&sql, [])
            .map_err(|e| CredError::Database(e.to_string()))?;
    }
    Ok(())
}

/// Add a missing `cred_audit` column if the table and column are absent.
fn ensure_cred_audit_column(
    conn: &rusqlite::Connection,
    column: &str,
    definition: &str,
) -> Result<(), CredError> {
    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cred_audit'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| CredError::Database(e.to_string()))?;

    if table_exists == 0 {
        return Ok(());
    }

    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('cred_audit') WHERE name = ?1",
            params![column],
            |row| row.get(0),
        )
        .map_err(|e| CredError::Database(e.to_string()))?;

    if exists == 0 {
        let sql = format!(
            "ALTER TABLE cred_audit ADD COLUMN {} {}",
            column, definition
        );
        conn.execute(&sql, [])
            .map_err(|e| CredError::Database(e.to_string()))?;
    }

    Ok(())
}
