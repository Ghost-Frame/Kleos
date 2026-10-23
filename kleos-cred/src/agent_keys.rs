//! Agent key management with permission scoping and revocation.

use kleos_lib::db::Database;
use rand::rngs::OsRng;
use rand::TryRngCore;
use rusqlite::params;
use subtle::ConstantTimeEq;

use crate::crypto::hash_key;
use crate::{CredError, Result};

/// An agent key for service authentication.
#[derive(Debug, Clone)]
pub struct AgentKey {
    pub id: i64,
    pub user_id: i64,
    pub key_hash: String,
    pub name: String,
    pub permissions: AgentKeyPermissions,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// Validity and access checks for a stored agent key.
impl AgentKey {
    /// Check if this key is currently valid (not revoked).
    pub fn is_valid(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Check if this key has permission to access a category.
    pub fn can_access(&self, category: &str) -> bool {
        if !self.is_valid() {
            return false;
        }
        self.permissions.allows_category(category)
    }
}

/// Permissions for an agent key.
#[derive(Debug, Clone, Default)]
pub struct AgentKeyPermissions {
    /// Allowed category patterns (empty = all categories).
    pub categories: Vec<String>,
    /// Allowed namespace patterns (empty = all namespaces allowed).
    pub namespaces: Vec<String>,
    /// Set when the stored permissions blob failed to parse. Empty category and
    /// namespace lists mean "all", so a corrupt blob must not deserialize to an
    /// all-empty struct that silently grants everything; when true, allows_*
    /// deny unconditionally (fail closed). Not serialized; defaults false.
    malformed: bool,
}

/// Permission checks and JSON (de)serialization for an agent key's allow-lists.
impl AgentKeyPermissions {
    /// Check if a category is allowed.
    pub fn allows_category(&self, category: &str) -> bool {
        if self.malformed {
            return false;
        }
        if self.categories.is_empty() {
            return true;
        }
        self.categories.iter().any(|pat| {
            if pat.ends_with('*') {
                category.starts_with(&pat[..pat.len() - 1])
            } else {
                category == pat
            }
        })
    }

    /// Check if this agent key is allowed to access a namespace.
    ///
    /// Empty namespaces list means all namespaces are allowed.
    pub fn allows_namespace(&self, ns: &str) -> bool {
        if self.malformed {
            return false;
        }
        if self.namespaces.is_empty() {
            return true;
        }
        self.namespaces.iter().any(|pattern| {
            if pattern == "*" {
                true
            } else if let Some(prefix) = pattern.strip_suffix("/*") {
                ns.starts_with(prefix)
                    && ns.len() > prefix.len()
                    && ns.as_bytes()[prefix.len()] == b'/'
            } else {
                pattern == ns
            }
        })
    }

    /// Construct permissions from explicit allow-lists (not from a stored blob).
    /// The `malformed` fail-closed flag stays private; use this from other crates
    /// instead of a struct literal.
    pub fn new(categories: Vec<String>, namespaces: Vec<String>) -> Self {
        Self {
            categories,
            namespaces,
            malformed: false,
        }
    }

    /// Serialize to JSON for storage.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "categories": self.categories,
            "namespaces": self.namespaces,
        })
        .to_string()
    }

    /// Deserialize from JSON.
    ///
    /// Rows written by older builds may carry an `allow_raw` key; it is
    /// accepted and ignored (the capability no longer exists).
    pub fn from_json(json: &str) -> Self {
        // Fail closed: a permissions blob that does not parse must not widen
        // access. Empty category/namespace lists mean "all", so returning a
        // Default (all-empty) here would grant everything -- flag it malformed
        // instead so allows_* deny.
        let value: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => {
                return Self {
                    malformed: true,
                    categories: Vec::new(),
                    namespaces: Vec::new(),
                };
            }
        };
        let categories = value
            .get("categories")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let namespaces = value
            .get("namespaces")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            categories,
            namespaces,
            malformed: false,
        }
    }
}

/// Generate a new agent key.
///
/// Returns (raw_key_bytes, key_hash).
pub fn generate_agent_key() -> ([u8; 32], String) {
    let mut key = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .expect("OS CSPRNG must be available");
    let hash = hash_key(&key);
    (key, hash)
}

/// Format a raw key as a displayable string (hex).
pub fn format_agent_key(key: &[u8]) -> String {
    hex::encode(key)
}

/// Parse a hex-encoded agent key.
pub fn parse_agent_key(encoded: &str) -> Result<Vec<u8>> {
    hex::decode(encoded).map_err(|e| CredError::InvalidInput(format!("invalid key format: {}", e)))
}

/// Create a new agent key in the database.
#[tracing::instrument(skip(db, permissions), fields(user_id, name = %name))]
pub async fn create_agent_key(
    db: &Database,
    user_id: i64,
    name: &str,
    permissions: &AgentKeyPermissions,
) -> Result<(String, AgentKey)> {
    let (raw_key, key_hash) = generate_agent_key();
    let permissions_json = permissions.to_json();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let name_owned = name.to_string();
    let permissions_clone = permissions.clone();
    let key_hash_ret = key_hash.clone();
    let now_ret = now.clone();

    let id = db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO cred_agent_keys (user_id, key_hash, name, permissions, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![user_id, key_hash, name_owned, permissions_json, now],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    let key = AgentKey {
        id,
        user_id,
        key_hash: key_hash_ret,
        name: name.to_string(),
        permissions: permissions_clone,
        created_at: now_ret,
        revoked_at: None,
    };

    Ok((format_agent_key(&raw_key), key))
}

/// Validate an agent key and return its info.
#[tracing::instrument(skip(db, raw_key))]
pub async fn validate_agent_key(db: &Database, raw_key: &[u8]) -> Result<AgentKey> {
    let key_hash = hash_key(raw_key);

    let key = db
        .read(move |conn| {
            // Look up by hash (single-row scan) then verify with constant-time eq.
            let mut stmt = conn.prepare(
                "SELECT id, user_id, key_hash, name, permissions, created_at, revoked_at
                     FROM cred_agent_keys
                     WHERE revoked_at IS NULL AND key_hash = ?1
                     LIMIT 1",
            )?;

            let mut rows = stmt.query(rusqlite::params![key_hash])?;

            if let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let user_id: i64 = row.get(1)?;
                let stored_hash: String = row.get(2)?;
                let name: String = row.get(3)?;
                let permissions_json: String = row.get(4)?;
                let created_at: String = row.get(5)?;
                let revoked_at: Option<String> = row.get(6)?;

                // Defense-in-depth: constant-time verify after index lookup.
                if key_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into() {
                    let permissions = AgentKeyPermissions::from_json(&permissions_json);
                    return Ok(Some(AgentKey {
                        id,
                        user_id,
                        key_hash: stored_hash,
                        name,
                        permissions,
                        created_at,
                        revoked_at,
                    }));
                }
            }
            Ok(None)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?
        .ok_or_else(|| CredError::AuthFailed("invalid agent key".into()))?;

    if !key.is_valid() {
        return Err(CredError::KeyRevoked(key.name.clone()));
    }

    Ok(key)
}

/// List agent keys for a user.
#[tracing::instrument(skip(db), fields(user_id))]
pub async fn list_agent_keys(db: &Database, user_id: i64) -> Result<Vec<AgentKey>> {
    db.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, user_id, key_hash, name, permissions, created_at, revoked_at
                 FROM cred_agent_keys
                 WHERE user_id = ?1
                 ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map(params![user_id], |row| {
            let id: i64 = row.get(0)?;
            let user_id: i64 = row.get(1)?;
            let key_hash: String = row.get(2)?;
            let name: String = row.get(3)?;
            let permissions_json: String = row.get(4)?;
            let created_at: String = row.get(5)?;
            let revoked_at: Option<String> = row.get(6)?;
            Ok((
                id,
                user_id,
                key_hash,
                name,
                permissions_json,
                created_at,
                revoked_at,
            ))
        })?;

        let mut keys = Vec::new();
        for row_result in rows {
            let (id, user_id, key_hash, name, permissions_json, created_at, revoked_at) =
                row_result?;
            let permissions = AgentKeyPermissions::from_json(&permissions_json);
            keys.push(AgentKey {
                id,
                user_id,
                key_hash,
                name,
                permissions,
                created_at,
                revoked_at,
            });
        }

        Ok(keys)
    })
    .await
    .map_err(|e| CredError::Database(e.to_string()))
}

/// Revoke an agent key.
#[tracing::instrument(skip(db), fields(user_id, name = %name))]
pub async fn revoke_agent_key(db: &Database, user_id: i64, name: &str) -> Result<()> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let name_owned = name.to_string();

    let affected = db
        .write(move |conn| {
            Ok(conn.execute(
                "UPDATE cred_agent_keys SET revoked_at = ?1 WHERE user_id = ?2 AND name = ?3 AND revoked_at IS NULL",
                params![now, user_id, name_owned],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    if affected == 0 {
        return Err(CredError::NotFound(format!("agent key: {}", name)));
    }

    Ok(())
}

/// Delete an agent key entirely (for cleanup).
#[tracing::instrument(skip(db), fields(user_id, name = %name))]
pub async fn delete_agent_key(db: &Database, user_id: i64, name: &str) -> Result<()> {
    let name_owned = name.to_string();

    let affected = db
        .write(move |conn| {
            Ok(conn.execute(
                "DELETE FROM cred_agent_keys WHERE user_id = ?1 AND name = ?2",
                params![user_id, name_owned],
            )?)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    if affected == 0 {
        return Err(CredError::NotFound(format!("agent key: {}", name)));
    }

    Ok(())
}

/// Unit tests for agent-key permission scoping and key encoding.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a test permissions struct with known categories, namespaces, and raw access.
    fn setup_permissions() -> AgentKeyPermissions {
        AgentKeyPermissions {
            categories: vec!["aws".into(), "gcp*".into()],
            namespaces: vec!["prod".into(), "staging/*".into()],
            malformed: false,
        }
    }

    /// A malformed permissions blob must fail closed (deny everything), not
    /// deserialize to an all-empty struct that grants everything. A valid blob
    /// with empty lists still legitimately means "all".
    #[test]
    fn malformed_permissions_blob_fails_closed() {
        let bad = AgentKeyPermissions::from_json("{not valid json");
        assert!(
            !bad.allows_category("aws"),
            "malformed must deny categories"
        );
        assert!(
            !bad.allows_namespace("prod"),
            "malformed must deny namespaces"
        );
        let empty = AgentKeyPermissions::from_json(r#"{"categories":[],"namespaces":[]}"#);
        assert!(
            empty.allows_category("aws"),
            "valid empty blob still means all"
        );
        assert!(
            empty.allows_namespace("prod"),
            "valid empty blob still means all"
        );
    }

    /// An exact category pattern matches only that category.
    #[test]
    fn permissions_allows_exact_match() {
        let perms = setup_permissions();
        assert!(perms.allows_category("aws"));
        assert!(!perms.allows_category("azure"));
    }

    /// A trailing-star category pattern matches by prefix.
    #[test]
    fn permissions_allows_wildcard() {
        let perms = setup_permissions();
        assert!(perms.allows_category("gcp"));
        assert!(perms.allows_category("gcp-prod"));
        assert!(perms.allows_category("gcp/project"));
    }

    /// An empty category list allows every category.
    #[test]
    fn permissions_empty_allows_all() {
        let perms = AgentKeyPermissions::default();
        assert!(perms.allows_category("anything"));
        assert!(perms.allows_category("really/anything"));
    }

    /// to_json then from_json preserves the permission fields.
    #[test]
    fn permissions_json_roundtrip() {
        let perms = setup_permissions();
        let json = perms.to_json();
        let restored = AgentKeyPermissions::from_json(&json);
        assert_eq!(perms.categories, restored.categories);
        assert_eq!(perms.namespaces, restored.namespaces);
    }

    /// An exact namespace pattern matches only that namespace.
    #[test]
    fn permissions_allows_namespace_exact() {
        let perms = setup_permissions();
        assert!(perms.allows_namespace("prod"));
        assert!(!perms.allows_namespace("dev"));
    }

    /// A "prefix/*" namespace pattern matches paths under the prefix, not the bare prefix.
    #[test]
    fn permissions_allows_namespace_prefix_wildcard() {
        let perms = setup_permissions();
        assert!(perms.allows_namespace("staging/feature-x"));
        assert!(perms.allows_namespace("staging/main"));
        assert!(!perms.allows_namespace("staging")); // prefix match requires content after /
    }

    /// An empty namespace list allows every namespace.
    #[test]
    fn permissions_namespace_empty_allows_all() {
        let perms = AgentKeyPermissions::default();
        assert!(perms.allows_namespace("anything"));
        assert!(perms.allows_namespace("prod"));
    }

    /// A "*" namespace pattern allows every namespace.
    #[test]
    fn permissions_namespace_star_allows_all() {
        let perms = AgentKeyPermissions {
            categories: vec![],
            namespaces: vec!["*".into()],
            malformed: false,
        };
        assert!(perms.allows_namespace("prod"));
        assert!(perms.allows_namespace("dev"));
        assert!(perms.allows_namespace("any-namespace"));
    }

    /// A blob without a "namespaces" field deserializes to "all namespaces" (back-compat).
    #[test]
    fn permissions_json_backward_compat_missing_namespaces() {
        // Old JSON without "namespaces" field should deserialize to empty vec (all allowed).
        let json = r#"{"categories":["aws"]}"#;
        let perms = AgentKeyPermissions::from_json(json);
        assert!(perms.namespaces.is_empty());
        assert!(perms.allows_namespace("any-namespace"));
    }

    /// A legacy blob carrying `allow_raw` still parses (key ignored) and the
    /// capability is never re-serialized.
    #[test]
    fn legacy_allow_raw_key_is_ignored_and_not_rewritten() {
        let perms = AgentKeyPermissions::from_json(
            r#"{"categories":["aws"],"allow_raw":true,"namespaces":["prod"]}"#,
        );
        assert_eq!(perms.categories, vec!["aws".to_string()]);
        assert_eq!(perms.namespaces, vec!["prod".to_string()]);
        assert!(!perms.to_json().contains("allow_raw"));
    }

    /// Key generation yields a 32-byte key and a matching SHA-256 hex hash.
    #[test]
    fn generate_key_produces_valid_hash() {
        let (key, hash) = generate_agent_key();
        assert_eq!(key.len(), 32);
        assert_eq!(hash.len(), 64); // SHA-256 hex
                                    // Verify hash matches key
        assert_eq!(hash_key(&key), hash);
    }

    /// A formatted key round-trips through parse_agent_key.
    #[test]
    fn format_and_parse_key() {
        let (key, _) = generate_agent_key();
        let formatted = format_agent_key(&key);
        let parsed = parse_agent_key(&formatted).unwrap();
        assert_eq!(key.as_slice(), parsed.as_slice());
    }
}
