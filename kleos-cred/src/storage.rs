//! Database storage layer for encrypted secrets.

use kleos_lib::db::Database;

use crate::crypto::{decrypt_secret_with_policy, encrypt_secret_with_policy, KEY_SIZE, NONCE_SIZE};
use crate::types::{ProxyPolicy, SecretData, SecretType};
use crate::{CredError, Result};

/// A stored secret row from the database.
#[derive(Debug, Clone)]
pub struct SecretRow {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub category: String,
    pub secret_type: SecretType,
    pub created_at: String,
    pub updated_at: String,
}

/// Store a new secret with the default (empty) proxy policy.
///
/// On a `(user, category, name)` conflict the row is replaced wholesale,
/// including its proxy policy, which resets to the default.
pub async fn store_secret(
    db: &Database,
    user_id: i64,
    category: &str,
    name: &str,
    data: &SecretData,
    key: &[u8; KEY_SIZE],
) -> Result<i64> {
    store_secret_with_policy(
        db,
        user_id,
        category,
        name,
        data,
        &ProxyPolicy::default(),
        key,
    )
    .await
}

/// Store a new secret together with its per-secret proxy policy.
///
/// The caller is responsible for running [`ProxyPolicy::validated`] first.
#[tracing::instrument(skip(db, data, policy, key), fields(user_id, category = %category, name = %name))]
pub async fn store_secret_with_policy(
    db: &Database,
    user_id: i64,
    category: &str,
    name: &str,
    data: &SecretData,
    policy: &ProxyPolicy,
    key: &[u8; KEY_SIZE],
) -> Result<i64> {
    let (encrypted, nonce) = encrypt_secret_with_policy(key, data, policy)?;
    let secret_type = data.secret_type().as_str().to_string();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let name = name.to_string();
    let category = category.to_string();

    let id = db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(user_id, category, name) DO UPDATE SET
                    secret_type = excluded.secret_type,
                    encrypted_data = excluded.encrypted_data,
                    nonce = excluded.nonce,
                    updated_at = excluded.updated_at",
                rusqlite::params![
                    user_id,
                    name,
                    category,
                    secret_type,
                    encrypted.as_slice(),
                    nonce.as_slice(),
                    now.clone(),
                    now
                ],
            )
            ?;

            Ok(conn.last_insert_rowid())
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    Ok(id)
}

/// Get a secret by category and name, discarding its proxy policy.
pub async fn get_secret(
    db: &Database,
    user_id: i64,
    category: &str,
    name: &str,
    key: &[u8; KEY_SIZE],
) -> Result<(SecretRow, SecretData)> {
    let (row, data, _policy) = get_secret_with_policy(db, user_id, category, name, key).await?;
    Ok((row, data))
}

/// Get a secret by category and name together with its proxy policy. Rows
/// written before the policy existed load with the default policy.
#[tracing::instrument(skip(db, key), fields(user_id, category = %category, name = %name))]
pub async fn get_secret_with_policy(
    db: &Database,
    user_id: i64,
    category: &str,
    name: &str,
    key: &[u8; KEY_SIZE],
) -> Result<(SecretRow, SecretData, ProxyPolicy)> {
    let category = category.to_string();
    let name = name.to_string();
    let category_name = format!("{}/{}", category, name);

    type RawRow = (
        i64,
        i64,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
    );

    let raw: Option<RawRow> = db
        .read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at
                     FROM cred_secrets
                     WHERE user_id = ?1 AND category = ?2 AND name = ?3",
                )
                ?;

            let mut rows = stmt
                .query(rusqlite::params![user_id, category, name])
                ?;

            match rows.next()? {
                Some(row) => {
                    let id: i64 = row.get(0)?;
                    let uid: i64 = row.get(1)?;
                    let rname: String = row.get(2)?;
                    let rcat: String = row.get(3)?;
                    let stype: String = row.get(4)?;
                    let enc: Vec<u8> = row.get(5)?;
                    let nonce: Vec<u8> = row.get(6)?;
                    let created: String = row.get(7)?;
                    let updated: String = row.get(8)?;
                    Ok(Some((id, uid, rname, rcat, stype, enc, nonce, created, updated)))
                }
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    let (id, uid, rname, rcat, secret_type_str, encrypted_data, nonce_vec, created_at, updated_at) =
        raw.ok_or(CredError::NotFound(category_name))?;

    let secret_type = SecretType::parse(&secret_type_str).ok_or_else(|| {
        CredError::InvalidInput(format!("unknown secret type: {}", secret_type_str))
    })?;

    let mut nonce = [0u8; NONCE_SIZE];
    if nonce_vec.len() != NONCE_SIZE {
        return Err(CredError::Decryption("invalid nonce length".into()));
    }
    nonce.copy_from_slice(&nonce_vec);

    let (data, policy) = decrypt_secret_with_policy(key, &encrypted_data, &nonce)?;

    let secret_row = SecretRow {
        id,
        user_id: uid,
        name: rname,
        category: rcat,
        secret_type,
        created_at,
        updated_at,
    };

    Ok((secret_row, data, policy))
}

/// List secrets for a user, optionally filtered by category.
#[tracing::instrument(skip(db), fields(user_id, category = ?category))]
pub async fn list_secrets(
    db: &Database,
    user_id: i64,
    category: Option<&str>,
) -> Result<Vec<SecretRow>> {
    type RawRow = (i64, i64, String, String, String, String, String);

    let category = category.map(|s| s.to_string());

    let rows: Vec<RawRow> = db
        .read(move |conn| {
            let (sql, with_cat) = match &category {
                Some(_) => (
                    "SELECT id, user_id, name, category, secret_type, created_at, updated_at
                     FROM cred_secrets
                     WHERE user_id = ?1 AND category = ?2
                     ORDER BY category, name",
                    true,
                ),
                None => (
                    "SELECT id, user_id, name, category, secret_type, created_at, updated_at
                     FROM cred_secrets
                     WHERE user_id = ?1
                     ORDER BY category, name",
                    false,
                ),
            };

            let mut stmt = conn.prepare(sql)?;

            #[allow(clippy::type_complexity)]
            fn map_row(
                row: &rusqlite::Row<'_>,
            ) -> std::result::Result<
                (i64, i64, String, String, String, String, String),
                rusqlite::Error,
            > {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            }

            if with_cat {
                Ok(stmt
                    .query_map(rusqlite::params![user_id, category.as_deref()], map_row)
                    .and_then(|rows| rows.collect::<std::result::Result<Vec<_>, _>>())?)
            } else {
                Ok(stmt
                    .query_map(rusqlite::params![user_id], map_row)
                    .and_then(|rows| rows.collect::<std::result::Result<Vec<_>, _>>())?)
            }
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    // Surface unknown/corrupt secret_type values instead of silently coercing
    // them to Note (which would risk emitting structured data as raw plaintext).
    // Matches the fail-loud behavior of get_secret above.
    let secrets = rows
        .into_iter()
        .map(|(id, uid, name, cat, stype_str, created, updated)| {
            let secret_type = SecretType::parse(&stype_str).ok_or_else(|| {
                CredError::InvalidInput(format!("unknown secret type: {}", stype_str))
            })?;
            Ok(SecretRow {
                id,
                user_id: uid,
                name,
                category: cat,
                secret_type,
                created_at: created,
                updated_at: updated,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(secrets)
}

/// Update an existing secret, keeping its stored proxy policy unchanged.
pub async fn update_secret(
    db: &Database,
    user_id: i64,
    category: &str,
    name: &str,
    data: &SecretData,
    key: &[u8; KEY_SIZE],
) -> Result<()> {
    update_secret_with_policy(db, user_id, category, name, data, None, key).await
}

/// Update an existing secret. `policy = Some(p)` replaces the stored proxy
/// policy; `None` preserves whatever policy the row already has. Returns
/// `NotFound` when the row does not exist.
#[tracing::instrument(skip(db, data, policy, key), fields(user_id, category = %category, name = %name))]
pub async fn update_secret_with_policy(
    db: &Database,
    user_id: i64,
    category: &str,
    name: &str,
    data: &SecretData,
    policy: Option<&ProxyPolicy>,
    key: &[u8; KEY_SIZE],
) -> Result<()> {
    let effective = match policy {
        Some(p) => p.clone(),
        None => {
            get_secret_with_policy(db, user_id, category, name, key)
                .await?
                .2
        }
    };
    let (encrypted, nonce) = encrypt_secret_with_policy(key, data, &effective)?;
    let secret_type = data.secret_type().as_str().to_string();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let category = category.to_string();
    let name = name.to_string();
    let category_name = format!("{}/{}", category, name);

    let affected = db
        .write(move |conn| {
            let n = conn.execute(
                "UPDATE cred_secrets
                     SET encrypted_data = ?1, nonce = ?2, secret_type = ?3, updated_at = ?4
                     WHERE user_id = ?5 AND category = ?6 AND name = ?7",
                rusqlite::params![
                    encrypted.as_slice(),
                    nonce.as_slice(),
                    secret_type,
                    now,
                    user_id,
                    category,
                    name
                ],
            )?;
            Ok(n)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    if affected == 0 {
        return Err(CredError::NotFound(category_name));
    }

    Ok(())
}

/// Delete a secret.
#[tracing::instrument(skip(db), fields(user_id, category = %category, name = %name))]
pub async fn delete_secret(db: &Database, user_id: i64, category: &str, name: &str) -> Result<()> {
    let category = category.to_string();
    let name = name.to_string();
    let category_name = format!("{}/{}", category, name);

    let affected = db
        .write(move |conn| {
            let n = conn.execute(
                "DELETE FROM cred_secrets WHERE user_id = ?1 AND category = ?2 AND name = ?3",
                rusqlite::params![user_id, category, name],
            )?;
            Ok(n)
        })
        .await
        .map_err(|e| CredError::Database(e.to_string()))?;

    if affected == 0 {
        return Err(CredError::NotFound(category_name));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;

    async fn setup_db() -> Database {
        let db = Database::connect_memory().await.expect("db");
        db.write(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS cred_secrets (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    encrypted_data BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, category, name)
                );",
            )?;
            Ok(())
        })
        .await
        .expect("create table");
        db
    }

    #[tokio::test]
    async fn store_and_get_secret() {
        let db = setup_db().await;
        let key = derive_key(1, b"password", None);
        let data = SecretData::ApiKey {
            key: "my-api-key".into(),
            endpoint: Some("https://api.example.com".into()),
            notes: None,
        };

        let id = store_secret(&db, 1, "service", "api-key", &data, &key)
            .await
            .expect("store");
        assert!(id > 0);

        let (row, retrieved) = get_secret(&db, 1, "service", "api-key", &key)
            .await
            .expect("get");
        assert_eq!(row.name, "api-key");
        assert_eq!(row.category, "service");
        assert_eq!(row.secret_type, SecretType::ApiKey);

        match retrieved {
            SecretData::ApiKey { key, endpoint, .. } => {
                assert_eq!(key, "my-api-key");
                assert_eq!(endpoint, Some("https://api.example.com".into()));
            }
            _ => panic!("wrong type"),
        }
    }

    #[tokio::test]
    async fn list_secrets_filters_by_category() {
        let db = setup_db().await;
        let key = derive_key(1, b"password", None);

        store_secret(
            &db,
            1,
            "aws",
            "prod-key",
            &SecretData::ApiKey {
                key: "k1".into(),
                endpoint: None,
                notes: None,
            },
            &key,
        )
        .await
        .expect("store 1");

        store_secret(
            &db,
            1,
            "gcp",
            "dev-key",
            &SecretData::ApiKey {
                key: "k2".into(),
                endpoint: None,
                notes: None,
            },
            &key,
        )
        .await
        .expect("store 2");

        let all = list_secrets(&db, 1, None).await.expect("list all");
        assert_eq!(all.len(), 2);

        let aws_only = list_secrets(&db, 1, Some("aws")).await.expect("list aws");
        assert_eq!(aws_only.len(), 1);
        assert_eq!(aws_only[0].name, "prod-key");
    }

    #[tokio::test]
    async fn update_secret_changes_data() {
        let db = setup_db().await;
        let key = derive_key(1, b"password", None);

        store_secret(
            &db,
            1,
            "svc",
            "token",
            &SecretData::ApiKey {
                key: "old-key".into(),
                endpoint: None,
                notes: None,
            },
            &key,
        )
        .await
        .expect("store");

        update_secret(
            &db,
            1,
            "svc",
            "token",
            &SecretData::ApiKey {
                key: "new-key".into(),
                endpoint: Some("https://new.api".into()),
                notes: None,
            },
            &key,
        )
        .await
        .expect("update");

        let (_, data) = get_secret(&db, 1, "svc", "token", &key).await.expect("get");
        match data {
            SecretData::ApiKey { key, endpoint, .. } => {
                assert_eq!(key, "new-key");
                assert_eq!(endpoint, Some("https://new.api".into()));
            }
            _ => panic!("wrong type"),
        }
    }

    #[tokio::test]
    async fn delete_secret_removes_row() {
        let db = setup_db().await;
        let key = derive_key(1, b"password", None);

        store_secret(
            &db,
            1,
            "svc",
            "key",
            &SecretData::Note {
                content: "test".into(),
            },
            &key,
        )
        .await
        .expect("store");

        delete_secret(&db, 1, "svc", "key").await.expect("delete");

        let result = get_secret(&db, 1, "svc", "key", &key).await;
        assert!(matches!(result, Err(CredError::NotFound(_))));
    }

    #[tokio::test]
    async fn wrong_key_fails_get() {
        let db = setup_db().await;
        let key1 = derive_key(1, b"correct", None);
        let key2 = derive_key(1, b"wrong", None);

        store_secret(
            &db,
            1,
            "svc",
            "secret",
            &SecretData::Note {
                content: "hidden".into(),
            },
            &key1,
        )
        .await
        .expect("store");

        let result = get_secret(&db, 1, "svc", "secret", &key2).await;
        assert!(matches!(result, Err(CredError::Decryption(_))));
    }

    #[tokio::test]
    async fn policy_persists_and_survives_plain_update() {
        let db = setup_db().await;
        let key = derive_key(1, b"password", None);
        let policy = ProxyPolicy {
            allowed_origins: vec![crate::types::Origin {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
            }],
            extra_auth_headers: vec!["x-token".into()],
            drop_response_body: true,
        };
        let data = |k: &str| SecretData::ApiKey {
            key: k.into(),
            endpoint: None,
            notes: None,
        };

        store_secret_with_policy(&db, 1, "svc", "tok", &data("one"), &policy, &key)
            .await
            .expect("store");
        let (_, _, got) = get_secret_with_policy(&db, 1, "svc", "tok", &key)
            .await
            .expect("get");
        assert_eq!(got, policy);

        // A value-only update keeps the policy; an explicit policy replaces it.
        update_secret(&db, 1, "svc", "tok", &data("two"), &key)
            .await
            .expect("update");
        let (_, d, got) = get_secret_with_policy(&db, 1, "svc", "tok", &key)
            .await
            .expect("get");
        assert_eq!(d.primary_value(), "two");
        assert_eq!(got, policy);

        update_secret_with_policy(
            &db,
            1,
            "svc",
            "tok",
            &data("three"),
            Some(&ProxyPolicy::default()),
            &key,
        )
        .await
        .expect("update");
        let (_, _, got) = get_secret_with_policy(&db, 1, "svc", "tok", &key)
            .await
            .expect("get");
        assert!(got.is_default());
    }
}
