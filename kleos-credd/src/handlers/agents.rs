//! Agent key management handlers.

pub use super::types::{AgentKeyInfo, CreateKeyRequest, CustodyCreateKeyRequest};

use std::path::{Component, Path as FsPath};

use axum::{
    extract::{Extension, Path, State},
    Json,
};
use serde_json::{json, Value};
use zeroize::Zeroize;

use kleos_cred::agent_keys::{
    create_agent_key, delete_agent_key, list_agent_keys, revoke_agent_key, AgentKeyPermissions,
};
use kleos_cred::CredError;

use crate::auth::{Auth, IsUnixSocket};
use crate::handlers::AppError;
use crate::state::AppState;

/// List agent keys.
#[tracing::instrument(skip_all, fields(handler = "credd.agents.list"))]
pub async fn list_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can list agent keys".into()).into(),
        );
    }

    let keys = list_agent_keys(&state.db, auth.user_id()).await?;
    let items: Vec<AgentKeyInfo> = keys
        .into_iter()
        .map(|k| {
            let is_valid = k.is_valid();
            AgentKeyInfo {
                name: k.name,
                categories: k.permissions.categories,
                created_at: k.created_at,
                revoked_at: k.revoked_at,
                is_valid,
            }
        })
        .collect();

    Ok(Json(json!({ "keys": items })))
}

/// Create a new agent key.
#[tracing::instrument(skip_all, fields(handler = "credd.agents.create"))]
pub async fn create_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(body): Json<CreateKeyRequest>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can create agent keys".into()).into(),
        );
    }

    let permissions = AgentKeyPermissions::new(body.categories, Vec::new());

    let (raw_key, key_info) =
        create_agent_key(&state.db, auth.user_id(), &body.name, &permissions).await?;

    Ok(Json(json!({
        "name": key_info.name,
        "key": raw_key,
        "created_at": key_info.created_at,
        "note": "Save this key securely - it cannot be retrieved later",
    })))
}

/// Number of hex characters of the stored key hash returned as a fingerprint.
const FINGERPRINT_HEX_LEN: usize = 16;

/// Short, non-reversible identifier for an agent key (prefix of its stored
/// SHA-256 hash). Safe to return and log; it cannot authenticate anything.
fn key_fingerprint(key_hash: &str) -> String {
    key_hash.chars().take(FINGERPRINT_HEX_LEN).collect()
}

/// Validate a caller-supplied key file path: absolute, no NUL, no `..`.
fn validate_key_path(raw: &str) -> Result<&FsPath, CredError> {
    let path = FsPath::new(raw);
    if raw.is_empty() || raw.contains('\0') || !path.is_absolute() {
        return Err(CredError::InvalidInput(
            "key_path must be an absolute path".into(),
        ));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(CredError::InvalidInput(
            "key_path must not contain `..`".into(),
        ));
    }
    Ok(path)
}

/// Create the key file with `O_EXCL` and mode 0600. The file is created
/// before the key exists so a bad path fails without minting a key.
#[cfg(unix)]
fn create_key_file(path: &FsPath) -> Result<std::fs::File, CredError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                CredError::InvalidInput("key_path already exists".into())
            } else {
                tracing::error!(error = %e, path = %path.display(), "cannot create agent key file");
                CredError::InvalidInput("key_path cannot be created".into())
            }
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| {
            tracing::error!(error = %e, path = %path.display(), "cannot chmod agent key file");
            CredError::InvalidInput("key_path cannot be created".into())
        })?;
    Ok(file)
}

/// Non-Unix platforms cannot guarantee a 0600 key file, so custody refuses.
#[cfg(not(unix))]
fn create_key_file(_path: &FsPath) -> Result<std::fs::File, CredError> {
    Err(CredError::InvalidInput(
        "custody key files require a Unix platform".into(),
    ))
}

/// Create a new agent key under the custody profile.
///
/// Reachable only over the Unix socket by the master identity. The raw key is
/// written to `key_path` (0600, `O_EXCL`) and never appears in the response,
/// which carries only the name, a fingerprint, and the creation time. If
/// anything fails after the key row exists, the row and the file are removed.
#[tracing::instrument(skip_all, fields(handler = "credd.agents.create_custody"))]
pub async fn create_custody_handler(
    Auth(auth): Auth,
    unix: Option<Extension<IsUnixSocket>>,
    State(state): State<AppState>,
    Json(body): Json<CustodyCreateKeyRequest>,
) -> Result<Json<Value>, AppError> {
    use std::io::Write;

    if !matches!(unix, Some(Extension(IsUnixSocket(true)))) {
        return Err(CredError::PermissionDenied(
            "agent creation is only available over the Unix socket under the custody profile"
                .into(),
        )
        .into());
    }
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can create agent keys".into()).into(),
        );
    }

    let path = validate_key_path(&body.key_path)?;
    let mut file = create_key_file(path)?;

    let permissions = AgentKeyPermissions::new(body.categories, Vec::new());
    let (mut raw_key, key_info) =
        match create_agent_key(&state.db, auth.user_id(), &body.name, &permissions).await {
            Ok(created) => created,
            Err(e) => {
                let _ = std::fs::remove_file(path);
                return Err(e.into());
            }
        };

    let written = file
        .write_all(raw_key.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    raw_key.zeroize();
    if let Err(e) = written {
        tracing::error!(error = %e, path = %path.display(), "cannot write agent key file");
        let _ = std::fs::remove_file(path);
        let _ = delete_agent_key(&state.db, auth.user_id(), &body.name).await;
        return Err(CredError::InvalidInput("key_path cannot be written".into()).into());
    }

    Ok(Json(json!({
        "name": key_info.name,
        "fingerprint": key_fingerprint(&key_info.key_hash),
        "created_at": key_info.created_at,
    })))
}

/// Revoke an agent key.
#[tracing::instrument(skip_all, fields(handler = "credd.agents.revoke"))]
pub async fn revoke_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can revoke agent keys".into()).into(),
        );
    }

    revoke_agent_key(&state.db, auth.user_id(), &name).await?;

    Ok(Json(json!({
        "name": name,
        "revoked": true,
    })))
}

/// Delete an agent key entirely.
#[tracing::instrument(skip_all, fields(handler = "credd.agents.delete"))]
pub async fn delete_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can delete agent keys".into()).into(),
        );
    }

    delete_agent_key(&state.db, auth.user_id(), &name).await?;

    Ok(Json(json!({
        "name": name,
        "deleted": true,
    })))
}
