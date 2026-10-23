//! Secret CRUD handlers.

pub use super::types::{ListQuery, SecretListItem, StoreRequest};

use std::collections::HashSet;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde_json::{json, Value};
use tracing::warn;

use kleos_cred::audit::{log_audit, AccessTier, AuditAction};
use kleos_cred::storage::{delete_secret, list_secrets, store_secret, update_secret};
use kleos_cred::CredError;

use super::kleos_sync;
use crate::auth::Auth;
use crate::handlers::AppError;
use crate::state::AppState;

/// List secrets -- merges local DB with Kleos v3 vault.
#[tracing::instrument(skip_all, fields(handler = "credd.secrets.list"))]
pub async fn list_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AppError> {
    let local_secrets = list_secrets(&state.db, auth.user_id(), query.category.as_deref()).await?;

    let mut items: Vec<SecretListItem> = local_secrets
        .iter()
        .filter(|s| auth.can_access_category(&s.category))
        .map(|s| SecretListItem {
            service: s.category.clone(),
            key: s.name.clone(),
            secret_type: s.secret_type.to_string(),
            created_at: s.created_at.clone(),
            updated_at: s.updated_at.clone(),
        })
        .collect();

    let local_keys: HashSet<(String, String)> = local_secrets
        .iter()
        .map(|s| (s.category.clone(), s.name.clone()))
        .collect();

    // Merge v3 entries not already in local DB
    match kleos_sync::fetch_v3_entries(&state).await {
        Ok(entries) => {
            for entry in entries {
                if local_keys.contains(&(entry.category.clone(), entry.name.clone())) {
                    continue;
                }
                if !auth.can_access_category(&entry.category) {
                    continue;
                }
                let secret_type = match kleos_sync::decrypt_v3_entry(
                    &entry.hex_data,
                    state.master_key.as_ref(),
                ) {
                    Ok(data) => data.secret_type().to_string(),
                    Err(_) => "encrypted".to_string(),
                };
                items.push(SecretListItem {
                    service: entry.category,
                    key: entry.name,
                    secret_type,
                    created_at: String::new(),
                    updated_at: String::new(),
                });
            }
        }
        Err(e) => {
            warn!(error = %e, "could not fetch Kleos v3 entries for list; showing local only");
        }
    }

    Ok(Json(json!({ "secrets": items })))
}

/// Store a new secret -- dual-writes to local DB and Kleos v3.
#[tracing::instrument(skip_all, fields(handler = "credd.secrets.store"))]
pub async fn store_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((category, name)): Path<(String, String)>,
    Json(body): Json<StoreRequest>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(CredError::PermissionDenied("only master key can store secrets".into()).into());
    }

    let id = store_secret(
        &state.db,
        auth.user_id(),
        &category,
        &name,
        &body.data,
        state.master_key.as_ref(),
    )
    .await?;

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Set,
        &category,
        &name,
        None,
        true,
    )
    .await?;

    // Sync to Kleos v3 (non-fatal)
    kleos_sync::store_to_kleos(
        &state,
        &category,
        &name,
        &body.data,
        state.master_key.as_ref(),
    )
    .await;

    Ok(Json(json!({
        "id": id,
        "category": category,
        "name": name,
    })))
}

/// Get a secret.
#[tracing::instrument(skip_all, fields(handler = "credd.secrets.get"))]
pub async fn get_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((category, name)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    // This legacy endpoint returns the secret plaintext directly and is not
    // intercepted by Phylax resolve policy. Keep it master-only so an agent
    // cannot bypass approval or non-plaintext enforcement. Not mounted at all
    // under the custody profile.
    if !auth.is_master() {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Get,
            &category,
            &name,
            Some(AccessTier::Raw),
            false,
        )
        .await?;
        return Err(CredError::PermissionDenied(
            "legacy plaintext retrieval is master-only; use a non-plaintext resolve mode".into(),
        )
        .into());
    }

    if !auth.can_access_category(&category) {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Get,
            &category,
            &name,
            None,
            false,
        )
        .await?;
        return Err(
            CredError::PermissionDenied(format!("no access to category: {}", category)).into(),
        );
    }

    let (row, data) =
        super::get_secret_with_fallback(&state, auth.user_id(), &category, &name).await?;

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Get,
        &category,
        &name,
        Some(AccessTier::Raw),
        true,
    )
    .await?;

    Ok(Json(json!({
        "service": row.category,
        "key": row.name,
        "type": row.secret_type.as_str(),
        "value": data,
    })))
}

/// Update a secret -- dual-writes to local DB and Kleos v3.
#[tracing::instrument(skip_all, fields(handler = "credd.secrets.update"))]
pub async fn update_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((category, name)): Path<(String, String)>,
    Json(body): Json<StoreRequest>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can update secrets".into()).into(),
        );
    }

    update_secret(
        &state.db,
        auth.user_id(),
        &category,
        &name,
        &body.data,
        state.master_key.as_ref(),
    )
    .await?;

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Update,
        &category,
        &name,
        None,
        true,
    )
    .await?;

    // Sync to Kleos v3: delete old + store new (non-fatal)
    kleos_sync::delete_from_kleos(&state, &category, &name).await;
    kleos_sync::store_to_kleos(
        &state,
        &category,
        &name,
        &body.data,
        state.master_key.as_ref(),
    )
    .await;

    Ok(Json(json!({
        "category": category,
        "name": name,
        "updated": true,
    })))
}

/// Delete a secret -- dual-deletes from local DB and Kleos v3.
#[tracing::instrument(skip_all, fields(handler = "credd.secrets.delete"))]
pub async fn delete_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((category, name)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(
            CredError::PermissionDenied("only master key can delete secrets".into()).into(),
        );
    }

    delete_secret(&state.db, auth.user_id(), &category, &name).await?;

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Delete,
        &category,
        &name,
        None,
        true,
    )
    .await?;

    // Sync delete to Kleos v3 (non-fatal)
    kleos_sync::delete_from_kleos(&state, &category, &name).await;

    Ok(Json(json!({
        "category": category,
        "name": name,
        "deleted": true,
    })))
}

/// Pull all v3 entries from Kleos into local DB. Idempotent. Master-only:
/// like store/update/delete this writes decrypted secret material into the
/// local store under `auth.user_id()`, so a non-master caller (notably a
/// BootstrapAgent, whose `user_id()` is also 0) must not be able to populate
/// the master-owned secret store.
#[tracing::instrument(skip_all, fields(handler = "credd.secrets.sync"))]
pub async fn sync_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    if !auth.is_master() {
        return Err(CredError::PermissionDenied("only master key can sync secrets".into()).into());
    }

    let entries = kleos_sync::fetch_v3_entries(&state)
        .await
        .map_err(CredError::InvalidInput)?;

    let mut synced = 0u32;
    let mut skipped = 0u32;
    let mut errors = 0u32;

    for entry in &entries {
        // Check if already local
        match kleos_cred::storage::get_secret(
            &state.db,
            auth.user_id(),
            &entry.category,
            &entry.name,
            state.master_key.as_ref(),
        )
        .await
        {
            Ok(_) => {
                skipped += 1;
                continue;
            }
            Err(CredError::NotFound(_)) => {}
            Err(_) => {
                skipped += 1;
                continue;
            }
        }

        let data = match kleos_sync::decrypt_v3_entry(&entry.hex_data, state.master_key.as_ref()) {
            Ok(d) => d,
            Err(e) => {
                warn!(category = %entry.category, name = %entry.name, error = %e, "failed to decrypt v3 entry during sync");
                errors += 1;
                continue;
            }
        };

        match store_secret(
            &state.db,
            auth.user_id(),
            &entry.category,
            &entry.name,
            &data,
            state.master_key.as_ref(),
        )
        .await
        {
            Ok(_) => synced += 1,
            Err(e) => {
                warn!(category = %entry.category, name = %entry.name, error = %e, "failed to store v3 entry locally during sync");
                errors += 1;
            }
        }
    }

    Ok(Json(json!({
        "synced": synced,
        "skipped": skipped,
        "errors": errors,
        "total_v3": entries.len(),
    })))
}
