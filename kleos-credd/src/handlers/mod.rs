//! HTTP request handlers for credd.

pub mod agents;
pub mod bootstrap_bearer;
pub mod kleos_sync;
pub mod resolve;
pub mod secrets;
pub mod types;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use kleos_cred::crypto::decrypt;
use kleos_cred::storage::SecretRow;
use kleos_cred::types::SecretData;
use kleos_cred::CredError;

use crate::state::AppState;

/// Convert CredError to HTTP response.
pub struct AppError(CredError);

impl From<CredError> for AppError {
    fn from(e: CredError) -> Self {
        Self(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self.0 {
            CredError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            CredError::AuthFailed(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            CredError::PermissionDenied(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            CredError::KeyRevoked(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            CredError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            // SECURITY (SEC-LOW-7): internal error variants must NOT leak
            // implementation details (DB engine, encryption backend, YubiKey
            // state) to API consumers. Log the real error server-side only.
            CredError::Encryption(msg) => {
                tracing::error!("encryption error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
                )
            }
            CredError::Decryption(msg) => {
                tracing::error!("decryption error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
                )
            }
            CredError::Database(msg) => {
                tracing::error!("database error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
                )
            }
            CredError::YubiKey(msg) => {
                tracing::error!("yubikey error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}

#[derive(serde::Deserialize)]
struct KleosListResponse {
    results: Vec<KleosMemoryRow>,
}

#[derive(serde::Deserialize)]
struct KleosMemoryRow {
    content: String,
}

/// Resolve a secret from Kleos [CRED:v3] entries.
/// Fallback for when the local SQLCipher database does not have the entry.
pub async fn resolve_from_kleos(
    state: &AppState,
    category: &str,
    name: &str,
) -> Result<(SecretRow, SecretData), AppError> {
    // Reject category/name that could corrupt the V3 content-format match: the
    // target_prefix below is built from these and matched with starts_with, so
    // a `/` in category or ` = ` in name could shadow or skip a different entry
    // (read-path sibling of the CREDD-1 write-path injection).
    if !kleos_sync::is_safe_v3_category(category) || !kleos_sync::is_safe_v3_name(name) {
        return Err(
            CredError::InvalidInput(format!("unsafe characters in {}/{}", category, name)).into(),
        );
    }

    let kleos_url = kleos_lib::kleos_env("URL").map_err(|_| {
        tracing::debug!(
            "KLEOS_URL not set; cannot resolve {}/{} from Kleos",
            category,
            name
        );
        CredError::NotFound(format!(
            "{}/{} not found (no vault configured)",
            category, name
        ))
    })?;

    // The request below attaches the master/PIV-signed Bearer to KLEOS_URL.
    // Refuse to send it over plaintext http to a non-loopback host so a
    // misconfigured remote KLEOS_URL cannot leak the credential in cleartext.
    // Treat an unsafe transport as "vault unavailable" (NotFound) rather than a
    // request error, matching the unreachable-vault path below and keeping the
    // resolve semantics unchanged for callers.
    if let Err(e) = kleos_lib::net::guard_bearer_transport(&kleos_url) {
        tracing::warn!(
            "refusing to resolve {}/{} from Kleos: {} (use an https KLEOS_URL or a loopback address)",
            category,
            name,
            e
        );
        return Err(CredError::NotFound(format!(
            "{}/{} not found (vault transport is not confidential)",
            category, name
        ))
        .into());
    }

    let http = reqwest::Client::new();
    let list_url = format!("{}/list", kleos_url.trim_end_matches('/'));
    let mut req = http
        .get(&list_url)
        .query(&[("category", "credential"), ("limit", "500")]);

    // PIV signing first, bootstrap bearer fallback
    if let Some(signer) = &state.kleos_signer {
        if let Some(session) = signer.cached_session() {
            req = req.header("X-Kleos-Session", session);
        } else {
            match signer.sign_request("GET", "/list", "category=credential&limit=500", &[]) {
                Ok(signed) => req = signed.apply_headers(req),
                Err(e) => {
                    // PIV is configured but signing failed. Default to hard
                    // error to prevent silent downgrade to weaker bearer.
                    if std::env::var("KLEOS_ALLOW_CRED_FALLBACK").as_deref() == Ok("1") {
                        tracing::error!(error = %e, "PIV signing failed, KLEOS_ALLOW_CRED_FALLBACK=1 allows bearer fallback");
                        if let Some(bm) = &state.bootstrap_master {
                            req = req.header("Authorization", format!("Bearer {}", bm.as_str()));
                        }
                    } else {
                        tracing::error!(error = %e, "PIV signing failed -- refusing bearer fallback (set KLEOS_ALLOW_CRED_FALLBACK=1 to override)");
                        return Err(
                            CredError::AuthFailed(format!("PIV signing failed: {}", e)).into()
                        );
                    }
                }
            }
        }
    } else if let Some(bm) = &state.bootstrap_master {
        req = req.header("Authorization", format!("Bearer {}", bm.as_str()));
    } else {
        return Err(CredError::NotFound("no auth available for Kleos vault".into()).into());
    }

    let resp = req.send().await.map_err(|e| {
        tracing::warn!("Kleos /list failed for {}/{}: {}", category, name, e);
        CredError::NotFound(format!(
            "{}/{} not found (vault unreachable)",
            category, name
        ))
    })?;

    // Capture session token if issued
    if let Some(signer) = &state.kleos_signer {
        if let Some(session_val) = resp.headers().get("X-Kleos-Session-Issued") {
            if let Ok(s) = session_val.to_str() {
                signer.set_session(s.to_string());
            }
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        tracing::error!("Kleos /list returned {} for {}/{}", status, category, name);
        return Err(CredError::InvalidInput(format!("kleos /list error: {}", status)).into());
    }

    let list: KleosListResponse = resp.json().await.map_err(|e| {
        tracing::error!("Kleos /list parse error for {}/{}: {}", category, name, e);
        CredError::InvalidInput(format!("kleos response parse error: {}", e))
    })?;

    let target_prefix = format!(
        "[CRED:v3] {}/{} = ",
        kleos_sync::encode_v3_category(category),
        name
    );
    let entry = list
        .results
        .iter()
        .find(|m| m.content.starts_with(&target_prefix))
        .ok_or_else(|| {
            tracing::warn!("no [CRED:v3] entry for {}/{}", category, name);
            CredError::NotFound(format!("{}/{}", category, name))
        })?;

    let hex_data = entry.content[target_prefix.len()..].trim();
    let ciphertext = hex::decode(hex_data).map_err(|e| {
        tracing::error!("hex decode failed for {}/{}: {}", category, name, e);
        CredError::Decryption("corrupt cred entry: hex decode failed".into())
    })?;

    let plaintext = decrypt(state.master_key.as_ref(), &ciphertext).map_err(|e| {
        tracing::error!("decrypt failed for {}/{}: {}", category, name, e);
        CredError::Decryption("corrupt cred entry: decrypt failed".into())
    })?;

    let data: SecretData = serde_json::from_slice(&plaintext).map_err(|e| {
        tracing::error!("JSON parse failed for {}/{}: {}", category, name, e);
        CredError::InvalidInput("corrupt cred entry: JSON parse failed".into())
    })?;

    let row = SecretRow {
        id: 0,
        user_id: 1,
        name: name.to_string(),
        category: category.to_string(),
        secret_type: data.secret_type(),
        created_at: String::new(),
        updated_at: String::new(),
    };

    Ok((row, data))
}

/// Get a secret, trying local DB first, then falling back to Kleos [CRED:v3].
pub async fn get_secret_with_fallback(
    state: &AppState,
    user_id: i64,
    category: &str,
    name: &str,
) -> Result<(SecretRow, SecretData), AppError> {
    use kleos_cred::storage::get_secret;

    match get_secret(
        &state.db,
        user_id,
        category,
        name,
        state.master_key.as_ref(),
    )
    .await
    {
        Ok(result) => Ok(result),
        Err(CredError::NotFound(_)) => {
            tracing::debug!("{}/{} not in local DB, trying Kleos vault", category, name);
            resolve_from_kleos(state, category, name).await
        }
        Err(e) => Err(e.into()),
    }
}
