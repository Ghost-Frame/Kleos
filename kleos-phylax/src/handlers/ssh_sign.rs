//! Server-side SSH signing: parse an OpenSSH private key and produce an
//! SSH wire-format signature. The private key never leaves this process.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
// Must be in scope for `key.try_sign(...)` to resolve; `Signer` is the trait
// that provides the `try_sign` method used below.
use signature::Signer;
use ssh_key::PrivateKey;

use kleos_cred::storage::get_secret;
use kleos_cred::types::SecretData;
use kleos_cred::CredError;
use kleos_credd::auth::Auth;
use kleos_credd::handlers::AppError;

use crate::audit::{actions, log_phylax_audit};
use crate::models::approval::{self, ApprovalStatus};
use crate::models::ssh_settings;
use crate::state::{approval_ttl_secs, PhylaxState};

/// Error type for the pure signer.
#[derive(Debug, thiserror::Error)]
pub enum SshSignError {
    /// The stored bytes did not parse as an OpenSSH private key.
    #[error("parse private key: {0}")]
    Parse(String),
    /// The signing operation itself failed.
    #[error("sign: {0}")]
    Sign(String),
    /// Encoding the signature to wire format failed.
    #[error("encode: {0}")]
    Encode(String),
}

/// Parse an OpenSSH-format PEM private key and produce an SSH wire-format
/// signature over `data`.
///
/// Only OpenSSH-format PEM private keys (the `-----BEGIN OPENSSH PRIVATE
/// KEY-----` envelope produced by `ssh-keygen`) are accepted. PKCS#8 /
/// SEC1 PEM private keys are NOT supported.
///
/// `_flags` carries SSH agent protocol sign-request flags (bit 2 =
/// SSH_AGENT_RSA_SHA2_256, bit 4 = SSH_AGENT_RSA_SHA2_512 for RSA keys).
/// The current implementation ignores them because ed25519 has exactly one
/// signature algorithm and needs no flag-based dispatch.
pub fn sign_with_pem(pem: &str, data: &[u8], _flags: u32) -> Result<Vec<u8>, SshSignError> {
    let key =
        PrivateKey::from_openssh(pem.as_bytes()).map_err(|e| SshSignError::Parse(e.to_string()))?;
    let sig: ssh_key::Signature = key
        .try_sign(data)
        .map_err(|e| SshSignError::Sign(e.to_string()))?;
    // TryFrom<Signature> for Vec<u8> encodes to SSH wire format (algorithm-prefixed).
    let blob = Vec::<u8>::try_from(sig).map_err(|e| SshSignError::Encode(e.to_string()))?;
    Ok(blob)
}

/// Body for a sign request: hex-encoded data to sign + agent protocol flags.
#[derive(Deserialize)]
pub struct SignRequest {
    /// Hex-encoded data the SSH client wants signed.
    pub data_hex: String,
    /// SSH agent protocol sign flags (0 for ed25519).
    pub flags: u32,
}

/// Response: hex-encoded SSH wire-format signature blob.
#[derive(Serialize)]
pub struct SignResponse {
    /// Hex-encoded signature blob for SSH_AGENT_SIGN_RESPONSE.
    pub signature_hex: String,
}

/// Load the plaintext SSH private key PEM for (user, category, name) from the vault.
async fn load_ssh_pem(
    state: &PhylaxState,
    user_id: i64,
    category: &str,
    name: &str,
) -> Result<String, AppError> {
    let (_row, data) = get_secret(
        &state.inner.db,
        user_id,
        category,
        name,
        state.inner.master_key.as_ref(),
    )
    .await?;
    match data {
        SecretData::SshKey { private_key, .. } => Ok(private_key),
        _ => Err(CredError::PermissionDenied("secret is not an SSH key".into()).into()),
    }
}

/// POST /phylax/ssh/{category}/{name}/sign -- sign `data_hex` with the vault key.
/// Keys with `auto_sign=true` proceed immediately; all others block on an M3 approval.
pub async fn sign(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Path((category, name)): Path<(String, String)>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    if !auth.is_master() && !auth.can_access_category(&category) {
        return Err(CredError::PermissionDenied("category not permitted".into()).into());
    }
    // FIX 6: bad hex is a client input error (400), not a permission denial (403).
    let data =
        hex::decode(&body.data_hex).map_err(|_| CredError::InvalidInput("bad data_hex".into()))?;

    // M3 approval gate: unless this key is marked auto_sign, a human must approve.
    let auto_sign =
        ssh_settings::get_ssh_settings(&state.inner.db, auth.user_id(), &category, &name)
            .await?
            .map(|s| s.auto_sign)
            .unwrap_or(false);

    if !auto_sign {
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::seconds(approval_ttl_secs(state.phone_approval_required)))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
        // FIX 9: fall back to "master" -- without an agent name the caller used a
        // master token, and "master" is the convention used everywhere else.
        let agent_name = auth.agent_name().unwrap_or("master").to_string();
        let (ap, raw_token) = approval::create_approval_with_token(
            &state.inner.db,
            auth.user_id(),
            &agent_name,
            &category,
            &name,
            "ssh-sign",
            None,
            &expires_at,
        )
        .await?;

        if state.phone_approval_required {
            let binding = approval::bind_phone_approval(&state.inner.db, &ap).await?;
            crate::notify::notify_phone_approval(
                ap.id,
                "ssh-sign",
                &agent_name,
                &category,
                &name,
                &expires_at,
                &raw_token,
                &binding,
            )
            .await;
        }

        // FIX 1: poll at most 25 iterations (25 < 30 = CREDD_REQUEST_TIMEOUT_SECS)
        // so the DENY path below fires before the global tower timeout would cancel
        // the request, avoiding an orphaned Pending approval and a raw 408.
        // FIX 2: always update `decided` from the latest poll, not only on break.
        let mut decided = ApprovalStatus::Pending;
        for _ in 0..25 {
            let cur = approval::get_approval(&state.inner.db, ap.id).await?;
            decided = cur.status;
            if !matches!(decided, ApprovalStatus::Pending) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        if !matches!(decided, ApprovalStatus::Approved) {
            // FIX 4 (denial audit): record the sign denial before returning.
            let _ = log_phylax_audit(
                &state.inner.db,
                auth.user_id(),
                Some(&agent_name),
                None,
                None,
                None,
                None,
                actions::SSH_SIGN,
                &category,
                &name,
                false,
                None,
            )
            .await;
            return Err(CredError::PermissionDenied("sign not approved".into()).into());
        }
    }

    let pem = load_ssh_pem(&state, auth.user_id(), &category, &name).await?;
    // FIX 5: suppress internal error detail from the client; log it server-side.
    let sig = sign_with_pem(&pem, &data, body.flags).map_err(|e| {
        tracing::error!(error = %e, "ssh sign failed");
        CredError::PermissionDenied("signing failed".into())
    })?;

    // FIX 4 (success audit): record the sign success (category + name, never key material).
    let agent_name_for_audit = auth.agent_name().unwrap_or("master").to_string();
    let _ = log_phylax_audit(
        &state.inner.db,
        auth.user_id(),
        Some(&agent_name_for_audit),
        None,
        None,
        None,
        None,
        actions::SSH_SIGN,
        &category,
        &name,
        true,
        None,
    )
    .await;

    Ok(Json(SignResponse {
        signature_hex: hex::encode(sig),
    }))
}

/// GET /phylax/ssh/identities -- list this user's SSH keys (PUBLIC material only).
pub async fn identities(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = ssh_settings::list_ssh_settings(&state.inner.db, auth.user_id()).await?;
    let mut out = Vec::new();
    for s in rows {
        if !auth.is_master() && !auth.can_access_category(&s.category) {
            continue;
        }
        // Fetch the secret to obtain the public half (prefer stored public_key).
        let (_row, data) = match get_secret(
            &state.inner.db,
            auth.user_id(),
            &s.category,
            &s.secret_name,
            state.inner.master_key.as_ref(),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => continue, // settings row without a usable secret -- skip
        };
        let (private_key, stored_pub) = match data {
            SecretData::SshKey {
                private_key,
                public_key,
                ..
            } => (private_key, public_key),
            _ => continue,
        };
        // Derive public material; private_key is used only locally and never
        // included in the response, logs, or errors.
        // FIX 7: never emit a blank public key -- skip the row if encoding fails.
        let public_openssh = match stored_pub {
            Some(p) => p,
            None => match PrivateKey::from_openssh(private_key.as_bytes()) {
                Ok(k) => match k.public_key().to_openssh() {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                Err(_) => continue,
            },
        };
        out.push(json!({
            "category": s.category,
            "name": s.secret_name,
            "public_openssh": public_openssh,
            "auto_sign": s.auto_sign,
        }));
    }
    Ok(Json(json!({ "identities": out })))
}
