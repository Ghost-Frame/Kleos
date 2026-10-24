//! X.509 handlers: leaf rotation under a vault-held CA, and public-half lookup.
//!
//! - `POST /custody/x509/rotate-leaf` (custody profile only) signs a fresh
//!   client certificate with a CA key that never leaves the vault, stores the
//!   new private key in place of the old one, keeps the old material under a
//!   rollback name, and returns only the new certificate.
//! - `POST /resolve/public` returns the public half of a secret (certificate
//!   and chain of a bundle, public key of an SSH key) and refuses everything
//!   else, so it can never return a private key.
//!
//! No handler logs a request body, a secret, or a key; audit rows carry the
//! agent, category and secret name only.

use std::time::SystemTime;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use kleos_cred::audit::{log_audit, AuditAction};
use kleos_cred::storage::{
    delete_secret, get_secret_with_policy, store_secret_with_policy, update_secret_with_policy,
};
use kleos_cred::types::{ProxyPolicy, SecretData, X509Material};
use kleos_cred::CredError;

use super::kleos_sync;
use crate::auth::{Auth, AuthInfo};
use crate::handlers::AppError;
use crate::state::AppState;
use crate::x509 as pki;

/// Serializes rotations so two concurrent calls on one leaf cannot interleave
/// the rollback write and the leaf update (the storage layer upserts, so a lost
/// update would otherwise be silent).
static ROTATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A secret named by category and name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Category the secret lives in.
    pub category: String,
    /// Secret name within the category.
    pub name: String,
}

/// Body of `POST /custody/x509/rotate-leaf`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateLeafRequest {
    /// The CA bundle whose key signs the replacement.
    pub ca: SecretRef,
    /// The leaf bundle to replace; must be issued by `ca`.
    pub leaf: SecretRef,
    /// Lifetime of the new certificate in days, 1..=398 (default 90).
    #[serde(default)]
    pub lifetime_days: Option<u32>,
    /// When set, rotate only if the current leaf expires within this many
    /// days; otherwise report the current certificate and change nothing.
    #[serde(default)]
    pub rotate_within_days: Option<u32>,
}

/// Result of a rotation request. Public data only.
#[derive(Debug, Clone, Serialize)]
pub struct RotateLeafResponse {
    /// True when a new certificate was issued and stored.
    pub rotated: bool,
    /// Lowercase hex serial of the (new, or unchanged) leaf certificate.
    pub serial_hex: String,
    /// `notAfter` of that certificate, RFC 3339 UTC.
    pub not_after: String,
    /// PEM of that certificate.
    pub certificate_pem: String,
    /// Name the previous material was kept under; `None` when nothing rotated.
    pub rollback_name: Option<String>,
}

/// Body of `POST /resolve/public`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRequest {
    /// Category the secret lives in.
    pub category: String,
    /// Secret name within the category.
    pub name: String,
}

/// Public half of a secret.
#[derive(Debug, Clone, Serialize)]
pub struct PublicResponse {
    /// Type label of the secret: `x509_bundle` or `ssh_key`.
    pub secret_type: String,
    /// Leaf certificate PEM (bundles).
    pub certificate_pem: Option<String>,
    /// Intermediate chain PEM (bundles with a chain).
    pub chain_pem: Option<String>,
    /// OpenSSH public key (SSH keys).
    pub public_key: Option<String>,
}

/// A 400 with a fixed message.
fn invalid(message: &str) -> AppError {
    CredError::InvalidInput(message.to_string()).into()
}

/// Audit a refused attempt on `category`/`name` and build the 403 for it.
async fn deny_category(
    state: &AppState,
    auth: &AuthInfo,
    action: AuditAction,
    category: &str,
    name: &str,
) -> AppError {
    // The refusal stands even if the audit write fails; the failure is logged
    // by the storage layer.
    let _ = log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        action,
        category,
        name,
        None,
        false,
    )
    .await;
    CredError::PermissionDenied(format!("no access to category: {category}")).into()
}

/// The bundle behind `data`, or a 400 naming `role` when it is not one.
fn require_bundle(data: &SecretData, role: &str) -> Result<X509Material, AppError> {
    data.as_x509_bundle()?
        .ok_or_else(|| invalid(&format!("{role} secret is not an x509 bundle")))
}

/// `notAfter` as an RFC 3339 UTC string.
fn rfc3339(unix_secs: u64) -> String {
    i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0))
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Rotate the leaf named in the request under the named CA.
///
/// Gates, in order: category access on both secrets (403, audited); lifetime
/// range (400); both secrets must be x509 bundles (400); the CA key must match
/// the CA certificate and the CA must be unexpired (400); the leaf must be
/// issued by the CA, by issuer name and by signature (403). With
/// `rotate_within_days` set and the leaf not yet inside the window, nothing is
/// written. Otherwise the previous material is stored first under
/// `<leaf>-rollback-<old serial hex>` (400 if that name exists, before the leaf
/// is touched), then the leaf is replaced in place keeping its proxy policy.
#[tracing::instrument(skip_all, fields(handler = "credd.x509.rotate_leaf"))]
pub async fn rotate_leaf(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(body): Json<RotateLeafRequest>,
) -> Result<Json<RotateLeafResponse>, AppError> {
    for reference in [&body.ca, &body.leaf] {
        if !auth.can_access_category(&reference.category) {
            return Err(deny_category(
                &state,
                &auth,
                AuditAction::Update,
                &reference.category,
                &reference.name,
            )
            .await);
        }
    }

    let lifetime_days = body
        .lifetime_days
        .unwrap_or(pki::DEFAULT_LEAF_LIFETIME_DAYS);
    if !(1..=pki::MAX_LEAF_LIFETIME_DAYS).contains(&lifetime_days) {
        return Err(invalid("lifetime_days must be between 1 and 398"));
    }
    if body.ca.category == body.leaf.category && body.ca.name == body.leaf.name {
        return Err(invalid("ca and leaf must be different secrets"));
    }

    let _rotation = ROTATION_LOCK.lock().await;

    let (_ca_row, ca_data, _ca_policy) = super::get_secret_and_policy_with_fallback(
        &state,
        auth.user_id(),
        &body.ca.category,
        &body.ca.name,
    )
    .await?;
    let (leaf_row, leaf_data, leaf_policy) = super::get_secret_and_policy_with_fallback(
        &state,
        auth.user_id(),
        &body.leaf.category,
        &body.leaf.name,
    )
    .await?;
    // A row id of 0 marks a secret served from the Kleos vault fallback; it
    // has no local row to update in place.
    if leaf_row.id == 0 {
        return Err(invalid(
            "leaf must be stored in the local vault to be rotated",
        ));
    }

    let ca_material = require_bundle(&ca_data, "ca")?;
    let leaf_material = require_bundle(&leaf_data, "leaf")?;
    let ca_cert = pki::parse_certificate(&ca_material.certificate_pem)
        .map_err(|_| invalid("ca certificate is not a valid PEM certificate"))?;
    let ca_key = pki::parse_signing_key(&ca_material.private_key_pem)
        .map_err(|_| invalid("ca private key is not a PKCS#8 P-256 key"))?;
    let leaf_cert = pki::parse_certificate(&leaf_material.certificate_pem)
        .map_err(|_| invalid("leaf certificate is not a valid PEM certificate"))?;

    if !pki::key_matches_certificate(&ca_cert, &ca_key) {
        return Err(invalid("ca private key does not match the ca certificate"));
    }
    let now = SystemTime::now();
    let now_secs = pki::unix_secs(now);
    if pki::not_after_unix(&ca_cert) <= now_secs {
        return Err(invalid("ca certificate has expired"));
    }
    if !pki::verify_issued_by(&leaf_cert, &ca_cert) {
        let _ = log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Update,
            &body.leaf.category,
            &body.leaf.name,
            None,
            false,
        )
        .await;
        return Err(
            CredError::PermissionDenied("leaf is not issued by the given CA".into()).into(),
        );
    }

    let old_not_after = pki::not_after_unix(&leaf_cert);
    let old_serial = pki::serial_hex(&leaf_cert);
    if let Some(window_days) = body.rotate_within_days {
        let window_secs = u64::from(window_days) * 24 * 60 * 60;
        if old_not_after.saturating_sub(now_secs) > window_secs {
            return Ok(Json(RotateLeafResponse {
                rotated: false,
                serial_hex: old_serial,
                not_after: rfc3339(old_not_after),
                certificate_pem: leaf_material.certificate_pem,
                rollback_name: None,
            }));
        }
    }

    let rollback_name = format!("{}-rollback-{}", body.leaf.name, old_serial);
    match get_secret_with_policy(
        &state.db,
        auth.user_id(),
        &body.leaf.category,
        &rollback_name,
        state.master_key.as_ref(),
    )
    .await
    {
        Ok(_) => return Err(invalid("rollback name already exists")),
        Err(CredError::NotFound(_)) => {}
        Err(other) => return Err(other.into()),
    }

    let issued = pki::issue_replacement_leaf(&ca_cert, &ca_key, &leaf_cert, lifetime_days, now)
        .map_err(|e| CredError::Encryption(format!("x509 issuance failed: {e}")))?;

    // Rollback first: if anything after this fails the old material is intact
    // in both places, and the leaf itself has not been touched yet.
    let rollback_data = SecretData::X509Bundle {
        certificate_pem: leaf_material.certificate_pem.clone(),
        private_key_pem: leaf_material.private_key_pem.clone(),
        chain_pem: leaf_material.chain_pem.clone(),
    };
    // The rollback copy carries no origins: the key it holds is the one being
    // retired, so it must not be usable through the proxy until an operator
    // opts in.
    let rollback_policy = ProxyPolicy::default();
    store_secret_with_policy(
        &state.db,
        auth.user_id(),
        &body.leaf.category,
        &rollback_name,
        &rollback_data,
        &rollback_policy,
        state.master_key.as_ref(),
    )
    .await?;
    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Set,
        &body.leaf.category,
        &rollback_name,
        None,
        true,
    )
    .await?;

    let new_data = SecretData::X509Bundle {
        certificate_pem: issued.certificate_pem.clone(),
        private_key_pem: issued.private_key_pem.to_string(),
        chain_pem: leaf_material.chain_pem.clone(),
    };
    // `None` keeps the stored proxy policy of the leaf.
    if let Err(error) = update_secret_with_policy(
        &state.db,
        auth.user_id(),
        &body.leaf.category,
        &body.leaf.name,
        &new_data,
        None,
        state.master_key.as_ref(),
    )
    .await
    {
        // Undo the rollback row so a retry is not blocked by its own name.
        let _ = delete_secret(
            &state.db,
            auth.user_id(),
            &body.leaf.category,
            &rollback_name,
        )
        .await;
        return Err(error.into());
    }
    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Set,
        &body.leaf.category,
        &body.leaf.name,
        None,
        true,
    )
    .await?;

    // Keep the Kleos v3 mirror in step with the vault (non-fatal, like the
    // store and update handlers).
    kleos_sync::store_to_kleos(
        &state,
        &body.leaf.category,
        &rollback_name,
        &rollback_data,
        &rollback_policy,
        state.master_key.as_ref(),
    )
    .await;
    kleos_sync::store_to_kleos(
        &state,
        &body.leaf.category,
        &body.leaf.name,
        &new_data,
        &leaf_policy,
        state.master_key.as_ref(),
    )
    .await;

    Ok(Json(RotateLeafResponse {
        rotated: true,
        serial_hex: issued.serial_hex,
        not_after: rfc3339(issued.not_after_unix),
        certificate_pem: issued.certificate_pem,
        rollback_name: Some(rollback_name),
    }))
}

/// Return the public half of a secret.
///
/// An x509 bundle (typed or legacy) yields its certificate and chain; an SSH
/// key yields its public key (400 when none is stored). Every other type is a
/// 400 "secret has no public half": there is no code path that returns a
/// private key or any other secret field.
#[tracing::instrument(skip_all, fields(handler = "credd.x509.public"))]
pub async fn public_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<PublicRequest>,
) -> Result<Json<PublicResponse>, AppError> {
    if !auth.can_access_category(&req.category) {
        return Err(deny_category(
            &state,
            &auth,
            AuditAction::Resolve,
            &req.category,
            &req.name,
        )
        .await);
    }

    let (_row, data) =
        super::get_secret_with_fallback(&state, auth.user_id(), &req.category, &req.name).await?;

    let response = match public_half(&data) {
        Ok(response) => response,
        Err(error) => {
            let _ = log_audit(
                &state.db,
                auth.user_id(),
                auth.agent_name(),
                AuditAction::Resolve,
                &req.category,
                &req.name,
                None,
                false,
            )
            .await;
            return Err(error);
        }
    };

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Resolve,
        &req.category,
        &req.name,
        None,
        true,
    )
    .await?;
    Ok(Json(response))
}

/// Extract only the public fields of `data`, or a 400 when it has none.
fn public_half(data: &SecretData) -> Result<PublicResponse, AppError> {
    if let Some(bundle) = data.as_x509_bundle()? {
        return Ok(PublicResponse {
            secret_type: "x509_bundle".to_string(),
            certificate_pem: Some(bundle.certificate_pem),
            chain_pem: bundle.chain_pem,
            public_key: None,
        });
    }
    match data {
        SecretData::SshKey {
            public_key: Some(public_key),
            ..
        } => Ok(PublicResponse {
            secret_type: "ssh_key".to_string(),
            certificate_pem: None,
            chain_pem: None,
            public_key: Some(public_key.clone()),
        }),
        SecretData::SshKey {
            public_key: None, ..
        } => Err(invalid("ssh key has no stored public key")),
        _ => Err(invalid("secret has no public half")),
    }
}

/// Unit tests for the pure public-half selection.
#[cfg(test)]
mod tests {
    use super::*;

    /// The public half of `data`, panicking when it has none.
    fn half(data: &SecretData) -> PublicResponse {
        match public_half(data) {
            Ok(response) => response,
            Err(_) => panic!("expected a public half"),
        }
    }

    /// Only bundles and SSH keys with a public key have a public half.
    #[test]
    fn public_half_selection() {
        let bundle = SecretData::X509Bundle {
            certificate_pem: "CERT".into(),
            private_key_pem: "PRIVATE".into(),
            chain_pem: Some("CHAIN".into()),
        };
        let shown = half(&bundle);
        assert_eq!(shown.certificate_pem.as_deref(), Some("CERT"));
        assert_eq!(shown.chain_pem.as_deref(), Some("CHAIN"));
        let json = serde_json::to_string(&shown).expect("serialize");
        assert!(!json.contains("PRIVATE"), "{json}");

        let ssh = SecretData::SshKey {
            private_key: "PRIVATE".into(),
            public_key: Some("ssh-ed25519 AAAA".into()),
            passphrase: None,
        };
        let shown = half(&ssh);
        assert_eq!(shown.public_key.as_deref(), Some("ssh-ed25519 AAAA"));
        assert!(!serde_json::to_string(&shown)
            .expect("serialize")
            .contains("PRIVATE"));

        let bare_ssh = SecretData::SshKey {
            private_key: "PRIVATE".into(),
            public_key: None,
            passphrase: None,
        };
        assert!(public_half(&bare_ssh).is_err());
        let api = SecretData::ApiKey {
            key: "k".into(),
            endpoint: None,
            notes: None,
        };
        assert!(public_half(&api).is_err());
    }

    /// Timestamps render as RFC 3339 UTC with second precision.
    #[test]
    fn rfc3339_formats_utc_seconds() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(86_400), "1970-01-02T00:00:00Z");
    }
}
