//! SSH certificate authority handlers.
//!
//! Authorization model (decision 2026-06-06): the SSH CA is a high-privilege
//! capability -- a signed cert can grant fleet-wide SSH access. Both endpoints
//! require an authenticated principal that is either a master token (signs
//! directly, for scripted `fallback-up` on an anchor) or has cleared an M3
//! approval (push to phone; a human approves each signing).
//!
//! On top of that, every request is bounded server-side regardless of caller:
//! the validity interval (`ttl`) is parsed and capped (see `max_ttl_secs`);
//! requested principals are checked against an optional allowlist; and
//! `identity`/`agent` are restricted to filename-safe characters so they cannot
//! traverse paths when the signer shells out to `cred ssh-ca`. Server
//! filesystem paths are never returned to the caller.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kleos_cred::CredError;
use kleos_credd::auth::Auth;
use kleos_credd::handlers::AppError;

use crate::audit::{actions, log_phylax_audit};
use crate::models::approval::{self, ApprovalStatus};
use crate::state::{approval_ttl_secs, PhylaxState};

/// Default ceiling on certificate validity when `KLEOS_SSH_CA_MAX_TTL_SECS` is
/// unset: 24h. The fleet's operational norm is 12h self-expiring certs, so this
/// leaves headroom while still bounding a stolen credential's blast radius.
const DEFAULT_MAX_TTL_SECS: i64 = 86_400;

/// Audit/approval category used for all SSH CA operations.
const SSH_CA_CATEGORY: &str = "ssh-ca";

/// Request body for signing caller-provided SSH public key material.
#[derive(Deserialize)]
pub struct SignRequest {
    /// SSH certificate key identity.
    pub identity: String,
    /// SSH authorized principal list.
    pub principal: String,
    /// OpenSSH validity interval such as `+5m` or `+2h`.
    pub ttl: String,
    /// OpenSSH public key text to sign.
    pub public_key: Option<String>,
}

/// Request body for minting an agent keypair and SSH certificate.
#[derive(Deserialize)]
pub struct MintRequest {
    /// Agent name used as key identity and output filename.
    pub agent: String,
    /// SSH authorized principal list.
    pub principal: String,
    /// OpenSSH validity interval such as `+5m` or `+2h`.
    pub ttl: String,
}

/// Sign caller-provided SSH public key material through the Phylax SSH CA.
pub async fn sign(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<SignRequest>,
) -> Result<Json<Value>, AppError> {
    // Input validation (400) before any authorization side effects.
    validate_identity("identity", &body.identity)?;
    validate_principals(&body.principal)?;
    validate_ttl(&body.ttl)?;
    let public_key = body.public_key.as_deref().ok_or_else(|| {
        CredError::InvalidInput("public_key is required for SSH CA signing".into())
    })?;
    validate_public_key(public_key)?;

    // Authorization: master signs directly; everyone else goes through M3.
    authorize_or_approve(&state, &auth, actions::SSH_CA_SIGN, &body.identity).await?;

    let signed =
        state
            .ssh_ca_signer
            .sign(&body.identity, &body.principal, &body.ttl, public_key)?;

    let _ = log_phylax_audit(
        &state.inner.db,
        auth.user_id(),
        Some(auth.agent_name().unwrap_or("master")),
        None,
        None,
        None,
        None,
        actions::SSH_CA_SIGN,
        SSH_CA_CATEGORY,
        &body.identity,
        true,
        None,
    )
    .await;

    Ok(Json(json!({
        "identity": body.identity,
        "principal": body.principal,
        "ttl": body.ttl,
        "cert_public_key": signed.cert_public_key,
    })))
}

/// Mint an agent keypair and SSH certificate through the Phylax SSH CA.
pub async fn mint(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<MintRequest>,
) -> Result<Json<Value>, AppError> {
    // Input validation (400). `agent` is filename-safe so it cannot traverse
    // paths inside the downstream `cred ssh-ca mint --agent` invocation.
    validate_identity("agent", &body.agent)?;
    validate_principals(&body.principal)?;
    validate_ttl(&body.ttl)?;

    authorize_or_approve(&state, &auth, actions::SSH_CA_MINT, &body.agent).await?;

    let minted = state
        .ssh_ca_signer
        .mint(&body.agent, &body.principal, &body.ttl)?;

    let _ = log_phylax_audit(
        &state.inner.db,
        auth.user_id(),
        Some(auth.agent_name().unwrap_or("master")),
        None,
        None,
        None,
        None,
        actions::SSH_CA_MINT,
        SSH_CA_CATEGORY,
        &body.agent,
        true,
        None,
    )
    .await;

    // Server filesystem paths (`key_path`/`cert_path`) are deliberately omitted
    // from the response: they live on the Phylax host, are useless to a remote
    // caller, and leak the host's storage layout.
    Ok(Json(json!({
        "agent": body.agent,
        "principal": body.principal,
        "ttl": body.ttl,
        "cert_public_key": minted.cert_public_key,
    })))
}

/// Authorize a CA operation: a master token proceeds directly; any other
/// authenticated caller must clear an M3 approval (push-to-phone, human decides).
///
/// On denial this records an audit entry and returns 403. `secret_name` is the
/// identity/agent the cert is being requested for (shown to the approver).
async fn authorize_or_approve(
    state: &PhylaxState,
    auth: &kleos_credd::auth::AuthInfo,
    action: &str,
    secret_name: &str,
) -> Result<(), AppError> {
    if auth.is_master() {
        return Ok(());
    }

    let agent_name = auth.agent_name().unwrap_or("unknown").to_string();
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(approval_ttl_secs(state.phone_approval_required)))
    .format("%Y-%m-%d %H:%M:%S")
    .to_string();
    let (ap, raw_token) = approval::create_approval_with_token(
        &state.inner.db,
        auth.user_id(),
        &agent_name,
        SSH_CA_CATEGORY,
        secret_name,
        action,
        None,
        &expires_at,
    )
    .await?;

    if state.phone_approval_required {
        let binding = approval::bind_phone_approval(&state.inner.db, &ap).await?;
        crate::notify::notify_phone_approval(
            ap.id,
            action,
            &agent_name,
            SSH_CA_CATEGORY,
            secret_name,
            &expires_at,
            &raw_token,
            &binding,
        )
        .await;
    } else {
        crate::notify::notify_approval(
            ap.id,
            action,
            &agent_name,
            SSH_CA_CATEGORY,
            secret_name,
            &expires_at,
            &raw_token,
        )
        .await;
    }

    // Poll for up to ~110 iterations (< the 120s per-route SSH CA timeout) so a
    // human has time to receive the push and tap before the request is cancelled.
    let mut decided = ApprovalStatus::Pending;
    for _ in 0..110 {
        let cur = approval::get_approval(&state.inner.db, ap.id).await?;
        decided = cur.status;
        if !matches!(decided, ApprovalStatus::Pending) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    if !matches!(decided, ApprovalStatus::Approved) {
        let _ = log_phylax_audit(
            &state.inner.db,
            auth.user_id(),
            Some(&agent_name),
            None,
            None,
            None,
            None,
            action,
            SSH_CA_CATEGORY,
            secret_name,
            false,
            None,
        )
        .await;
        return Err(CredError::PermissionDenied("ssh-ca operation not approved".into()).into());
    }
    Ok(())
}

/// Validate an identity/agent name: non-empty and restricted to characters that
/// are safe as a filename component (`[A-Za-z0-9_-]`). This blocks path
/// traversal (`/`, `..`) and shell-hostile characters reaching the signer.
fn validate_identity(field: &str, value: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(CredError::InvalidInput(format!("{field} is required")).into());
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CredError::InvalidInput(format!(
            "{field} may only contain letters, digits, '-' and '_'"
        ))
        .into());
    }
    Ok(())
}

/// Validate the requested principal list: non-empty, and -- when
/// `KLEOS_SSH_CA_ALLOWED_PRINCIPALS` is configured -- every requested principal
/// must appear in that comma-separated allowlist. When the allowlist is unset,
/// principals are bounded only by the master-trust / M3-approval gate above.
fn validate_principals(principal: &str) -> Result<(), AppError> {
    let requested: Vec<&str> = principal
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if requested.is_empty() {
        return Err(CredError::InvalidInput("principal is required".into()).into());
    }

    if let Ok(raw) = std::env::var("KLEOS_SSH_CA_ALLOWED_PRINCIPALS") {
        let allowed: Vec<String> = raw
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if !allowed.is_empty() {
            for p in &requested {
                if !allowed.iter().any(|a| a == p) {
                    return Err(CredError::PermissionDenied(format!(
                        "principal '{p}' is not in the SSH CA allowlist"
                    ))
                    .into());
                }
            }
        }
    }
    Ok(())
}

/// Configured maximum certificate validity in seconds.
fn max_ttl_secs() -> i64 {
    std::env::var("KLEOS_SSH_CA_MAX_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_TTL_SECS)
}

/// Validate and bound an OpenSSH relative validity interval (`+5m`, `+2h`,
/// `+1d12h`, ...). Rejects anything that is not a `+`-prefixed sequence of
/// `<digits><unit>` groups (unit in w/d/h/m/s) and anything exceeding the cap.
fn validate_ttl(ttl: &str) -> Result<(), AppError> {
    let secs = parse_relative_ttl_secs(ttl).ok_or_else(|| {
        CredError::InvalidInput("ttl must be a relative interval like +1h".into())
    })?;
    let max = max_ttl_secs();
    if secs > max {
        return Err(CredError::InvalidInput(format!(
            "ttl exceeds the maximum allowed validity ({max}s)"
        ))
        .into());
    }
    Ok(())
}

/// Parse a `+`-prefixed OpenSSH relative interval into seconds. Returns `None`
/// for any malformed input or a zero-length interval.
fn parse_relative_ttl_secs(ttl: &str) -> Option<i64> {
    let rest = ttl.strip_prefix('+')?;
    if rest.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    let mut digits = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        if digits.is_empty() {
            return None; // unit with no preceding number
        }
        let n: i64 = digits.parse().ok()?;
        let unit = match c {
            'w' => 604_800,
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        total = total.checked_add(n.checked_mul(unit)?)?;
        digits.clear();
    }
    // A trailing bare number (no unit) is invalid for ssh-keygen's `+` form.
    if !digits.is_empty() {
        return None;
    }
    if total <= 0 {
        return None;
    }
    Some(total)
}

/// Validate OpenSSH public key text before invoking the signer.
fn validate_public_key(public_key: &str) -> Result<(), AppError> {
    if !public_key.starts_with("ssh-") && !public_key.starts_with("ecdsa-") {
        return Err(
            CredError::InvalidInput("public_key must be an OpenSSH public key".into()).into(),
        );
    }
    Ok(())
}

#[cfg(test)]
/// SSH CA input-validation tests.
mod tests {
    use super::*;

    /// Common TTL suffixes convert to the expected number of seconds.
    #[test]
    fn ttl_parses_common_intervals() {
        assert_eq!(parse_relative_ttl_secs("+5m"), Some(300));
        assert_eq!(parse_relative_ttl_secs("+2h"), Some(7_200));
        assert_eq!(parse_relative_ttl_secs("+1d"), Some(86_400));
        assert_eq!(parse_relative_ttl_secs("+1d12h"), Some(86_400 + 43_200));
        assert_eq!(parse_relative_ttl_secs("+1w"), Some(604_800));
    }

    /// Malformed and zero TTL values are rejected.
    #[test]
    fn ttl_rejects_malformed() {
        assert_eq!(parse_relative_ttl_secs("5m"), None); // no '+'
        assert_eq!(parse_relative_ttl_secs("+"), None);
        assert_eq!(parse_relative_ttl_secs("+5"), None); // no unit
        assert_eq!(parse_relative_ttl_secs("+5x"), None); // bad unit
        assert_eq!(parse_relative_ttl_secs("+m"), None); // no number
        assert_eq!(parse_relative_ttl_secs("+0s"), None); // zero
    }

    /// TTL values above the configured cap are rejected.
    #[test]
    fn ttl_cap_rejects_overlong() {
        // Default cap is 24h; a multi-year request must be rejected.
        assert!(validate_ttl("+5m").is_ok());
        assert!(validate_ttl("+9999w").is_err());
    }

    /// Identity validation rejects traversal and unsafe characters.
    #[test]
    fn identity_rejects_traversal() {
        assert!(validate_identity("agent", "codex-test").is_ok());
        assert!(validate_identity("agent", "../../etc/cron.d/x").is_err());
        assert!(validate_identity("agent", "a/b").is_err());
        assert!(validate_identity("agent", "").is_err());
    }
}
