//! Non-plaintext resolve modes: exec, verify, sign, derive.
//!
//! These endpoints let an agent USE a secret without ever holding it: the
//! secret is loaded server-side, the cryptographic operation happens here,
//! and only the operation's result (a boolean, a signature, derived key
//! material) crosses the agent boundary. The policy middleware has already
//! ruled on /resolve/* requests before these handlers run; handlers still
//! enforce category access themselves (defense in depth).

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer as DalekSigner, Verifier};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use kleos_cred::storage::get_secret;
use kleos_cred::types::SecretData;
use kleos_cred::CredError;
use kleos_credd::auth::Auth;
use kleos_credd::handlers::AppError;

use crate::audit::{actions, log_phylax_audit};
use crate::state::PhylaxState;

/// Maximum derivable key length in bytes.
const MAX_DERIVE_LEN: usize = 64;

/// HMAC algorithm tag accepted by sign/verify.
const ALGO_HMAC: &str = "hmac-sha256";
/// Ed25519 algorithm tag accepted by sign/verify (requires an SshKey secret).
const ALGO_ED25519: &str = "ed25519";

/// Body for POST /resolve/sign.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignModeRequest {
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub name: String,
    /// Base64-encoded payload to sign.
    pub payload_b64: String,
    /// Signature algorithm: "hmac-sha256" or "ed25519".
    pub algo: String,
}

/// Body for POST /resolve/verify.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyModeRequest {
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub name: String,
    /// Base64-encoded payload the signature claims to cover.
    pub payload_b64: String,
    /// Base64-encoded signature to check.
    pub signature_b64: String,
    /// Signature algorithm: "hmac-sha256" or "ed25519".
    pub algo: String,
}

/// Body for POST /resolve/derive.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeriveModeRequest {
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub name: String,
    /// Domain-separation string; REQUIRED non-empty. Different purposes
    /// yield unrelated keys from the same root secret.
    pub purpose: String,
    /// Output length in bytes (1..=64).
    pub length: usize,
}

/// Load a secret's data after enforcing category access for the caller.
async fn load_secret(
    state: &PhylaxState,
    auth: &kleos_credd::auth::AuthInfo,
    category: &str,
    name: &str,
) -> Result<SecretData, AppError> {
    if !auth.is_master() && !auth.can_access_category(category) {
        return Err(CredError::PermissionDenied("category not permitted".into()).into());
    }
    let (_row, data) = get_secret(
        &state.inner.db,
        auth.user_id(),
        category,
        name,
        state.inner.master_key.as_ref(),
    )
    .await?;
    Ok(data)
}

/// The canonical secret bytes of each storable type, for keying HMAC/HKDF.
/// Environment secrets hold many values and are rejected: there is no single
/// "the secret" to key with.
fn secret_key_bytes(data: SecretData) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let bytes = match data {
        SecretData::Note { content } => content.into_bytes(),
        SecretData::ApiKey { key, .. } => key.into_bytes(),
        SecretData::Login { password, .. } => password.into_bytes(),
        SecretData::OAuthApp { client_secret, .. } => client_secret.into_bytes(),
        SecretData::SshKey { private_key, .. } => private_key.into_bytes(),
        SecretData::Environment { .. } => {
            return Err(CredError::InvalidInput(
                "environment secrets have no single key value".into(),
            )
            .into())
        }
    };
    Ok(Zeroizing::new(bytes))
}

/// Parse a stored ssh_key secret into an ed25519 signing key. The stored
/// PEM never appears in errors; parse failures report only the shape problem.
fn ed25519_signing_key(data: SecretData) -> Result<ed25519_dalek::SigningKey, AppError> {
    let SecretData::SshKey { private_key, .. } = data else {
        return Err(
            CredError::InvalidInput("ed25519 requires an ssh_key-type secret".into()).into(),
        );
    };
    let key = ssh_key::PrivateKey::from_openssh(private_key.as_bytes())
        .map_err(|_| CredError::InvalidInput("stored key is not OpenSSH-format".into()))?;
    let pair = key
        .key_data()
        .ed25519()
        .ok_or_else(|| CredError::InvalidInput("stored key is not ed25519".into()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(
        &pair.private.to_bytes(),
    ))
}

/// Record a mode operation in the phylax audit log (never key material).
async fn audit_mode(
    state: &PhylaxState,
    auth: &kleos_credd::auth::AuthInfo,
    action: &str,
    category: &str,
    name: &str,
    success: bool,
) {
    let agent_name = auth.agent_name().unwrap_or("master").to_string();
    let _ = log_phylax_audit(
        &state.inner.db,
        auth.user_id(),
        Some(&agent_name),
        None,
        None,
        None,
        None,
        action,
        category,
        name,
        success,
        None,
    )
    .await;
}

/// POST /resolve/sign -- sign a payload with a stored secret. The key never
/// leaves the process; only the signature is returned.
pub async fn sign_payload(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<SignModeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Validate client-shaped inputs before touching the vault so input
    // errors surface as 400 rather than as access-control responses.
    if body.algo != ALGO_HMAC && body.algo != ALGO_ED25519 {
        return Err(CredError::InvalidInput(format!("unknown algo '{}'", body.algo)).into());
    }
    let payload = B64
        .decode(&body.payload_b64)
        .map_err(|_| CredError::InvalidInput("bad payload_b64".into()))?;

    let data = load_secret(&state, &auth, &body.category, &body.name).await?;
    let signature = match body.algo.as_str() {
        ALGO_HMAC => {
            let key = secret_key_bytes(data)?;
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key length");
            mac.update(&payload);
            mac.finalize().into_bytes().to_vec()
        }
        ALGO_ED25519 => {
            let signing_key = ed25519_signing_key(data)?;
            signing_key.sign(&payload).to_bytes().to_vec()
        }
        other => {
            return Err(CredError::InvalidInput(format!("unknown algo '{other}'")).into());
        }
    };

    audit_mode(
        &state,
        &auth,
        actions::SIGN_RESOLVED,
        &body.category,
        &body.name,
        true,
    )
    .await;
    Ok(Json(json!({ "signature_b64": B64.encode(signature) })))
}

/// POST /resolve/verify -- check a signature against a stored secret.
/// Returns only {"valid": bool}; never key material.
pub async fn verify_payload(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<VerifyModeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if body.algo != ALGO_HMAC && body.algo != ALGO_ED25519 {
        return Err(CredError::InvalidInput(format!("unknown algo '{}'", body.algo)).into());
    }
    let payload = B64
        .decode(&body.payload_b64)
        .map_err(|_| CredError::InvalidInput("bad payload_b64".into()))?;
    let signature = B64
        .decode(&body.signature_b64)
        .map_err(|_| CredError::InvalidInput("bad signature_b64".into()))?;

    let data = load_secret(&state, &auth, &body.category, &body.name).await?;
    let valid = match body.algo.as_str() {
        ALGO_HMAC => {
            let key = secret_key_bytes(data)?;
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key length");
            mac.update(&payload);
            let expected = mac.finalize().into_bytes();
            // Constant-time compare; a wrong-length signature is simply
            // invalid, not an error worth distinguishing.
            expected.len() == signature.len()
                && expected.as_slice().ct_eq(&signature).unwrap_u8() == 1
        }
        ALGO_ED25519 => {
            let verifying_key = ed25519_signing_key(data)?.verifying_key();
            match ed25519_dalek::Signature::from_slice(&signature) {
                Ok(sig) => verifying_key.verify(&payload, &sig).is_ok(),
                Err(_) => false,
            }
        }
        other => {
            return Err(CredError::InvalidInput(format!("unknown algo '{other}'")).into());
        }
    };

    audit_mode(
        &state,
        &auth,
        actions::VERIFY_RESOLVED,
        &body.category,
        &body.name,
        true,
    )
    .await;
    Ok(Json(json!({ "valid": valid })))
}

/// POST /resolve/derive -- HKDF-SHA256 key derivation from a stored secret.
/// The purpose string domain-separates outputs; the root secret is
/// unrecoverable from any derived key.
pub async fn derive_key_material(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<DeriveModeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if body.purpose.is_empty() {
        return Err(CredError::InvalidInput("purpose must be non-empty".into()).into());
    }
    if body.length == 0 || body.length > MAX_DERIVE_LEN {
        return Err(CredError::InvalidInput(format!("length must be 1..={MAX_DERIVE_LEN}")).into());
    }

    let data = load_secret(&state, &auth, &body.category, &body.name).await?;
    let key = secret_key_bytes(data)?;
    let hk = Hkdf::<Sha256>::new(None, &key);
    let mut okm = Zeroizing::new(vec![0u8; body.length]);
    hk.expand(
        format!("phylax-derive:{}", body.purpose).as_bytes(),
        &mut okm,
    )
    .map_err(|_| CredError::InvalidInput("derive length invalid".into()))?;

    audit_mode(
        &state,
        &auth,
        actions::DERIVE_RESOLVED,
        &body.category,
        &body.name,
        true,
    )
    .await;
    Ok(Json(json!({ "derived_b64": B64.encode(&*okm) })))
}

/// Hard wall-clock limit for an exec-mode child. Below credd's 30s request
/// timeout so the structured timeout response beats the tower cutoff.
const EXEC_TIMEOUT_SECS: u64 = 20;
/// Cap on returned child output per stream, post-scrub.
const EXEC_OUTPUT_CAP: usize = 256 * 1024;

/// Body for POST /resolve/exec.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecModeRequest {
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub name: String,
    /// Command to run; argv[0] must be an absolute path on the policy's
    /// exec allowlist. Executed directly -- no shell.
    pub argv: Vec<String>,
    /// Environment variable name the secret is injected as.
    pub env_var: String,
}

/// POSIX-shaped environment variable names only.
fn valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Replace every occurrence of `needle` in `haystack` with `replacement`.
fn replace_all_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Scrub a secret from child output: the raw bytes plus their base64 and
/// hex (both cases) encodings. The child can always re-encode the secret in
/// a form this cannot catch, which is why exec is allowlist-gated; the
/// scrub closes the accidental-leak paths (echoed env, verbose logs).
fn scrub_secret(output: &[u8], secret: &[u8]) -> Vec<u8> {
    let encodings = [
        secret.to_vec(),
        B64.encode(secret).into_bytes(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
    ];
    let mut out = output.to_vec();
    for needle in &encodings {
        out = replace_all_bytes(&out, needle, b"[redacted]");
    }
    out
}

/// POST /resolve/exec -- run an allowlisted command with the secret injected
/// into its environment. The agent receives the command's (scrubbed) output
/// and exit code, never the secret itself.
pub async fn exec_command(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<ExecModeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(argv0) = body.argv.first().cloned() else {
        return Err(CredError::InvalidInput("argv must be non-empty".into()).into());
    };
    if !argv0.starts_with('/') {
        return Err(CredError::InvalidInput("argv[0] must be an absolute path".into()).into());
    }
    if !valid_env_var_name(&body.env_var) {
        return Err(CredError::InvalidInput("invalid env_var name".into()).into());
    }

    // The argv[0] allowlist is a property of the matched policy. The policy
    // middleware already required a policy naming "exec"; re-resolve it here
    // for the allowlist (and as defense in depth).
    let policy = crate::models::policy::find_matching_policy(
        &state.inner.db,
        auth.user_id(),
        "default",
        &body.category,
        &body.name,
    )
    .await?;
    let allowlisted = policy
        .as_ref()
        .and_then(|p| p.exec_allowlist.as_ref())
        .is_some_and(|list| list.contains(&argv0));
    if !allowlisted {
        audit_mode(
            &state,
            &auth,
            actions::EXEC_RESOLVED,
            &body.category,
            &body.name,
            false,
        )
        .await;
        return Err(CredError::PermissionDenied(
            "argv[0] is not in the policy's exec allowlist".into(),
        )
        .into());
    }

    let data = load_secret(&state, &auth, &body.category, &body.name).await?;
    let secret = secret_key_bytes(data)?;
    let secret_os = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(secret.to_vec())
    };

    // Direct spawn, no shell, minimal environment: only the injected
    // variable exists in the child. kill_on_drop reaps the child if the
    // timeout (or a dropped connection) abandons the wait below.
    let child = tokio::process::Command::new(&argv0)
        .args(&body.argv[1..])
        .env_clear()
        .env(&body.env_var, &secret_os)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            tracing::error!(error = %e, argv0 = %argv0, "exec spawn failed");
            CredError::InvalidInput("command could not be started".into())
        })?;

    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(EXEC_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "exec wait failed");
            return Err(CredError::Database("command execution failed".into()).into());
        }
        Err(_) => {
            // Timed out: the dropped future kills the child (kill_on_drop).
            audit_mode(
                &state,
                &auth,
                actions::EXEC_RESOLVED,
                &body.category,
                &body.name,
                false,
            )
            .await;
            return Ok(Json(json!({
                "timed_out": true,
                "exit_code": null,
                "stdout_b64": "",
                "stderr_b64": "",
            })));
        }
    };

    let mut stdout = scrub_secret(&output.stdout, &secret);
    let mut stderr = scrub_secret(&output.stderr, &secret);
    stdout.truncate(EXEC_OUTPUT_CAP);
    stderr.truncate(EXEC_OUTPUT_CAP);

    audit_mode(
        &state,
        &auth,
        actions::EXEC_RESOLVED,
        &body.category,
        &body.name,
        output.status.success(),
    )
    .await;
    Ok(Json(json!({
        "timed_out": false,
        "exit_code": output.status.code(),
        "stdout_b64": B64.encode(&stdout),
        "stderr_b64": B64.encode(&stderr),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Secrets under test: 4..64 arbitrary bytes, excluding anything that is
    /// a substring of the redaction marker itself (a 1-byte secret equal to
    /// a marker character would trivially "survive" its own replacement).
    fn secret_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 4..64).prop_filter(
            "secret must not be part of the marker",
            |s| {
                !b"[redacted]"
                    .windows(s.len().min(10))
                    .any(|w| w == &s[..s.len().min(10)])
            },
        )
    }

    /// True when `needle` occurs nowhere in `haystack`.
    fn absent(haystack: &[u8], needle: &[u8]) -> bool {
        needle.is_empty()
            || haystack.len() < needle.len()
            || !haystack.windows(needle.len()).any(|w| w == needle)
    }

    proptest! {
        /// replace_all_bytes leaves no occurrence of the needle behind, for
        /// any haystack including ones built by embedding the needle at
        /// arbitrary points.
        #[test]
        fn prop_replace_all_bytes_total(
            prefix in proptest::collection::vec(any::<u8>(), 0..128),
            middle in proptest::collection::vec(any::<u8>(), 0..128),
            suffix in proptest::collection::vec(any::<u8>(), 0..128),
            needle in secret_strategy(),
        ) {
            let mut haystack = prefix;
            haystack.extend_from_slice(&needle);
            haystack.extend_from_slice(&middle);
            haystack.extend_from_slice(&needle);
            haystack.extend_from_slice(&suffix);

            let out = replace_all_bytes(&haystack, &needle, b"[redacted]");
            prop_assert!(absent(&out, &needle));
        }

        /// Scrub totality: after scrub_secret, neither the raw secret nor
        /// its base64 / hex (lower or upper) encodings appear anywhere in
        /// the output, no matter where or how often the child embedded them.
        #[test]
        fn prop_scrub_secret_total(
            prefix in proptest::collection::vec(any::<u8>(), 0..96),
            middle in proptest::collection::vec(any::<u8>(), 0..96),
            secret in secret_strategy(),
            embed_choice in 0usize..4,
        ) {
            let encodings: [Vec<u8>; 4] = [
                secret.clone(),
                B64.encode(&secret).into_bytes(),
                hex::encode(&secret).into_bytes(),
                hex::encode_upper(&secret).into_bytes(),
            ];

            // Embed one chosen encoding twice plus the raw secret once,
            // separated by arbitrary noise.
            let mut output = prefix;
            output.extend_from_slice(&encodings[embed_choice]);
            output.extend_from_slice(&middle);
            output.extend_from_slice(&secret);
            output.extend_from_slice(&encodings[embed_choice]);

            let scrubbed = scrub_secret(&output, &secret);
            for enc in &encodings {
                prop_assert!(
                    absent(&scrubbed, enc),
                    "an encoding of the secret survived scrubbing"
                );
            }
        }
    }
}
