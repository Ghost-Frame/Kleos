//! Policy-check middleware for resolve endpoint interception.
//!
//! Intercepts requests to /resolve/* endpoints and checks if any
//! access policy requires approval before the request reaches credd's
//! handlers. If approval is required, returns 202 Accepted with a
//! poll URL instead of the resolved secret.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kleos_cred::agent_keys::parse_agent_key;
use kleos_cred::agent_keys::validate_agent_key;
use kleos_cred::crypto::hash_key;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use kleos_credd::auth::AuthInfo;

use crate::audit::{actions, log_phylax_audit};
use crate::models::{approval, lease, policy};
use crate::state::{approval_ttl_secs, PhylaxState};

/// Paths that are subject to policy-check interception.
const RESOLVE_PATHS: &[&str] = &[
    "/resolve/text",
    "/resolve/proxy",
    "/resolve/raw",
    "/resolve/exec",
    "/resolve/verify",
    "/resolve/sign",
    "/resolve/derive",
];

/// Header carrying the one-shot lease that resumes an approved operation.
const PHYLAX_LEASE_HEADER: &str = "x-phylax-lease";

/// Hash the exact method, path, and body that one approval may resume.
fn operation_digest(method: &str, path: &str, body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"phylax-approved-operation-v1\0");
    digest.update((method.len() as u64).to_be_bytes());
    digest.update(method.as_bytes());
    digest.update((path.len() as u64).to_be_bytes());
    digest.update(path.as_bytes());
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}

/// Policy-check middleware. Runs after auth but before credd's resolve handlers.
///
/// If the request targets a resolve endpoint and a matching policy requires
/// approval, creates an approval request and returns 202 instead of forwarding
/// to the handler.
pub async fn policy_check_middleware(
    State(state): State<PhylaxState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let operation_target = request
        .uri()
        .path_and_query()
        .map_or_else(|| path.clone(), ToString::to_string);

    // Only intercept resolve endpoints.
    if !RESOLVE_PATHS.iter().any(|p| path == *p) {
        return next.run(request).await;
    }

    // Extract auth info (inserted by auth_middleware) or derive it from the
    // request token when this middleware runs before auth.
    let auth = match request.extensions().get::<AuthInfo>().cloned() {
        Some(auth) => Some(auth),
        None => match extract_bearer_token(&request).map(str::to_owned) {
            Some(token) => resolve_auth_info(&state, token).await,
            None => None,
        },
    };

    let auth = match auth {
        Some(auth) => auth,
        None => return next.run(request).await,
    };

    // Only apply policies to agent requests. Master bypasses policies.
    if auth.is_master() {
        return next.run(request).await;
    }

    let agent_name = match auth.agent_name() {
        Some(name) => name.to_string(),
        None => return next.run(request).await,
    };

    // Determine resolve mode from the path.
    let resolve_mode = match path.as_str() {
        "/resolve/text" => "text",
        "/resolve/proxy" => "proxy",
        "/resolve/raw" => "raw",
        "/resolve/exec" => "exec",
        "/resolve/verify" => "verify",
        "/resolve/sign" => "sign",
        "/resolve/derive" => "derive",
        _ => return next.run(request).await,
    };
    // The non-plaintext modes are new capabilities with no legacy users:
    // they require an explicit allowing policy (deny by default), unlike
    // proxy which keeps its no-policy pass-through compatibility.
    let explicit_policy_required = matches!(resolve_mode, "exec" | "verify" | "sign" | "derive");

    // No-plaintext rule: text and raw return secret material to the caller,
    // so they are master-only. No policy can grant them to an agent and there
    // is no approval escape hatch -- agents use the non-plaintext modes.
    if matches!(resolve_mode, "text" | "raw") {
        let _ = log_phylax_audit(
            &state.inner.db,
            auth.user_id(),
            Some(&agent_name),
            None,
            None,
            None,
            None,
            actions::PLAINTEXT_DENIED,
            "unknown",
            "unknown",
            false,
            None,
        )
        .await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "resolve mode '{resolve_mode}' returns plaintext and is master-only"
                )
            })),
        )
            .into_response();
    }

    // We need to read the body to extract the secret reference, but the
    // downstream handler also needs it. Buffer the body.
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 64).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "request body too large"})),
            )
                .into_response();
        }
    };

    // Try to parse the body to extract category/secret_name.
    // For /resolve/text: look for {{secret:category/name}} patterns.
    // For /resolve/proxy and /resolve/raw: extract from JSON body.
    let (category, secret_name) = match extract_secret_ref(resolve_mode, &body_bytes) {
        Some(pair) => pair,
        None => {
            // An undeterminable secret reference must not evade the policy
            // layer: deny instead of forwarding to credd.
            let _ = log_phylax_audit(
                &state.inner.db,
                auth.user_id(),
                Some(&agent_name),
                None,
                None,
                None,
                None,
                actions::POLICY_FAIL_CLOSED,
                "unknown",
                "unknown",
                false,
                None,
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "secret reference could not be determined from the request"})),
            )
                .into_response();
        }
    };
    let bound_operation = operation_digest(parts.method.as_str(), &operation_target, &body_bytes);

    // A successful approval authorizes exactly one matching retry. Consume
    // the lease before the operation reaches its handler so replay, a changed
    // agent, secret, or resolve mode all fail closed.
    if let Some(jti) = parts
        .headers
        .get(PHYLAX_LEASE_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        let redeemed = lease::redeem_lease_for_operation(
            &state.inner.db,
            jti,
            auth.user_id(),
            &agent_name,
            &category,
            &secret_name,
            resolve_mode,
            &bound_operation,
        )
        .await;
        if redeemed.is_err() {
            let _ = log_phylax_audit(
                &state.inner.db,
                auth.user_id(),
                Some(&agent_name),
                None,
                None,
                None,
                None,
                actions::LEASE_REPLAY,
                &category,
                &secret_name,
                false,
                None,
            )
            .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "approval lease rejected"})),
            )
                .into_response();
        }
        let _ = log_phylax_audit(
            &state.inner.db,
            auth.user_id(),
            Some(&agent_name),
            None,
            None,
            None,
            None,
            actions::LEASE_REDEEMED,
            &category,
            &secret_name,
            true,
            None,
        )
        .await;
        let request = Request::from_parts(parts, Body::from(body_bytes));
        return next.run(request).await;
    }

    // Check for a matching policy. Use the "default" namespace for now.
    let namespace = "default";
    let matching_policy = match policy::find_matching_policy(
        &state.inner.db,
        auth.user_id(),
        namespace,
        &category,
        &secret_name,
    )
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            if explicit_policy_required {
                // exec/verify/sign/derive are deny-by-default: without an
                // explicit allowing policy the mode is not reachable.
                let _ = log_phylax_audit(
                    &state.inner.db,
                    auth.user_id(),
                    Some(&agent_name),
                    None,
                    None,
                    None,
                    None,
                    actions::MODE_POLICY_DENIED,
                    &category,
                    &secret_name,
                    false,
                    None,
                )
                .await;
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": format!(
                            "resolve mode '{resolve_mode}' requires an explicit allowing policy"
                        )
                    })),
                )
                    .into_response();
            }
            // No policy -- pass through to credd (legacy proxy compatibility).
            let request = Request::from_parts(parts, Body::from(body_bytes));
            return next.run(request).await;
        }
        Err(e) => {
            // Policy store unavailable: fail CLOSED. No secret may move when
            // the authority cannot be consulted.
            tracing::error!("policy lookup failed, denying agent resolve: {e}");
            let _ = log_phylax_audit(
                &state.inner.db,
                auth.user_id(),
                Some(&agent_name),
                None,
                None,
                None,
                None,
                actions::POLICY_FAIL_CLOSED,
                &category,
                &secret_name,
                false,
                None,
            )
            .await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "policy check unavailable"})),
            )
                .into_response();
        }
    };

    // For the deny-by-default modes the allowed_modes check applies
    // unconditionally: a policy that does not name the mode does not grant
    // it, with or without an approval requirement.
    if explicit_policy_required
        && !matching_policy
            .allowed_modes
            .iter()
            .any(|m| m == resolve_mode)
    {
        let _ = log_phylax_audit(
            &state.inner.db,
            auth.user_id(),
            Some(&agent_name),
            None,
            None,
            Some(matching_policy.id),
            None,
            actions::MODE_POLICY_DENIED,
            &category,
            &secret_name,
            false,
            None,
        )
        .await;
        return (
            StatusCode::FORBIDDEN,
            Json(
                json!({"error": format!("resolve mode '{}' not allowed by policy", resolve_mode)}),
            ),
        )
            .into_response();
    }

    // Policy found and requires approval.
    if !matching_policy.require_approval {
        // Policy exists but doesn't require approval -- pass through.
        let request = Request::from_parts(parts, Body::from(body_bytes));
        return next.run(request).await;
    }

    // Check if the resolve mode is allowed.
    if !matching_policy
        .allowed_modes
        .iter()
        .any(|m| m == resolve_mode)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(
                json!({"error": format!("resolve mode '{}' not allowed by policy", resolve_mode)}),
            ),
        )
            .into_response();
    }

    // Create an approval request.
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(approval_ttl_secs(state.phone_approval_required)))
    .format("%Y-%m-%d %H:%M:%S")
    .to_string();

    let approval_result = approval::create_approval_with_token(
        &state.inner.db,
        auth.user_id(),
        &agent_name,
        &category,
        &secret_name,
        resolve_mode,
        Some(&correlation_id),
        &expires_at,
    )
    .await;

    match approval_result {
        Ok((a, raw_token)) => {
            if let Err(error) =
                approval::set_operation_digest(&state.inner.db, a.id, &bound_operation).await
            {
                tracing::error!(%error, "failed to bind exact approval operation");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to bind approval operation"})),
                )
                    .into_response();
            }
            if state.phone_approval_required {
                let binding = match approval::bind_phone_approval(&state.inner.db, &a).await {
                    Ok(binding) => binding,
                    Err(error) => {
                        tracing::error!(%error, "failed to bind exact-phone approval");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "failed to bind approval"})),
                        )
                            .into_response();
                    }
                };
                crate::notify::notify_phone_approval(
                    a.id,
                    resolve_mode,
                    &agent_name,
                    &category,
                    &secret_name,
                    &expires_at,
                    &raw_token,
                    &binding,
                )
                .await;
            } else {
                crate::notify::notify_approval(
                    a.id,
                    resolve_mode,
                    &agent_name,
                    &category,
                    &secret_name,
                    &expires_at,
                    &raw_token,
                )
                .await;
            }
            let _ = log_phylax_audit(
                &state.inner.db,
                auth.user_id(),
                Some(&agent_name),
                None,
                None,
                Some(matching_policy.id),
                None,
                actions::APPROVAL_REQUESTED,
                &category,
                &secret_name,
                true,
                Some(&correlation_id),
            )
            .await;

            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "approval_required": true,
                    "approval_id": a.id,
                    "poll_url": format!("/phylax/approvals/{}/wait", a.id),
                    "correlation_id": correlation_id,
                    "expires_at": expires_at,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("failed to create approval: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "failed to create approval"})),
            )
                .into_response()
        }
    }
}

/// Extract the secret category and name from a resolve request body.
///
/// Returns None if the secret reference cannot be determined.
fn extract_secret_ref(mode: &str, body: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(body).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(text).ok()?;

    match mode {
        "text" => {
            // Text mode: look for {{secret:category/name}} in the "text" field.
            let text_field = parsed.get("text")?.as_str()?;
            let start = text_field.find("{{secret:")?;
            let inner_start = start + "{{secret:".len();
            let end = text_field[inner_start..].find("}}")?;
            let inner = &text_field[inner_start..inner_start + end];
            // Strip field accessor (e.g., category/name.field -> category/name)
            let inner = inner.split('.').next().unwrap_or(inner);
            let slash = inner.find('/')?;
            Some((inner[..slash].to_string(), inner[slash + 1..].to_string()))
        }
        "proxy" | "raw" | "exec" | "verify" | "sign" | "derive" => {
            // All JSON-bodied modes carry "category" and "name" fields.
            let category = parsed.get("category")?.as_str()?.to_string();
            let name = parsed.get("name")?.as_str()?.to_string();
            Some((category, name))
        }
        _ => None,
    }
}

/// Read the bearer token from the Authorization header.
fn extract_bearer_token(request: &Request) -> Option<&str> {
    request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Resolve AuthInfo from request credentials when auth middleware has not yet
/// executed.
///
/// This preserves behavior when policy middleware is mounted before auth and still
/// needs to identify the requesting agent for policy lookup.
async fn resolve_auth_info(state: &PhylaxState, token: String) -> Option<AuthInfo> {
    let master_hash = hash_key(&**state.master_key);
    let token_bytes = hex::decode(&token).unwrap_or_else(|_| token.as_bytes().to_vec());
    let token_hash = hash_key(&token_bytes);
    if master_hash.len() == token_hash.len()
        && master_hash
            .as_bytes()
            .ct_eq(token_hash.as_bytes())
            .unwrap_u8()
            == 1
    {
        return Some(AuthInfo::Master { user_id: 1 });
    }

    if let Ok(raw) = parse_agent_key(&token) {
        if let Ok(agent_key) = validate_agent_key(&state.db, &raw).await {
            return Some(AuthInfo::Agent {
                user_id: agent_key.user_id,
                key: agent_key,
            });
        }
    }

    let mut store = state.inner.file_agent_keys.lock().ok()?;
    let agent_id = store.validate(&token)?;
    let scopes = store.scopes_for(&agent_id);
    store.touch(&agent_id);

    Some(AuthInfo::BootstrapAgent {
        name: agent_id,
        scopes,
    })
}
