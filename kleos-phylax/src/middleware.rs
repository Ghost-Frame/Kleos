//! Policy-check middleware for resolve endpoint interception.
//!
//! Intercepts requests to /resolve/* endpoints and checks if any
//! access policy requires approval before the request reaches credd's
//! handlers. If approval is required, returns 202 Accepted with a
//! poll URL instead of the resolved secret.
//!
//! The layer is mounted INSIDE credd's authentication layer (see
//! `router::compose_router_with_phylax_state`), so it only ever sees requests
//! whose identity `auth_middleware` has already established. It never
//! authenticates anything itself: a request without an `AuthInfo` extension is
//! answered 401 and gets no policy decision. The secret reference it evaluates
//! is parsed with the very structs the handlers deserialize (all
//! `deny_unknown_fields`), so policy and handler cannot disagree about which
//! secret a request names.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};

use kleos_credd::auth::AuthInfo;
use kleos_credd::handlers::types::ProxyRequest;

use crate::audit::{actions, log_phylax_audit};
use crate::handlers::resolve_modes::{
    DeriveModeRequest, ExecModeRequest, SignModeRequest, VerifyModeRequest,
};
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
/// to the handler. Fails closed: no identity, an unparseable body, or an
/// unavailable policy store all end in a denial, never a pass-through.
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

    // The identity inserted by auth_middleware, which wraps this layer. If it is
    // missing the layer was mounted outside auth: refuse rather than guess.
    let auth = match request.extensions().get::<AuthInfo>().cloned() {
        Some(auth) => auth,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "authentication required"})),
            )
                .into_response();
        }
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
/// Each mode is parsed with the same request struct its handler deserializes,
/// all of which reject unknown fields. A body carrying decoy fields (for
/// example a `category`/`name` pair on a proxy request, whose handler reads
/// `secret_category`/`secret_name`) therefore fails to parse here and is
/// denied, instead of being judged on fields the handler ignores.
///
/// Returns None if the body does not parse as the mode's request or the mode
/// has no agent-reachable handler (`text` and `raw` are master-only and are
/// refused before this runs).
fn extract_secret_ref(mode: &str, body: &[u8]) -> Option<(String, String)> {
    match mode {
        "proxy" => {
            let req: ProxyRequest = serde_json::from_slice(body).ok()?;
            Some((req.secret_category, req.secret_name))
        }
        "exec" => {
            let req: ExecModeRequest = serde_json::from_slice(body).ok()?;
            Some((req.category, req.name))
        }
        "sign" => {
            let req: SignModeRequest = serde_json::from_slice(body).ok()?;
            Some((req.category, req.name))
        }
        "verify" => {
            let req: VerifyModeRequest = serde_json::from_slice(body).ok()?;
            Some((req.category, req.name))
        }
        "derive" => {
            let req: DeriveModeRequest = serde_json::from_slice(body).ok()?;
            Some((req.category, req.name))
        }
        _ => None,
    }
}

/// Unit tests for secret-reference extraction and the missing-identity guard.
#[cfg(test)]
mod tests {
    use super::*;

    /// Mounted without an authentication layer in front of it, the middleware
    /// answers 401 and never reaches the handler or makes a policy decision.
    #[tokio::test]
    async fn missing_identity_is_401_not_a_policy_decision() {
        use tower::ServiceExt;

        let db = kleos_lib::db::Database::connect_memory()
            .await
            .expect("in-memory db");
        let state = PhylaxState::from_app_state(kleos_credd::state::AppState::new(db, [7u8; 32]));
        let app = axum::Router::new()
            .route(
                "/resolve/proxy",
                axum::routing::post(|| async { "reached" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                policy_check_middleware,
            ));
        let request = Request::builder()
            .method("POST")
            .uri("/resolve/proxy")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"url":"https://a.test/","secret_category":"prod","secret_name":"k"}"#,
            ))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Build the expected `Some((category, name))` result.
    fn pair(category: &str, name: &str) -> Option<(String, String)> {
        Some((category.to_string(), name.to_string()))
    }

    /// A well-formed proxy body yields the handler's secret reference.
    #[test]
    fn proxy_uses_secret_category_and_name() {
        let body = br#"{"url":"https://a.test/","secret_category":"prod","secret_name":"k"}"#;
        assert_eq!(extract_secret_ref("proxy", body), pair("prod", "k"));
    }

    /// Decoy `category`/`name` fields on a proxy body are a parse failure, not
    /// a policy decision on the decoy.
    #[test]
    fn proxy_decoy_fields_fail_closed() {
        let body =
            br#"{"url":"u","secret_category":"prod","secret_name":"k","category":"h","name":"d"}"#;
        assert_eq!(extract_secret_ref("proxy", body), None);
        let only_decoy = br#"{"url":"u","category":"harmless","name":"decoy"}"#;
        assert_eq!(extract_secret_ref("proxy", only_decoy), None);
    }

    /// Duplicate keys, wrong types and non-JSON all fail closed.
    #[test]
    fn malformed_bodies_fail_closed() {
        for body in [
            r#"{"url":"u","secret_category":"a","secret_category":"b","secret_name":"k"}"#,
            r#"{"url":1,"secret_category":"a","secret_name":"k"}"#,
            "not json",
            "",
        ] {
            assert_eq!(extract_secret_ref("proxy", body.as_bytes()), None);
        }
    }

    /// The other JSON modes parse their handler structs and reject extras.
    #[test]
    fn other_modes_use_handler_structs() {
        let exec = br#"{"category":"c","name":"n","argv":["/bin/x"],"env_var":"S"}"#;
        assert_eq!(extract_secret_ref("exec", exec), pair("c", "n"));
        let exec_extra = br#"{"category":"c","name":"n","argv":["/bin/x"],"env_var":"S","x":1}"#;
        assert_eq!(extract_secret_ref("exec", exec_extra), None);
        let sign = br#"{"category":"c","name":"n","payload_b64":"eA==","algo":"hmac-sha256"}"#;
        assert_eq!(extract_secret_ref("sign", sign), pair("c", "n"));
        assert_eq!(extract_secret_ref("text", br#"{"text":"x"}"#), None);
        assert_eq!(
            extract_secret_ref("raw", br#"{"category":"c","name":"n"}"#),
            None
        );
    }
}
