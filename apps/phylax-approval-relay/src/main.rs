//! Exact-phone approval relay with separated private intake and public transport.

mod config;
mod state;
mod telegram;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use config::Config;
use state::{ApprovalState, PhoneDecisionEnvelope, PublicApprovalRequest};

/// Maximum server-owned lifetime accepted by the public relay.
const MAX_NOTIFICATION_LIFETIME_SECS: i64 = 180;

/// Phone binding nested in a Phylax notification.
#[derive(Debug, Deserialize)]
struct PhoneBinding {
    /// Wire protocol version.
    version: u64,
    /// Sole active device selected by Phylax.
    device_id: String,
    /// Base64url request nonce.
    nonce: String,
    /// Base64url immutable request digest.
    request_digest: String,
    /// Base64url digest of the request fields the phone does not display.
    hidden_digest: String,
    /// Server-owned expiry as Unix seconds.
    expires_at: i64,
}

/// Private notification posted by Phylax over the private network.
#[derive(Debug, Deserialize)]
struct NotifyPayload {
    /// Approval row identifier.
    approval_id: i64,
    /// Requested operation.
    action: String,
    /// Requesting agent.
    agent_name: String,
    /// Credential or operation category.
    category: String,
    /// Human-visible target.
    secret_name: String,
    /// Raw capability retained only in relay memory.
    decide_token: String,
    /// Exact-phone binding, required by this relay.
    phone: PhoneBinding,
}

/// Shared state for private notification intake.
#[derive(Clone)]
struct NotifyState {
    /// Pending in-memory approvals.
    approvals: ApprovalState,
    /// Outbound HTTP client with redirects disabled.
    client: reqwest::Client,
    /// Validated runtime configuration.
    config: Arc<Config>,
}

/// Shared state for the public phone-facing API.
#[derive(Clone)]
struct PhoneState {
    /// Pending in-memory approvals.
    approvals: ApprovalState,
    /// Outbound HTTP client with redirects disabled.
    client: reqwest::Client,
    /// Validated runtime configuration.
    config: Arc<Config>,
}

/// Initialize tracing, separate listeners, and the expiry sweeper.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Arc::new(Config::from_env()?);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let approvals = ApprovalState::new();

    let notify_router = build_notify_router(NotifyState {
        approvals: approvals.clone(),
        client: client.clone(),
        config: config.clone(),
    });
    let phone_router = build_phone_router(PhoneState {
        approvals: approvals.clone(),
        client,
        config: config.clone(),
    });

    let sweep_state = approvals;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            sweep_state.sweep_expired(chrono_now());
        }
    });

    let notify_listener = tokio::net::TcpListener::bind(&config.notify_bind).await?;
    let phone_listener = tokio::net::TcpListener::bind(&config.phone_bind).await?;
    tracing::info!(bind = %config.notify_bind, "private notification intake ready");
    tracing::info!(bind = %config.phone_bind, "phone relay API ready");
    let (notify_result, phone_result) = tokio::join!(
        axum::serve(notify_listener, notify_router),
        axum::serve(phone_listener, phone_router)
    );
    notify_result?;
    phone_result?;
    Ok(())
}

/// Build the private-network-only notification router.
fn build_notify_router(state: NotifyState) -> Router {
    Router::new()
        .route("/notify", post(handle_notify))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

/// Build the public phone-facing router behind TLS ingress.
fn build_phone_router(state: PhoneState) -> Router {
    Router::new()
        .route("/v1/phone/requests/{pickup}", get(get_approval))
        .route("/v1/phone/requests/{pickup}/decision", post(post_decision))
        .route("/v1/phone/open/{pickup}", get(open_approval))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(add_public_security_headers))
        .with_state(state)
}

/// Accept a bounded exact-phone request and send its opaque HTTPS pickup link.
async fn handle_notify(
    State(state): State<NotifyState>,
    headers: HeaderMap,
    Json(payload): Json<NotifyPayload>,
) -> StatusCode {
    if !authorized_notify(&headers, &state.config.notify_token) {
        return StatusCode::UNAUTHORIZED;
    }
    let request = PublicApprovalRequest {
        version: payload.phone.version,
        approval_id: payload.approval_id,
        nonce: payload.phone.nonce,
        request_digest: payload.phone.request_digest,
        hidden_digest: payload.phone.hidden_digest,
        device_id: payload.phone.device_id,
        action: payload.action,
        agent_name: payload.agent_name,
        category: payload.category,
        target_name: payload.secret_name,
        expires_at: payload.phone.expires_at,
    };
    if !valid_notification(&request, &payload.decide_token) {
        return StatusCode::BAD_REQUEST;
    }
    let Ok(handle) = state
        .approvals
        .insert(payload.decide_token, request.clone(), chrono_now())
    else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if telegram::send_approval(&state.client, &state.config, &request, &handle)
        .await
        .is_err()
    {
        state.approvals.finish_decision(&handle, true);
        tracing::warn!(
            approval_id = request.approval_id,
            "Telegram notification failed"
        );
        return StatusCode::BAD_GATEWAY;
    }
    tracing::info!(
        approval_id = request.approval_id,
        "phone approval notification sent"
    );
    StatusCode::ACCEPTED
}

/// Compare a fixed-shape bearer credential without data-dependent byte comparison.
fn authorized_notify(headers: &HeaderMap, expected: &str) -> bool {
    let Some(presented) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

/// Apply anti-cache and browser-containment headers to every public response.
async fn add_public_security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
        ),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Return public metadata for a live opaque pickup handle.
async fn get_approval(
    State(state): State<PhoneState>,
    Path(pickup): Path<String>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let request = state
        .approvals
        .get_public(&pickup, chrono_now())
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(request)))
}

/// Confirm a live App Link without redirecting to a claimable custom scheme.
async fn open_approval(
    State(state): State<PhoneState>,
    Path(pickup): Path<String>,
) -> Result<StatusCode, StatusCode> {
    state
        .approvals
        .get_public(&pickup, chrono_now())
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reserve, forward, and consume one phone-signed decision.
async fn post_decision(
    State(state): State<PhoneState>,
    Path(pickup): Path<String>,
    Json(envelope): Json<PhoneDecisionEnvelope>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let capability = state
        .approvals
        .begin_decision(&pickup, &envelope, chrono_now())
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let decide_url = format!(
        "{}/phylax/approvals/{}/decide-token",
        state.config.phylaxd_url, capability.approval_id
    );
    let response = state
        .client
        .post(decide_url)
        .json(&json!({ "token": capability.token, "phone": envelope }))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            state.approvals.finish_decision(&pickup, true);
            tracing::info!(
                approval_id = capability.approval_id,
                "signed decision accepted"
            );
            Ok((
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({ "status": "accepted" })),
            ))
        }
        Ok(response) if response.status().is_server_error() => {
            // A phylaxd 5xx is transient: keep the entry so the phone can retry.
            state.approvals.finish_decision(&pickup, false);
            tracing::warn!(
                approval_id = capability.approval_id,
                status = %response.status(),
                "Phylax failed to process signed decision"
            );
            Err(StatusCode::BAD_GATEWAY)
        }
        Ok(response) => {
            state.approvals.finish_decision(&pickup, true);
            tracing::warn!(
                approval_id = capability.approval_id,
                status = %response.status(),
                "signed decision rejected"
            );
            Err(StatusCode::FORBIDDEN)
        }
        Err(_) => {
            state.approvals.finish_decision(&pickup, false);
            tracing::warn!(
                approval_id = capability.approval_id,
                "Phylax delivery failed"
            );
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

/// Reject malformed or oversized private notifications before state insertion.
fn valid_notification(request: &PublicApprovalRequest, token: &str) -> bool {
    let now = chrono_now();
    request.version == 1
        && request.approval_id > 0
        && request.expires_at > now
        && request.expires_at <= now.saturating_add(MAX_NOTIFICATION_LIFETIME_SECS)
        && request.nonce.len() == 43
        && request.request_digest.len() == 43
        && request.hidden_digest.len() == 43
        && !request.device_id.is_empty()
        && request.device_id.len() <= 128
        && !request.action.is_empty()
        && request.action.len() <= 256
        && !request.agent_name.is_empty()
        && request.agent_name.len() <= 256
        && !request.category.is_empty()
        && request.category.len() <= 256
        && !request.target_name.is_empty()
        && request.target_name.len() <= 512
        && token.len() >= 32
        && token.len() <= 512
}

/// Return current Unix seconds without trusting relay input.
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
/// HTTP boundary and capability-flow tests.
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Build a live public request and matching signed-envelope shape.
    fn fixture() -> (PublicApprovalRequest, PhoneDecisionEnvelope) {
        let request = PublicApprovalRequest {
            version: 1,
            approval_id: 42,
            nonce: "n".repeat(43),
            request_digest: "d".repeat(43),
            hidden_digest: "h".repeat(43),
            device_id: "phone-1".into(),
            action: "ssh_ca_sign".into(),
            agent_name: "codex".into(),
            category: "ssh-ca".into(),
            target_name: "host".into(),
            expires_at: chrono_now() + 300,
        };
        let envelope = PhoneDecisionEnvelope {
            version: request.version,
            approval_id: request.approval_id,
            nonce: request.nonce.clone(),
            request_digest: request.request_digest.clone(),
            decision: "approved".into(),
            device_id: request.device_id.clone(),
            issued_at: chrono_now(),
            expires_at: request.expires_at,
            signature: "opaque-signature".into(),
        };
        (request, envelope)
    }

    /// Build a test public router pointed at a local mock Phylax origin.
    fn test_router(approvals: ApprovalState, phylaxd_url: String) -> Router {
        let config = Arc::new(Config {
            bot_token: "unused".into(),
            chat_id: 1,
            phylaxd_url,
            notify_token: "a".repeat(43),
            notify_bind: "10.0.0.1:0".parse().expect("notify bind"),
            phone_bind: "127.0.0.1:0".parse().expect("phone bind"),
            public_base_url: config::APPROVAL_PUBLIC_ORIGIN.into(),
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client");
        build_phone_router(PhoneState {
            approvals,
            client,
            config,
        })
    }

    /// Public GET omits the server capability and a successful POST consumes once.
    #[tokio::test]
    async fn public_api_is_capability_safe_and_one_shot() {
        let mock = Router::new().route(
            "/phylax/approvals/{id}/decide-token",
            post(|| async { StatusCode::OK }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, mock).await;
        });

        let approvals = ApprovalState::new();
        let (public, envelope) = fixture();
        let handle = approvals
            .insert("server-capability".into(), public, chrono_now())
            .expect("insert approval");
        let router = test_router(approvals, format!("http://{address}"));

        let get_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/phone/requests/{handle}"))
                    .body(Body::empty())
                    .expect("GET request"),
            )
            .await
            .expect("GET response");
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = get_response
            .into_body()
            .collect()
            .await
            .expect("GET body")
            .to_bytes();
        assert!(!String::from_utf8_lossy(&get_body).contains("server-capability"));

        let body = serde_json::to_vec(&envelope).expect("decision JSON");
        let first = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/phone/requests/{handle}/decision"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .expect("first POST"),
            )
            .await
            .expect("first response");
        assert_eq!(first.status(), StatusCode::OK);

        let replay = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/phone/requests/{handle}/decision"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("replay POST"),
            )
            .await
            .expect("replay response");
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    }

    /// Malformed and unknown pickup handles return a uniform not-found response.
    #[tokio::test]
    async fn invalid_pickup_handles_are_uniformly_rejected() {
        let router = test_router(ApprovalState::new(), "http://127.0.0.1:1".into());
        for handle in ["short", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/phone/requests/{handle}"))
                        .body(Body::empty())
                        .expect("invalid GET"),
                )
                .await
                .expect("invalid response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_public_security_headers(response.headers());
        }
    }

    /// Public responses carry the full anti-cache and containment policy.
    #[tokio::test]
    async fn public_security_headers_cover_success_and_fallback() {
        let approvals = ApprovalState::new();
        let (public, _) = fixture();
        let handle = approvals
            .insert("server-capability".into(), public, chrono_now())
            .expect("insert approval");
        let router = test_router(approvals, "http://127.0.0.1:1".into());
        for uri in [format!("/v1/phone/requests/{handle}"), "/missing".into()] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("public request"),
                )
                .await
                .expect("public response");
            assert_public_security_headers(response.headers());
        }
    }

    /// Browser fallback never redirects a pickup handle into a custom URI scheme.
    #[tokio::test]
    async fn app_link_fallback_never_redirects() {
        let approvals = ApprovalState::new();
        let (public, _) = fixture();
        let handle = approvals
            .insert("server-capability".into(), public, chrono_now())
            .expect("insert approval");
        let response = test_router(approvals, "http://127.0.0.1:1".into())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/phone/open/{handle}"))
                    .body(Body::empty())
                    .expect("App Link request"),
            )
            .await
            .expect("App Link response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_public_security_headers(response.headers());
    }

    /// Private notification intake rejects absent and incorrect credentials uniformly.
    #[tokio::test]
    async fn notify_intake_requires_bearer_authentication() {
        let config = Arc::new(Config {
            bot_token: "unused".into(),
            chat_id: 1,
            phylaxd_url: "http://127.0.0.1:4400".into(),
            notify_token: "a".repeat(43),
            notify_bind: "10.0.0.1:0".parse().expect("notify bind"),
            phone_bind: "127.0.0.1:0".parse().expect("phone bind"),
            public_base_url: config::APPROVAL_PUBLIC_ORIGIN.into(),
        });
        let router = build_notify_router(NotifyState {
            approvals: ApprovalState::new(),
            client: reqwest::Client::new(),
            config,
        });
        let body = serde_json::to_vec(&json!({
            "approval_id": 42,
            "action": "ssh_ca_sign",
            "agent_name": "codex",
            "category": "ssh-ca",
            "secret_name": "host",
            "decide_token": "s".repeat(43),
            "phone": {
                "version": 1,
                "device_id": "phone-1",
                "nonce": "n".repeat(43),
                "request_digest": "d".repeat(43),
                "hidden_digest": "h".repeat(43),
                "expires_at": chrono_now() + 60
            }
        }))
        .expect("notify JSON");
        for authorization in [None, Some(format!("Bearer {}", "b".repeat(43)))] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/notify")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(value) = authorization {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = router
                .clone()
                .oneshot(
                    request
                        .body(Body::from(body.clone()))
                        .expect("notify request"),
                )
                .await
                .expect("notify response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    /// Assert the fixed public response-header contract.
    fn assert_public_security_headers(headers: &HeaderMap) {
        assert_eq!(
            headers.get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "no-store, no-cache, must-revalidate, max-age=0"
            ))
        );
        assert_eq!(
            headers.get("content-security-policy"),
            Some(&HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            ))
        );
        assert_eq!(
            headers.get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            headers.get("referrer-policy"),
            Some(&HeaderValue::from_static("no-referrer"))
        );
    }
}
