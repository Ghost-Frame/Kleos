//! Integration tests for Phylax agent-native credential features.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::params;
use serde_json::{json, Value};
use tower::ServiceExt;

use kleos_cred::audit::{self, AccessTier, AuditAction};
use kleos_cred::crypto::derive_key;
use kleos_cred::storage::store_secret;
use kleos_cred::types::SecretData;
use kleos_cred::CredError;
use kleos_credd::state::AppState;
use kleos_lib::db::Database;
use kleos_lib::EngError;
use kleos_phylax::audit::{actions, log_phylax_audit};
use kleos_phylax::models::ssh_settings::{list_ssh_settings, upsert_ssh_settings};
use kleos_phylax::router::compose_router_with_phylax_state;
use kleos_phylax::ssh_ca_signer::{MintedSshCertificate, SignedSshCertificate, SshCaSigner};
use kleos_phylax::state::PhylaxState;

/// Fake SSH CA signer used by integration tests.
#[derive(Clone)]
struct FakeSshCaSigner;

/// Implement deterministic SSH CA responses for route contract tests.
impl SshCaSigner for FakeSshCaSigner {
    /// Return deterministic certificate text for route contract tests.
    fn sign(
        &self,
        _identity: &str,
        _principal: &str,
        _ttl: &str,
        _public_key: &str,
    ) -> Result<SignedSshCertificate, CredError> {
        Ok(SignedSshCertificate {
            cert_public_key: "ssh-ed25519-cert-v01@openssh.com AAAAFakeCert phylax@test".into(),
        })
    }

    /// Return deterministic key and certificate paths for route contract tests.
    fn mint(
        &self,
        agent: &str,
        _principal: &str,
        _ttl: &str,
    ) -> Result<MintedSshCertificate, CredError> {
        Ok(MintedSshCertificate {
            key_path: format!("/tmp/{}.key", agent).into(),
            cert_path: format!("/tmp/{}-cert.pub", agent).into(),
            cert_public_key: "ssh-ed25519-cert-v01@openssh.com AAAAFakeCert phylax@test".into(),
        })
    }
}

/// Test harness wrapping a Phylax-enabled router.
struct TestApp {
    /// Combined credd + phylax router with all middleware applied.
    router: Router,
    /// Shared test database.
    db: std::sync::Arc<Database>,
    /// Hex-encoded master token derived from the test password.
    master_token: String,
}

/// Helpers for building and exercising a Phylax-aware test app.
impl TestApp {
    /// Create a test app with in-memory DB, migrations applied.
    async fn new() -> Self {
        let db = Database::connect_memory().await.expect("in-memory db");
        let master_password = "test-master-password";
        let master_key = derive_key(1, master_password.as_bytes(), None);
        let master_token = hex::encode(*master_key);

        let app_state = AppState::new(db, *master_key);
        let phylax_state = PhylaxState::from_app_state(app_state.clone())
            .with_ssh_ca_signer(std::sync::Arc::new(FakeSshCaSigner));

        // Compose base credd routes with phylax extensions and shared policy
        // middleware ordering.
        let router = compose_router_with_phylax_state(phylax_state);

        Self {
            router,
            db: app_state.db.clone(),
            master_token,
        }
    }

    /// Send an authenticated request with the master token.
    async fn request_master(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.request_auth(method, path, body, &self.master_token.clone())
            .await
    }

    /// Send an authenticated request with a specific token.
    async fn request_auth(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", token));

        let body = if let Some(json) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json).unwrap())
        } else {
            Body::empty()
        };

        let req = builder.body(body).unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: Value = if body_bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body_bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    /// Send an authenticated request carrying a one-shot Phylax approval lease.
    async fn request_auth_with_lease(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        token: &str,
        lease: &str,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", token))
            .header("x-phylax-lease", lease);

        let body = if let Some(json) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json).unwrap())
        } else {
            Body::empty()
        };

        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
        (status, json)
    }
}

// ---- Policy CRUD tests ----

/// Test full create/read/update/delete lifecycle for access policies.
#[tokio::test]
async fn test_policy_crud() {
    let app = TestApp::new().await;

    // List policies -- should be empty.
    let (status, body) = app.request_master("GET", "/phylax/policies", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["policies"].as_array().unwrap().len(), 0);

    // Create a policy.
    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": true,
                "allowed_modes": ["text", "proxy"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let policy_id = body["id"].as_i64().unwrap();
    assert!(policy_id > 0);
    assert_eq!(body["namespace"], "default");
    assert_eq!(body["require_approval"], true);

    // List policies -- should have one.
    let (status, body) = app.request_master("GET", "/phylax/policies", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["policies"].as_array().unwrap().len(), 1);

    // Update the policy.
    let (status, _) = app
        .request_master(
            "PUT",
            &format!("/phylax/policies/{}", policy_id),
            Some(json!({
                "require_approval": false,
                "allowed_modes": ["text"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Delete the policy.
    let (status, _) = app
        .request_master("DELETE", &format!("/phylax/policies/{}", policy_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // List policies -- should be empty again.
    let (status, body) = app.request_master("GET", "/phylax/policies", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["policies"].as_array().unwrap().len(), 0);
}

// ---- Approval flow tests ----

/// A metadata-only approval can be decided but cannot mint an operation lease.
#[tokio::test]
async fn test_approval_flow() {
    let app = TestApp::new().await;

    // Create a policy requiring approval for prod secrets.
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": true
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Create an agent key for testing.
    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "test-agent",
                "categories": ["prod/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    // Agent requests approval.
    let (status, body) = app
        .request_auth(
            "POST",
            "/phylax/approvals",
            Some(json!({
                "category": "prod",
                "secret_name": "deploy-key",
                "resolve_mode": "text"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let approval_id = body["approval_id"].as_i64().unwrap();
    assert!(approval_id > 0);
    assert!(body["poll_url"]
        .as_str()
        .unwrap()
        .contains(&approval_id.to_string()));

    // Get approval status -- should be pending (status=0).
    let (status, body) = app
        .request_master("GET", &format!("/phylax/approvals/{}", approval_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], 0);

    // Approve it.
    let (status, body) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{}", approval_id),
            Some(json!({
                "decision": "approved",
                "reason": "test approval"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "approved");
    assert!(body.get("lease").is_none());

    // Without a server-observed request body there is no exact operation to
    // bind, so the approval cannot become a generic capability.
    let (status, body) = app.request_master("GET", "/phylax/leases", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["leases"].as_array().unwrap().is_empty());
}

/// Raw mode is plaintext-returning, so agents are denied outright under the
/// five-mode no-plaintext model -- even a permissive policy cannot grant it.
/// (Until 2026-06 this returned a 202 approval flow; the approval workflow
/// remains for non-plaintext modes.)
#[tokio::test]
async fn test_resolve_raw_denied_for_agents() {
    let app = TestApp::new().await;

    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({
                "data": {
                    "type": "note",
                    "content": "super-secret"
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Even an explicitly raw-allowing policy must not open the plaintext path.
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": true,
                "allowed_modes": ["raw"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "raw-agent",
                "categories": ["prod/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/raw",
            Some(json!({
                "category": "prod",
                "name": "db-pass"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("super-secret"),
        "denial response must not leak the secret"
    );
}

/// Text mode substitutes plaintext into the response, so agents are denied
/// outright -- no policy consultation, no approval escape hatch.
#[tokio::test]
async fn test_resolve_text_denied_for_agents() {
    let app = TestApp::new().await;

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "text-agent",
                "categories": ["prod/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/text",
            Some(json!({"text": "{{secret:prod/db-pass}}"})),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Master keeps full access to the plaintext modes: the no-plaintext rule
/// binds agents only.
#[tokio::test]
async fn test_resolve_text_unaffected_for_master() {
    let app = TestApp::new().await;

    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({
                "data": {
                    "type": "note",
                    "content": "super-secret"
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_master(
            "POST",
            "/resolve/text",
            Some(json!({"text": "{{secret:prod/db-pass}}"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        serde_json::to_string(&body)
            .unwrap()
            .contains("super-secret"),
        "master text resolution must still substitute the secret"
    );
}

/// An agent resolve body the middleware cannot parse is denied, not passed
/// through: an unparseable secret reference must not evade policy checks.
#[tokio::test]
async fn test_agent_unparseable_resolve_body_denied() {
    let app = TestApp::new().await;

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "sneaky-agent",
                "categories": ["prod/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    // Parseable JSON but no category/name fields: the secret reference is
    // undeterminable, so the policy layer must deny rather than forward.
    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/proxy",
            Some(json!({"junk": true})),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A policy-store failure fails CLOSED for agents: no secret may move when
/// the authority cannot be consulted.
#[tokio::test]
async fn test_agent_resolve_fails_closed_on_policy_error() {
    let app = TestApp::new().await;

    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({
                "data": {
                    "type": "note",
                    "content": "super-secret"
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "outage-agent",
                "categories": ["prod/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    // Break the policy store out from under the middleware.
    app.db
        .write(|conn| {
            conn.execute("DROP TABLE phylax_access_policies", [])?;
            Ok(())
        })
        .await
        .expect("drop policy table");

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/proxy",
            Some(json!({
                "url": "https://api.example.com/",
                "secret_category": "prod",
                "secret_name": "db-pass"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("super-secret"),
        "fail-closed response must not leak the secret"
    );
}

// ---- Approval denial test ----

/// Test that an approval can be denied and returns denied status.
#[tokio::test]
async fn test_approval_denial() {
    let app = TestApp::new().await;

    // Create an agent key.
    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "deny-agent",
                "categories": ["prod/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    // Agent requests approval.
    let (status, body) = app
        .request_auth(
            "POST",
            "/phylax/approvals",
            Some(json!({
                "category": "prod",
                "secret_name": "secret-key",
                "resolve_mode": "text"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let approval_id = body["approval_id"].as_i64().unwrap();

    // Deny it.
    let (status, body) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{}", approval_id),
            Some(json!({
                "decision": "denied",
                "reason": "test denial"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "denied");
}

// ---- Namespace enumeration test ----

/// Test that policies created in different namespaces are all visible via
/// the namespace enumeration endpoint.
#[tokio::test]
async fn test_namespace_list() {
    let app = TestApp::new().await;

    // Create policies in different namespaces.
    for ns in &["alpha", "beta", "gamma"] {
        let (status, _) = app
            .request_master(
                "POST",
                "/phylax/policies",
                Some(json!({
                    "namespace": ns,
                    "require_approval": true
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    // List namespaces.
    let (status, body) = app.request_master("GET", "/phylax/namespaces", None).await;
    assert_eq!(status, StatusCode::OK);
    let namespaces = body["namespaces"].as_array().unwrap();
    assert_eq!(namespaces.len(), 3);
    assert!(namespaces.iter().any(|n| n == "alpha"));
    assert!(namespaces.iter().any(|n| n == "beta"));
    assert!(namespaces.iter().any(|n| n == "gamma"));
}

// ---- ECDH challenge test ----

/// Test that an ECDH challenge can be issued and returns a valid 32-byte nonce.
#[tokio::test]
async fn test_ecdh_challenge() {
    let app = TestApp::new().await;

    // Issue a challenge.
    let (status, body) = app
        .request_master("POST", "/phylax/ecdh/challenge", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["challenge_id"].is_string());
    assert!(body["nonce"].is_string());
    // Nonce should be 64 hex chars (32 bytes).
    assert_eq!(body["nonce"].as_str().unwrap().len(), 64);
}

// ---- SSH settings test ----

/// Test get/update lifecycle for SSH key settings on a specific secret.
#[tokio::test]
async fn test_ssh_settings() {
    let app = TestApp::new().await;

    // Get default settings (no settings configured yet).
    let (status, body) = app
        .request_master("GET", "/phylax/ssh/ssh-keys/deploy", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["auto_sign"], false);
    assert_eq!(body["auto_load"], false);

    // Update settings.
    let (status, body) = app
        .request_master(
            "PUT",
            "/phylax/ssh/ssh-keys/deploy",
            Some(json!({
                "auto_sign": true,
                "auto_load": true
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["auto_sign"], true);
    assert_eq!(body["auto_load"], true);

    // Get updated settings -- should reflect the change.
    let (status, body) = app
        .request_master("GET", "/phylax/ssh/ssh-keys/deploy", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["auto_sign"], true);
    assert_eq!(body["auto_load"], true);
}

// ---- SSH CA tests ----

/// Test that Phylax can sign caller-provided SSH public keys through its SSH CA endpoint.
#[tokio::test]
async fn test_ssh_ca_sign_endpoint() {
    let app = TestApp::new().await;

    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/ssh-ca/sign",
            Some(json!({
                "identity": "codex-test",
                "principal": "operator",
                "ttl": "+5m",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyForRouteContractOnly codex@test"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["identity"], "codex-test");
    assert_eq!(body["principal"], "operator");
    assert!(body["cert_public_key"]
        .as_str()
        .unwrap()
        .contains("ssh-ed25519-cert"));
}

/// Test that Phylax can mint an agent keypair and SSH certificate without returning private key bytes.
#[tokio::test]
async fn test_ssh_ca_mint_endpoint_does_not_return_private_key() {
    let app = TestApp::new().await;

    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/ssh-ca/mint",
            Some(json!({
                "agent": "codex-test",
                "principal": "operator",
                "ttl": "+5m"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["agent"], "codex-test");
    assert_eq!(body["principal"], "operator");
    assert!(body["cert_public_key"]
        .as_str()
        .unwrap()
        .contains("ssh-ed25519-cert"));
    assert!(
        body.get("private_key").is_none(),
        "mint endpoint must not return private key bytes"
    );
    // Server filesystem paths must not leak to the caller.
    assert!(
        body.get("key_path").is_none(),
        "mint endpoint must not return the server key path"
    );
    assert!(
        body.get("cert_path").is_none(),
        "mint endpoint must not return the server cert path"
    );
}

/// Test that Phylax rejects malformed SSH CA signing requests before invoking a signer.
#[tokio::test]
async fn test_ssh_ca_sign_rejects_missing_public_key() {
    let app = TestApp::new().await;

    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/ssh-ca/sign",
            Some(json!({
                "identity": "codex-test",
                "principal": "operator",
                "ttl": "+5m"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("public_key"));
}

/// A multi-year TTL must be rejected before any signing occurs (master path).
#[tokio::test]
async fn test_ssh_ca_sign_rejects_overlong_ttl() {
    let app = TestApp::new().await;

    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/ssh-ca/sign",
            Some(json!({
                "identity": "codex-test",
                "principal": "operator",
                "ttl": "+9999w",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyForRouteContractOnly codex@test"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("ttl"));
}

/// A path-traversal identity must be rejected before reaching the signer.
#[tokio::test]
async fn test_ssh_ca_mint_rejects_traversal_agent() {
    let app = TestApp::new().await;

    let (status, _body) = app
        .request_master(
            "POST",
            "/phylax/ssh-ca/mint",
            Some(json!({
                "agent": "../../etc/cron.d/x",
                "principal": "operator",
                "ttl": "+5m"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Helper: create an agent token (non-master) for authorization tests.
async fn create_agent_token(app: &TestApp, name: &str) -> String {
    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": name,
                "categories": ["ssh-ca/*"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "agent creation failed: {body:?}");
    body["key"].as_str().unwrap().to_string()
}

/// A non-master caller must NOT be able to sign directly: the request goes
/// through the M3 approval gate, and a denial yields 403. This is the core
/// privilege-escalation fix -- before it, any valid token could mint a root cert.
#[tokio::test]
async fn test_ssh_ca_sign_non_master_is_gated_and_denied() {
    let app = TestApp::new().await;
    let agent_key = create_agent_token(&app, "ca-agent-denied").await;

    // Fire the sign request as the agent; it will block on the approval gate.
    let router: Router = app.router.clone();
    let key = agent_key.clone();
    let handle = tokio::spawn(async move {
        let req = Request::builder()
            .method("POST")
            .uri("/phylax/ssh-ca/sign")
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "identity": "ca-agent-denied",
                    "principal": "root",
                    "ttl": "+5m",
                    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyForRouteContractOnly a@b"
                }))
                .unwrap(),
            ))
            .unwrap();
        router.oneshot(req).await.unwrap().status()
    });

    // Find the pending approval via the agent's own (user-scoped) list, then deny it as master.
    let mut approval_id = None;
    for _ in 0..50 {
        let (_, list) = app
            .request_auth("GET", "/phylax/approvals", None, &agent_key)
            .await;
        if let Some(arr) = list["approvals"].as_array() {
            if let Some(a) = arr.iter().find(|a| a["status"].as_i64() == Some(0)) {
                approval_id = a["id"].as_i64();
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let id = approval_id.expect("non-master sign must create a pending approval");

    let (st, _) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{id}"),
            Some(json!({ "decision": "denied" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    let status = handle.await.unwrap();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "denied non-master sign must be 403"
    );
}

/// A non-master caller CAN sign once a human approves the M3 request.
#[tokio::test]
async fn test_ssh_ca_sign_non_master_succeeds_after_approval() {
    let app = TestApp::new().await;
    let agent_key = create_agent_token(&app, "ca-agent-approved").await;

    let router: Router = app.router.clone();
    let key = agent_key.clone();
    let handle = tokio::spawn(async move {
        let req = Request::builder()
            .method("POST")
            .uri("/phylax/ssh-ca/sign")
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "identity": "ca-agent-approved",
                    "principal": "operator",
                    "ttl": "+5m",
                    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyForRouteContractOnly a@b"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    });

    let mut approval_id = None;
    for _ in 0..50 {
        let (_, list) = app
            .request_auth("GET", "/phylax/approvals", None, &agent_key)
            .await;
        if let Some(arr) = list["approvals"].as_array() {
            if let Some(a) = arr.iter().find(|a| a["status"].as_i64() == Some(0)) {
                approval_id = a["id"].as_i64();
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let id = approval_id.expect("non-master sign must create a pending approval");

    let (st, _) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{id}"),
            Some(json!({ "decision": "approved" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    let (status, body) = handle.await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "approved non-master sign must be 200"
    );
    assert!(body["cert_public_key"]
        .as_str()
        .unwrap()
        .contains("ssh-ed25519-cert"));
}

// ---- PIV enrollment test ----

/// Test PIV public key enrollment and revocation, including idempotency
/// check (double-revoke must fail).
#[tokio::test]
async fn test_piv_enroll_revoke() {
    let app = TestApp::new().await;

    // Enroll a pubkey.
    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/ecdh/enroll",
            Some(json!({
                "agent_name": "test-agent",
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let pubkey_id = body["id"].as_i64().unwrap();
    assert!(pubkey_id > 0);

    // Revoke it.
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/ecdh/revoke",
            Some(json!({
                "pubkey_id": pubkey_id
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Revoking again should fail (already revoked).
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/ecdh/revoke",
            Some(json!({
                "pubkey_id": pubkey_id
            })),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
/// Verify legacy audit insertion still works with the new nullable columns present.
async fn test_log_audit_compatible_after_cred_audit_extension() {
    let app = TestApp::new().await;

    let audit_id = audit::log_audit(
        &app.db,
        1,
        Some("agent-legacy"),
        AuditAction::Get,
        "prod",
        "api-key",
        Some(AccessTier::Proxy),
        true,
    )
    .await
    .unwrap();

    let (operator_id, source_ip, policy_id, session_id): (Option<String>, Option<String>, Option<i64>, Option<String>) =
        app.db
            .read(move |conn| {
                conn.query_row(
                    "SELECT operator_id, source_ip, policy_id, session_id FROM cred_audit WHERE id = ?1",
                    params![audit_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                        ))
                    },
                )
                .map_err(|e| EngError::DatabaseMessage(e.to_string()))
            })
            .await
            .unwrap();

    assert!(operator_id.is_none());
    assert!(source_ip.is_none());
    assert!(policy_id.is_none());
    assert!(session_id.is_none());
}

#[tokio::test]
/// Verify Phylax audit can write operator/source/policy/session metadata columns.
async fn test_phylax_audit_writes_attribution_columns() {
    let app = TestApp::new().await;

    let id = log_phylax_audit(
        &app.db,
        1,
        Some("agent-1"),
        Some("operator-1"),
        Some("127.0.0.1"),
        Some(42),
        Some("session-1"),
        actions::LEASE_MINTED,
        "prod",
        "api-key",
        true,
        Some("corr-1"),
    )
    .await
    .unwrap();

    let (operator_id, source_ip, policy_id, session_id): (Option<String>, Option<String>, Option<i64>, Option<String>) =
        app.db
            .read(move |conn| {
                conn.query_row(
                    "SELECT operator_id, source_ip, policy_id, session_id FROM cred_audit WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                        ))
                    },
                )
                .map_err(|e| EngError::DatabaseMessage(e.to_string()))
            })
            .await
            .unwrap();

    assert_eq!(operator_id.as_deref(), Some("operator-1"));
    assert_eq!(source_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(policy_id, Some(42));
    assert_eq!(session_id.as_deref(), Some("session-1"));
}

#[tokio::test]
/// Verify lease redemption consumes approval without returning the secret value.
async fn test_redeem_lease_does_not_return_plaintext_secret() {
    let app = TestApp::new().await;

    let (status, _body) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_auth(
            "POST",
            "/agents",
            Some(json!({
                "name": "redeem-agent",
                "categories": ["prod/*"]
            })),
            &app.master_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/secret-key",
            Some(json!({
                "data": { "type": "api_key", "key": "super-secret-key" }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_auth(
            "POST",
            "/phylax/approvals",
            Some(json!({
                "category": "prod",
                "secret_name": "secret-key",
                "resolve_mode": "text"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let approval_id = body["approval_id"].as_i64().unwrap();

    // Legacy metadata-only approval creation cannot mint an operation lease.
    // Attach a synthetic digest here only to exercise the separate legacy
    // redeem response contract, which must never include plaintext material.
    kleos_phylax::models::approval::set_operation_digest(&app.db, approval_id, &[0x42; 32])
        .await
        .unwrap();

    let (status, body) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{}", approval_id),
            Some(json!({
                "decision": "approved",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let jti = body["lease"]["jti"].as_str().unwrap().to_string();

    let (status, body) = app
        .request_auth(
            "POST",
            &format!("/phylax/leases/{}/redeem", jti),
            None,
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "redeemed");
    assert!(body["secret"].is_null());
    assert_eq!(
        body["message"],
        "plaintext delivery disabled until proxy delivery is enabled"
    );
    assert!(
        !body.to_string().contains("super-secret-key"),
        "redeemed lease response must not contain the secret value"
    );

    let (status, body) = app
        .request_auth(
            "POST",
            &format!("/phylax/leases/{}/redeem", jti),
            None,
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "lease already redeemed");
}

// ---- list_ssh_settings model test ----

/// Verify list_ssh_settings returns all rows for a user, ordered by
/// category then secret_name, and excludes rows for other users.
#[tokio::test]
async fn test_list_ssh_settings_returns_all_rows_for_user() {
    let app = TestApp::new().await;

    // user_id=1 is the master; insert two settings rows via upsert.
    upsert_ssh_settings(&app.db, 1, "ssh-keys", "deploy", true, false)
        .await
        .unwrap();
    upsert_ssh_settings(&app.db, 1, "infra", "bastion", false, true)
        .await
        .unwrap();
    // Row for a different user -- must not appear in user_id=1 results.
    upsert_ssh_settings(&app.db, 99, "ssh-keys", "other", false, false)
        .await
        .unwrap();

    let rows = list_ssh_settings(&app.db, 1).await.unwrap();

    // Should be ordered category ASC, secret_name ASC: infra/bastion then ssh-keys/deploy.
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].category, "infra");
    assert_eq!(rows[0].secret_name, "bastion");
    assert!(!rows[0].auto_sign);
    assert!(rows[0].auto_load);

    assert_eq!(rows[1].category, "ssh-keys");
    assert_eq!(rows[1].secret_name, "deploy");
    assert!(rows[1].auto_sign);
    assert!(!rows[1].auto_load);
}

// ---- SSH sign + identities HTTP integration tests ----

/// Happy-path sign: generate an ephemeral ed25519 key, seed it with auto_sign=true,
/// POST to the sign endpoint, assert HTTP 200 + non-empty signature_hex, then
/// cryptographically verify the signature against the generated public key.
#[tokio::test]
async fn test_ssh_sign_auto_sign_true_returns_verified_signature() {
    // Must be in scope for `public_key.verify(...)` to resolve.
    use signature::Verifier;

    // Generate a fresh ephemeral key for this test.
    // ssh-key 0.6 requires rand_core 0.6.x; rand 0.9 (workspace) uses rand_core 0.9,
    // so we pull rand_core 0.6 directly as a dev-dependency.
    let key =
        ssh_key::private::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("ephemeral ed25519 key generation must succeed");
    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("private key must encode to OpenSSH PEM");
    let public_key = key.public_key().clone();
    // Encode public key in OpenSSH authorized_keys format for storage.
    let public_key_str = public_key
        .to_openssh()
        .expect("public key must encode to OpenSSH");

    let app = TestApp::new().await;
    let master_key = derive_key(1, "test-master-password".as_bytes(), None);

    // Seed the SSH key secret into the vault (user_id=1 is the master).
    store_secret(
        &app.db,
        1,
        "ssh-keys",
        "deploy",
        &SecretData::SshKey {
            private_key: pem.to_string(),
            public_key: Some(public_key_str.trim().to_string()),
            passphrase: None,
        },
        &master_key,
    )
    .await
    .expect("store_secret must succeed");

    // Mark the key as auto_sign=true so no approval gate is triggered.
    upsert_ssh_settings(&app.db, 1, "ssh-keys", "deploy", true, false)
        .await
        .expect("upsert_ssh_settings must succeed");

    // Bytes to sign -- use a short challenge.
    let challenge = b"http-integration-challenge";
    let data_hex = hex::encode(challenge);

    // POST /phylax/ssh/ssh-keys/deploy/sign with master auth.
    let (status, body) = app
        .request_master(
            "POST",
            "/phylax/ssh/ssh-keys/deploy/sign",
            Some(json!({ "data_hex": data_hex, "flags": 0 })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "sign endpoint must return 200; body={body}"
    );

    let sig_hex = body["signature_hex"]
        .as_str()
        .expect("signature_hex must be a string");
    assert!(!sig_hex.is_empty(), "signature_hex must not be empty");

    // Decode the SSH wire-format blob and verify it cryptographically.
    let blob = hex::decode(sig_hex).expect("signature_hex must be valid hex");
    let sig = ssh_key::Signature::try_from(blob.as_slice())
        .expect("blob must decode as a valid ssh_key::Signature");

    // Call through key_data() to reach the Verifier<ssh_key::Signature> impl
    // (mirrors ssh_sign_test.rs approach).
    Verifier::verify(public_key.key_data(), challenge.as_slice(), &sig)
        .expect("signature must cryptographically verify against the generated public key");
}

/// Identities lists public-only: generate an ephemeral key, seed it with auto_sign=true,
/// GET /phylax/ssh/identities, assert the key appears with public_openssh populated
/// and auto_sign=true, and assert no private key material leaks into the response JSON.
#[tokio::test]
async fn test_ssh_identities_returns_public_material_only() {
    // Generate a fresh ephemeral key for this test -- independent of the sign test's key.
    let key =
        ssh_key::private::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("ephemeral ed25519 key generation must succeed");
    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("private key must encode to OpenSSH PEM");
    let public_key_str = key
        .public_key()
        .to_openssh()
        .expect("public key must encode to OpenSSH");

    let app = TestApp::new().await;
    let master_key = derive_key(1, "test-master-password".as_bytes(), None);

    // Seed the key.
    store_secret(
        &app.db,
        1,
        "ssh-keys",
        "id-test",
        &SecretData::SshKey {
            private_key: pem.to_string(),
            public_key: Some(public_key_str.trim().to_string()),
            passphrase: None,
        },
        &master_key,
    )
    .await
    .expect("store_secret must succeed");

    // Set auto_sign=true so the key appears in identities.
    upsert_ssh_settings(&app.db, 1, "ssh-keys", "id-test", true, false)
        .await
        .expect("upsert_ssh_settings must succeed");

    // GET /phylax/ssh/identities with master auth.
    let (status, body) = app
        .request_master("GET", "/phylax/ssh/identities", None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "identities endpoint must return 200; body={body}"
    );

    let identities = body["identities"]
        .as_array()
        .expect("response must have identities array");
    // Find the seeded key in the list.
    let entry = identities
        .iter()
        .find(|e| e["category"] == "ssh-keys" && e["name"] == "id-test")
        .expect("seeded key must appear in identities");

    // Public key must be populated and be a non-empty string.
    let public_openssh = entry["public_openssh"]
        .as_str()
        .expect("public_openssh must be a string");
    assert!(
        !public_openssh.is_empty(),
        "public_openssh must not be empty"
    );

    // auto_sign must be reflected as true.
    assert_eq!(
        entry["auto_sign"], true,
        "auto_sign must be true for the seeded key"
    );

    // The raw JSON body must not contain any private key material.
    let raw_json = body.to_string();
    assert!(
        !raw_json.contains("PRIVATE KEY"),
        "response must not contain private key material (found 'PRIVATE KEY')"
    );
    assert!(
        !raw_json.contains("BEGIN OPENSSH"),
        "response must not contain private key PEM envelope (found 'BEGIN OPENSSH')"
    );
}

/// Stub for the approval-gate path (auto_sign=false). This test is intentionally
/// ignored because it would require a 25-second wall-clock wait for the approval
/// timeout to fire. The gate's logic is unit-tested in the sign handler; the
/// manual e2e path is covered by Task 12.
#[tokio::test]
#[ignore = "approval-gate path takes up to 25 s; verified by gate unit logic and Task 12 e2e"]
async fn test_ssh_sign_auto_sign_false_requires_approval_gate() {
    // When auto_sign=false, POST /phylax/ssh/{category}/{name}/sign must
    // create a pending approval and block until approved or timed-out (25 s max).
    // This long-running path is not exercised in automated CI; see Task 12.
}

// ---- Capability-token approval decision (decide-token) ----

/// Builds a signed exact-phone decision using the protocol implementation.
fn sign_phone_decision(
    signing_key: &p256::ecdsa::SigningKey,
    approval_id: i64,
    device_id: &str,
    binding: &kleos_phylax::models::approval::PhoneApprovalBinding,
    decision: kleos_phylax::models::phone_approval::PhoneDecision,
) -> kleos_phylax::models::phone_approval::PhoneDecisionEnvelope {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Signer;

    let mut envelope = kleos_phylax::models::phone_approval::PhoneDecisionEnvelope {
        version: kleos_phylax::models::phone_approval::PHONE_APPROVAL_VERSION,
        approval_id,
        nonce: binding.nonce.clone(),
        request_digest: binding.request_digest.clone(),
        decision,
        device_id: device_id.to_string(),
        issued_at: chrono::Utc::now().timestamp(),
        expires_at: binding.expires_at,
        signature: String::new(),
    };
    let message = envelope.canonical_message().expect("canonical decision");
    let signature: p256::ecdsa::Signature = signing_key.sign(&message);
    envelope.signature = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());
    envelope
}

/// Enrolls one verified test phone and returns its signing key and device row.
async fn enroll_test_phone(
    app: &TestApp,
) -> (
    p256::ecdsa::SigningKey,
    kleos_phylax::models::phone_device::PhoneDevice,
) {
    use p256::pkcs8::EncodePublicKey;

    let signing_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let public_key = signing_key
        .verifying_key()
        .to_public_key_der()
        .expect("encode phone public key");
    let device = kleos_phylax::models::phone_device::enroll_verified_device(
        &app.db,
        1,
        "Zan primary phone",
        public_key.as_bytes(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .await
    .expect("enroll test phone");
    (signing_key, device)
}

/// A phone-required approval rejects a legacy Telegram-only decision.
#[tokio::test]
async fn test_phone_required_rejects_legacy_decision() {
    use kleos_phylax::models::approval;

    let app = TestApp::new().await;
    let (_, _) = enroll_test_phone(&app).await;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(300))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (ap, raw_token) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "codex-test",
        "ssh_ca_sign",
        Some("phone-required-test"),
        &expires_at,
    )
    .await
    .expect("create approval");
    approval::bind_phone_approval(&app.db, &ap)
        .await
        .expect("bind phone challenge");

    let path = format!("/phylax/approvals/{}/decide-token", ap.id);
    let (status, _) = app
        .request_auth(
            "POST",
            &path,
            Some(json!({ "token": raw_token, "decision": "approved" })),
            "ignored-bearer",
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A readable master bearer cannot bypass an approval already bound to the phone.
#[tokio::test]
async fn test_phone_required_rejects_master_decision_route() {
    use kleos_phylax::models::approval;

    let app = TestApp::new().await;
    let (_, _) = enroll_test_phone(&app).await;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(300))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (ap, _) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "master-bypass-test",
        "ssh_ca_sign",
        Some("master-bypass-test"),
        &expires_at,
    )
    .await
    .expect("create approval");
    approval::bind_phone_approval(&app.db, &ap)
        .await
        .expect("bind phone challenge");

    let (status, _) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{}", ap.id),
            Some(json!({ "decision": "approved" })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    let persisted = approval::get_approval(&app.db, ap.id)
        .await
        .expect("load approval");
    assert_eq!(persisted.status, approval::ApprovalStatus::Pending);
}

/// Binding selects the sole active phone and rejects ambiguous active enrollment.
#[tokio::test]
async fn test_phone_binding_requires_exactly_one_active_device() {
    use kleos_phylax::models::approval;

    let app = TestApp::new().await;
    let (_, device) = enroll_test_phone(&app).await;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(300))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (single, _) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "sole-device-test",
        "ssh_ca_sign",
        None,
        &expires_at,
    )
    .await
    .expect("create approval");
    let binding = approval::bind_phone_approval(&app.db, &single)
        .await
        .expect("bind sole phone");
    assert_eq!(binding.device_id, device.device_id);

    let app = TestApp::new().await;
    let _ = enroll_test_phone(&app).await;
    let _ = enroll_test_phone(&app).await;
    let (ambiguous, _) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "ambiguous-device-test",
        "ssh_ca_sign",
        None,
        &expires_at,
    )
    .await
    .expect("create approval");
    assert!(approval::bind_phone_approval(&app.db, &ambiguous)
        .await
        .is_err());
}

/// A valid enrolled-phone signature approves once and a replay is rejected.
#[tokio::test]
async fn test_phone_decision_verifies_and_replay_fails() {
    use kleos_phylax::models::approval;
    use kleos_phylax::models::phone_approval::PhoneDecision;

    let app = TestApp::new().await;
    let (signing_key, device) = enroll_test_phone(&app).await;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(300))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (ap, raw_token) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "codex-test",
        "ssh_ca_sign",
        Some("signed-phone-test"),
        &expires_at,
    )
    .await
    .expect("create approval");
    let binding = approval::bind_phone_approval(&app.db, &ap)
        .await
        .expect("bind phone challenge");
    let envelope = sign_phone_decision(
        &signing_key,
        ap.id,
        &device.device_id,
        &binding,
        PhoneDecision::Approved,
    );
    let body = json!({ "token": raw_token, "phone": envelope });
    let path = format!("/phylax/approvals/{}/decide-token", ap.id);

    let (status, response) = app
        .request_auth("POST", &path, Some(body.clone()), "ignored-bearer")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["status"], 1);

    let (status, leases) = app.request_master("GET", "/phylax/leases", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        leases["leases"].as_array().unwrap().is_empty(),
        "direct-status SSH CA approval must not mint a generic resolve lease"
    );

    let (status, _) = app
        .request_auth("POST", &path, Some(body), "ignored-bearer")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "replay must fail closed");
}

/// A revoked enrolled device cannot decide a still-pending approval.
#[tokio::test]
async fn test_revoked_phone_is_rejected() {
    use kleos_phylax::models::phone_approval::PhoneDecision;
    use kleos_phylax::models::{approval, phone_device};

    let app = TestApp::new().await;
    let (signing_key, device) = enroll_test_phone(&app).await;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(300))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (ap, raw_token) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "codex-test",
        "ssh_ca_sign",
        Some("revoked-phone-test"),
        &expires_at,
    )
    .await
    .expect("create approval");
    let binding = approval::bind_phone_approval(&app.db, &ap)
        .await
        .expect("bind phone challenge");
    let envelope = sign_phone_decision(
        &signing_key,
        ap.id,
        &device.device_id,
        &binding,
        PhoneDecision::Approved,
    );
    phone_device::revoke_device(&app.db, 1, &device.device_id)
        .await
        .expect("revoke phone");
    let path = format!("/phylax/approvals/{}/decide-token", ap.id);

    let (status, _) = app
        .request_auth(
            "POST",
            &path,
            Some(json!({ "token": raw_token, "phone": envelope })),
            "ignored-bearer",
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The auth-exempt `POST /phylax/approvals/{id}/decide-token` route accepts only
/// the single-use capability token: a wrong token is rejected, the correct token
/// approves once, and a replay cannot flip an already-decided approval.
#[tokio::test]
async fn test_decide_token_single_use() {
    use kleos_phylax::models::approval;

    let app = TestApp::new().await;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(300))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let (ap, raw_token) = approval::create_approval_with_token(
        &app.db,
        1,
        "test-agent",
        "ssh-ca",
        "codex-test",
        "ssh_ca_sign",
        None,
        &expires_at,
    )
    .await
    .expect("create approval with token");

    let path = format!("/phylax/approvals/{}/decide-token", ap.id);

    // (a) Wrong token -> rejected. The route is auth-exempt, so the bearer is
    // irrelevant; the body token is the only authorization.
    let (status, _) = app
        .request_auth(
            "POST",
            &path,
            Some(json!({ "token": "deadbeef", "decision": "approved" })),
            "ignored-bearer",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "wrong token must be rejected"
    );

    // (b) Correct token + approved -> 200 with status=1 (Approved).
    let (status, body) = app
        .request_auth(
            "POST",
            &path,
            Some(json!({ "token": raw_token, "decision": "approved" })),
            "ignored-bearer",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "correct token must be accepted");
    assert_eq!(body["status"], 1, "decision must be Approved");

    // (c) Replay the (now-cleared) token with a different decision -> must not
    // flip an already-decided approval; still reports Approved.
    let (status, body) = app
        .request_auth(
            "POST",
            &path,
            Some(json!({ "token": raw_token, "decision": "denied" })),
            "ignored-bearer",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["status"], 1,
        "a replayed token must not re-decide an approval"
    );
}

// ---- Non-plaintext resolve mode tests (verify / sign / derive) ----

/// Create the standard fixture for mode tests: a note secret
/// prod/db-pass = "super-secret", a policy with the given allowed modes,
/// and an agent key scoped to prod/*. Returns the agent key.
async fn setup_mode_fixture(
    app: &TestApp,
    agent: &str,
    allowed_modes: Value,
    require_approval: bool,
) -> String {
    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({
                "data": {
                    "type": "note",
                    "content": "super-secret"
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": require_approval,
                "allowed_modes": allowed_modes
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": agent,
                "categories": ["prod"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    body["key"].as_str().unwrap().to_string()
}

/// derive without any policy is denied: the new modes are deny-by-default.
#[tokio::test]
async fn test_derive_requires_explicit_policy() {
    let app = TestApp::new().await;

    // Secret + agent, but NO policy at all.
    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({"data": {"type": "note", "content": "super-secret"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({"name": "derive-agent", "categories": ["prod"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "session-key",
                "length": 32
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A policy that names other modes does not grant derive.
#[tokio::test]
async fn test_derive_mode_not_in_policy_denied() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "narrow-agent", json!(["sign"]), false).await;

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "session-key",
                "length": 32
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// derive happy path: deterministic, purpose-separated, never leaks the
/// root secret.
#[tokio::test]
async fn test_derive_happy_path_deterministic_and_purpose_separated() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "derive-agent", json!(["derive"]), false).await;

    let req = json!({
        "category": "prod",
        "name": "db-pass",
        "purpose": "session-key",
        "length": 32
    });
    let (status, body1) = app
        .request_auth("POST", "/resolve/derive", Some(req.clone()), &agent_key)
        .await;
    assert_eq!(status, StatusCode::OK, "derive failed: {body1}");
    let derived1 = body1["derived_b64"]
        .as_str()
        .expect("derived_b64")
        .to_string();
    assert!(
        !serde_json::to_string(&body1)
            .unwrap()
            .contains("super-secret"),
        "derive response must not leak the root secret"
    );

    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&derived1)
        .expect("valid base64");
    assert_eq!(raw.len(), 32);

    // Same inputs, same output.
    let (_, body2) = app
        .request_auth("POST", "/resolve/derive", Some(req), &agent_key)
        .await;
    assert_eq!(body2["derived_b64"].as_str().unwrap(), derived1);

    // Different purpose, different output.
    let (_, body3) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "other-purpose",
                "length": 32
            })),
            &agent_key,
        )
        .await;
    assert_ne!(body3["derived_b64"].as_str().unwrap(), derived1);
}

/// derive input validation: empty purpose and oversize length are 400s.
#[tokio::test]
async fn test_derive_rejects_bad_inputs() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "picky-agent", json!(["derive"]), false).await;

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "",
                "length": 32
            })),
            &agent_key,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "empty purpose must be rejected"
    );

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "p",
                "length": 65
            })),
            &agent_key,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "length > 64 must be rejected"
    );
}

/// hmac-sha256 sign + verify round trip through both endpoints, plus a
/// tamper check, with no key material in any response.
#[tokio::test]
async fn test_sign_verify_hmac_round_trip() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "hmac-agent", json!(["sign", "verify"]), false).await;

    use base64::Engine as _;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"attest this");

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/sign",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "payload_b64": payload_b64,
                "algo": "hmac-sha256"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "sign failed: {body}");
    let signature_b64 = body["signature_b64"]
        .as_str()
        .expect("signature")
        .to_string();
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("super-secret"),
        "sign response must not leak the key"
    );

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/verify",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "payload_b64": payload_b64,
                "signature_b64": signature_b64,
                "algo": "hmac-sha256"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);

    // Tampered payload must not verify.
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(b"attest THAT");
    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/verify",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "payload_b64": tampered_b64,
                "signature_b64": signature_b64,
                "algo": "hmac-sha256"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], false);
}

/// ed25519 sign + verify round trip over a stored SSH key secret.
#[tokio::test]
async fn test_sign_verify_ed25519_round_trip() {
    let app = TestApp::new().await;

    // Generate a throwaway ed25519 key for this test only.
    let key =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("generate test key");
    let pem = key.to_openssh(ssh_key::LineEnding::LF).expect("to openssh");

    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/signer",
            Some(json!({
                "data": {
                    "type": "ssh_key",
                    "private_key": *pem
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": false,
                "allowed_modes": ["sign", "verify"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({"name": "ed-agent", "categories": ["prod"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    use base64::Engine as _;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"release manifest");

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/sign",
            Some(json!({
                "category": "prod",
                "name": "signer",
                "payload_b64": payload_b64,
                "algo": "ed25519"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "ed25519 sign failed: {body}");
    let signature_b64 = body["signature_b64"]
        .as_str()
        .expect("signature")
        .to_string();
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("PRIVATE KEY"),
        "sign response must not leak key material"
    );

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/verify",
            Some(json!({
                "category": "prod",
                "name": "signer",
                "payload_b64": payload_b64,
                "signature_b64": signature_b64,
                "algo": "ed25519"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);
}

/// Unknown algorithms are a client error, not a crash or a silent fallback.
#[tokio::test]
async fn test_sign_unknown_algo_rejected() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "algo-agent", json!(["sign"]), false).await;

    use base64::Engine as _;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"x");
    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/sign",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "payload_b64": payload_b64,
                "algo": "md5"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// require_approval on a new mode goes through the 202 approval flow rather
/// than executing immediately.
#[tokio::test]
async fn test_derive_with_approval_policy_returns_202() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "approval-agent", json!(["derive"]), true).await;

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "session-key",
                "length": 32
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["approval_required"], true);
}

/// An approved lease reaches only the requesting agent, resumes one matching
/// operation, and is rejected on replay.
#[tokio::test]
async fn test_approved_derive_lease_resumes_once() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "lease-agent", json!(["derive"]), true).await;
    let request_body = json!({
        "category": "prod",
        "name": "db-pass",
        "purpose": "session-key",
        "length": 32
    });

    let (status, pending) = app
        .request_auth(
            "POST",
            "/resolve/derive",
            Some(request_body.clone()),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let approval_id = pending["approval_id"].as_i64().unwrap();

    let (status, _) = app
        .request_master(
            "PUT",
            &format!("/phylax/approvals/{approval_id}"),
            Some(json!({"decision": "approved"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let duplicate = kleos_phylax::models::lease::mint_lease(
        &app.db,
        1,
        approval_id,
        "lease-agent",
        "prod",
        "db-pass",
        None,
        300,
    )
    .await;
    assert!(
        duplicate.is_err(),
        "one approval must never mint more than one operation lease"
    );

    let (status, other_agent) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({"name": "lease-thief", "categories": ["prod"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let other_agent_key = other_agent["key"].as_str().unwrap();
    let (status, _) = app
        .request_auth(
            "GET",
            &format!("/phylax/approvals/{approval_id}/wait"),
            None,
            other_agent_key,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another same-user agent must not collect the approval lease"
    );

    let (status, decided) = app
        .request_auth(
            "GET",
            &format!("/phylax/approvals/{approval_id}/wait"),
            None,
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let lease = decided["lease"]["jti"].as_str().unwrap().to_string();

    let (status, _) = app
        .request_auth_with_lease(
            "POST",
            "/resolve/derive?mutated=true",
            Some(request_body.clone()),
            &agent_key,
            &lease,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "mutating the request target must reject without consuming the lease"
    );

    let (status, _) = app
        .request_auth_with_lease(
            "POST",
            "/resolve/derive",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "purpose": "different-purpose",
                "length": 32
            })),
            &agent_key,
            &lease,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "mutating mode-specific request fields must reject without consuming the lease"
    );

    let (status, completed) = app
        .request_auth_with_lease(
            "POST",
            "/resolve/derive",
            Some(request_body.clone()),
            &agent_key,
            &lease,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(completed["derived_b64"].is_string());

    let (status, _) = app
        .request_auth_with_lease(
            "POST",
            "/resolve/derive",
            Some(request_body),
            &agent_key,
            &lease,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Policy CRUD rejects unknown mode strings.
#[tokio::test]
async fn test_policy_rejects_unknown_mode_string() {
    let app = TestApp::new().await;
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": false,
                "allowed_modes": ["dervie"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- exec mode tests ----

/// Build the exec fixture: secret, exec policy with the given allowlist,
/// and an agent. Returns the agent key.
async fn setup_exec_fixture(app: &TestApp, agent: &str, allowlist: Option<Value>) -> String {
    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({"data": {"type": "note", "content": "super-secret"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let mut policy = json!({
        "namespace": "default",
        "category": "prod",
        "require_approval": false,
        "allowed_modes": ["exec"]
    });
    if let Some(list) = allowlist {
        policy["exec_allowlist"] = list;
    }
    let (status, body) = app
        .request_master("POST", "/phylax/policies", Some(policy))
        .await;
    assert_eq!(status, StatusCode::OK, "policy create failed: {body}");

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({"name": agent, "categories": ["prod"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    body["key"].as_str().unwrap().to_string()
}

/// exec runs an allowlisted command and scrubs the secret from its output,
/// even when the command prints its entire environment.
#[tokio::test]
async fn test_exec_runs_allowlisted_command_and_scrubs_secret() {
    let app = TestApp::new().await;
    let agent_key = setup_exec_fixture(&app, "exec-agent", Some(json!(["/usr/bin/env"]))).await;

    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/exec",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "argv": ["/usr/bin/env"],
                "env_var": "INJECTED_SECRET"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "exec failed: {body}");
    assert_eq!(body["timed_out"], false);
    assert_eq!(body["exit_code"], 0);

    use base64::Engine as _;
    let stdout = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(body["stdout_b64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        stdout.contains("INJECTED_SECRET=[redacted]"),
        "env var must be present but scrubbed, got: {stdout}"
    );
    assert!(
        !stdout.contains("super-secret"),
        "secret must never appear in exec output"
    );
}

/// A command not on the allowlist is denied even though exec mode itself
/// is policy-allowed.
#[tokio::test]
async fn test_exec_non_allowlisted_argv_denied() {
    let app = TestApp::new().await;
    let agent_key =
        setup_exec_fixture(&app, "exec-deny-agent", Some(json!(["/usr/bin/env"]))).await;

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/exec",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "argv": ["/bin/cat", "/etc/hostname"],
                "env_var": "X"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// An exec policy without an allowlist denies every command: the allowlist
/// is the capability, not the mode string alone.
#[tokio::test]
async fn test_exec_policy_without_allowlist_denies() {
    let app = TestApp::new().await;
    let agent_key = setup_exec_fixture(&app, "exec-null-agent", None).await;

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/exec",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "argv": ["/usr/bin/env"],
                "env_var": "X"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Relative argv[0] and malformed env var names are client errors.
#[tokio::test]
async fn test_exec_rejects_malformed_inputs() {
    let app = TestApp::new().await;
    let agent_key =
        setup_exec_fixture(&app, "exec-input-agent", Some(json!(["/usr/bin/env"]))).await;

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/exec",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "argv": ["env"],
                "env_var": "X"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "relative argv[0] must be rejected"
    );

    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/exec",
            Some(json!({
                "category": "prod",
                "name": "db-pass",
                "argv": ["/usr/bin/env"],
                "env_var": "BAD;NAME"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed env_var must be rejected"
    );
}

/// Policy CRUD rejects relative paths in the exec allowlist.
#[tokio::test]
async fn test_policy_rejects_relative_exec_allowlist() {
    let app = TestApp::new().await;
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": false,
                "allowed_modes": ["exec"],
                "exec_allowlist": ["env"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Adversarial plaintext-bypass: an agent granted EVERY mode still cannot
/// obtain the secret through any resolve path. text/raw deny outright; the
/// non-plaintext modes' responses never contain the secret in any form.
#[tokio::test]
async fn test_adversarial_agent_cannot_obtain_plaintext_via_any_mode() {
    let app = TestApp::new().await;

    let (status, _) = app
        .request_master(
            "POST",
            "/secret/prod/db-pass",
            Some(json!({"data": {"type": "note", "content": "super-secret"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Most permissive policy expressible: all modes, no approvals, env
    // allowlisted for exec.
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "prod",
                "require_approval": false,
                "allowed_modes": ["text", "proxy", "raw", "exec", "verify", "sign", "derive"],
                "exec_allowlist": ["/usr/bin/env"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request_master(
            "POST",
            "/agents",
            Some(json!({
                "name": "hostile-agent",
                "categories": ["prod"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

    // Every resolve request the agent can make against this secret.
    let attempts: Vec<(&str, Value)> = vec![
        ("/resolve/text", json!({"text": "{{secret:prod/db-pass}}"})),
        (
            "/resolve/raw",
            json!({"category": "prod", "name": "db-pass"}),
        ),
        (
            "/resolve/sign",
            json!({"category": "prod", "name": "db-pass",
                   "payload_b64": b64(b"x"), "algo": "hmac-sha256"}),
        ),
        (
            "/resolve/verify",
            json!({"category": "prod", "name": "db-pass",
                   "payload_b64": b64(b"x"), "signature_b64": b64(b"y"),
                   "algo": "hmac-sha256"}),
        ),
        (
            "/resolve/derive",
            json!({"category": "prod", "name": "db-pass",
                   "purpose": "leak-attempt", "length": 64}),
        ),
        (
            "/resolve/exec",
            json!({"category": "prod", "name": "db-pass",
                   "argv": ["/usr/bin/env"], "env_var": "S"}),
        ),
    ];

    let secret_hex = hex::encode(b"super-secret");
    let secret_b64 = b64(b"super-secret");

    for (path, body_json) in attempts {
        let (status, body) = app
            .request_auth("POST", path, Some(body_json), &agent_key)
            .await;
        if path == "/resolve/text" || path == "/resolve/raw" {
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} must deny agents");
        }
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains("super-secret")
                && !serialized.contains(&secret_hex)
                && !serialized.contains(&secret_b64),
            "{path} response leaked the secret: {serialized}"
        );
        // exec output is base64-wrapped; check the decoded streams too.
        if path == "/resolve/exec" {
            for stream in ["stdout_b64", "stderr_b64"] {
                if let Some(encoded) = body[stream].as_str() {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .unwrap_or_default();
                    let text = String::from_utf8_lossy(&decoded);
                    assert!(
                        !text.contains("super-secret"),
                        "exec {stream} leaked the secret: {text}"
                    );
                }
            }
        }
    }
}

/// Valid calls through both router branches leave the authentication failure budget available.
#[tokio::test]
async fn maintenance_phylax_valid_calls_preserve_failure_budget() {
    let app = TestApp::new().await;
    for _ in 0..20 {
        for path in ["/secrets", "/phylax/namespaces"] {
            let (status, _) = app.request_master("GET", path, None).await;
            assert_eq!(status, StatusCode::OK, "{path}");
        }
    }
    let mut pending = tokio::task::JoinSet::new();
    for index in 0..20 {
        let router = app.router.clone();
        pending.spawn(async move {
            router
                .oneshot(
                    Request::builder()
                        .uri(if index % 2 == 0 {
                            "/secrets"
                        } else {
                            "/phylax/namespaces"
                        })
                        .header("authorization", "Bearer invalid-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        });
    }
    let mut outcomes = Vec::new();
    while let Some(status) = pending.join_next().await {
        outcomes.push(status.unwrap());
    }
    assert_eq!(
        outcomes
            .iter()
            .filter(|status| **status == StatusCode::UNAUTHORIZED)
            .count(),
        10
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|status| **status == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        10
    );
}

// ---- Sealed proxy: policy extraction and ordering ----

/// SQL counting approval rows.
const COUNT_APPROVALS_SQL: &str = "SELECT COUNT(*) FROM phylax_approvals";

/// Count rows in the approvals table.
async fn approval_count(app: &TestApp) -> i64 {
    let read = app.db.read(|conn| {
        let n: i64 = conn.query_row(COUNT_APPROVALS_SQL, [], |r| r.get(0))?;
        Ok(n)
    });
    read.await.expect("count approvals")
}

/// Send a POST with an optional bearer, returning only the status.
async fn status_for(app: &TestApp, path: &str, token: Option<&str>, body: Value) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.router.clone().oneshot(req).await.unwrap().status()
}

/// A proxy body that smuggles a decoy `category`/`name` pair next to the real
/// `secret_category`/`secret_name` is refused outright. Before this, policy was
/// evaluated on the decoy pair while the handler used the real one.
#[tokio::test]
async fn test_proxy_decoy_fields_cannot_steer_policy() {
    let app = TestApp::new().await;
    let agent_key = setup_mode_fixture(&app, "decoy-agent", json!(["proxy"]), true).await;

    // A harmless category with a no-approval policy: the decoy target.
    let (status, _) = app
        .request_master(
            "POST",
            "/phylax/policies",
            Some(json!({
                "namespace": "default",
                "category": "harmless",
                "require_approval": false,
                "allowed_modes": ["proxy"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The honest request is held for approval by the prod policy.
    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/proxy",
            Some(json!({
                "url": "https://api.example.com/",
                "secret_category": "prod",
                "secret_name": "db-pass"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let approvals_before = approval_count(&app).await;

    // The decoy request is a hard error, not a pass-through and not a policy
    // decision on the decoy pair.
    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/proxy",
            Some(json!({
                "url": "https://api.example.com/",
                "secret_category": "prod",
                "secret_name": "db-pass",
                "category": "harmless",
                "name": "anything"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("super-secret"),
        "decoy rejection must not leak the secret"
    );
    assert_eq!(
        approval_count(&app).await,
        approvals_before,
        "a rejected decoy must not create approvals"
    );

    // A body with only the decoy pair (no real reference) is rejected too.
    let (status, _) = app
        .request_auth(
            "POST",
            "/resolve/proxy",
            Some(json!({
                "url": "https://api.example.com/",
                "category": "harmless",
                "name": "anything"
            })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// An unauthenticated resolve request gets 401 and never reaches policy: no
/// approval is created even though a matching approval-required policy exists.
#[tokio::test]
async fn test_unauthenticated_resolve_is_401_before_policy() {
    let app = TestApp::new().await;
    let _agent_key = setup_mode_fixture(&app, "order-agent", json!(["proxy"]), true).await;
    let before = approval_count(&app).await;

    let body = json!({
        "url": "https://api.example.com/",
        "secret_category": "prod",
        "secret_name": "db-pass"
    });
    for token in [None, Some("not-a-real-token")] {
        let status = status_for(&app, "/resolve/proxy", token, body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "token {token:?}");
    }
    // A body that would be a policy denial for an authenticated agent is still
    // a plain 401 for an anonymous caller.
    let exec_body = json!({
        "category": "prod",
        "name": "db-pass",
        "argv": ["/bin/x"],
        "env_var": "S"
    });
    let status = status_for(&app, "/resolve/exec", None, exec_body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(approval_count(&app).await, before);
}
