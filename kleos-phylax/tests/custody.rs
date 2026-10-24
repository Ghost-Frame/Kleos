//! Custody-profile tests for the composed credd + Phylax router.
//!
//! Covers route enumeration (excluded routes are not mounted), the adversarial
//! canary (no mounted route returns the secret in any encoding), and that the
//! same detector does flag the legacy plaintext routes (positive control).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kleos_cred::crypto::derive_key;
use kleos_cred::CredError;
use kleos_credd::auth::IsUnixSocket;
use kleos_credd::profile::RunProfile;
use kleos_credd::state::AppState;
use kleos_lib::db::Database;
use kleos_phylax::router::{compose_router_with_phylax_state, mounted_paths};
use kleos_phylax::ssh_ca_signer::{MintedSshCertificate, SignedSshCertificate, SshCaSigner};
use kleos_phylax::state::PhylaxState;

use common::{Canary, CANARY_SECRET};

/// Routes that return secret material and must not exist under custody.
const EXCLUDED_UNDER_CUSTODY: &[&str] = &[
    "GET /secret/{category}/{*name}",
    "POST /resolve/text",
    "POST /resolve/raw",
    "POST /resolve/derive",
    "GET /bootstrap/kleos-bearer",
];

/// Routes that must survive under custody.
const RETAINED_UNDER_CUSTODY: &[&str] = &[
    "GET /health",
    "GET /secrets",
    "POST /secret/{category}/{*name}",
    "POST /resolve/proxy",
    "POST /resolve/public",
    "POST /custody/x509/rotate-leaf",
    "POST /resolve/sign",
    "POST /resolve/verify",
    "POST /resolve/exec",
    "POST /agents",
    "POST /bootstrap/kleos-bearer",
    "POST /phylax/kleos/token",
];

/// Routes that exist only under custody (they have no legacy counterpart).
const CUSTODY_ONLY: &[&str] = &["POST /custody/x509/rotate-leaf"];

/// SSH CA signer that refuses everything, so no test ever shells out.
struct DenySigner;

/// Always-deny signer implementation.
impl SshCaSigner for DenySigner {
    /// Refuse to sign.
    fn sign(
        &self,
        _identity: &str,
        _principal: &str,
        _ttl: &str,
        _public_key: &str,
    ) -> Result<SignedSshCertificate, CredError> {
        Err(CredError::PermissionDenied("test signer denies".into()))
    }

    /// Refuse to mint.
    fn mint(
        &self,
        _agent: &str,
        _principal: &str,
        _ttl: &str,
    ) -> Result<MintedSshCertificate, CredError> {
        Err(CredError::PermissionDenied("test signer denies".into()))
    }
}

/// Which listener a simulated request came from.
#[derive(Clone, Copy, Debug)]
enum Origin {
    /// Unix socket marker (`IsUnixSocket(true)`).
    Unix,
    /// Explicit TCP marker (`IsUnixSocket(false)`).
    Tcp,
}

/// One HTTP response reduced to what the tests inspect.
struct Reply {
    /// Response status.
    status: StatusCode,
    /// Full body bytes.
    body: Vec<u8>,
}

/// Composed router plus the credentials needed to drive it.
struct App {
    /// Router under test.
    router: Router,
    /// Hex master bearer.
    master_token: String,
    /// Directory holding agent key files written by custody agent creation.
    key_dir: tempfile::TempDir,
}

/// Request helpers and fixture provisioning.
impl App {
    /// Build an in-memory app for `profile`.
    async fn new(profile: RunProfile) -> Self {
        let db = Database::connect_memory().await.expect("in-memory db");
        let master_key = derive_key(1, b"test-master-password", None);
        let master_token = hex::encode(*master_key);
        let state = AppState::new(db, *master_key).with_run_profile(profile);
        let phylax_state =
            PhylaxState::from_app_state(state).with_ssh_ca_signer(Arc::new(DenySigner));
        Self {
            router: compose_router_with_phylax_state(phylax_state),
            master_token,
            key_dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// Send one request carrying an origin marker and optional bearer.
    async fn send(
        &self,
        origin: Origin,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body = match body {
            Some(json) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&json).expect("json"))
            }
            None => Body::empty(),
        };
        let mut req = builder.body(body).expect("request");
        let marker = match origin {
            Origin::Unix => IsUnixSocket(true),
            Origin::Tcp => IsUnixSocket(false),
        };
        req.extensions_mut().insert(marker);

        let res = self.router.clone().oneshot(req).await.expect("response");
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        Reply { status, body }
    }

    /// Store the fixture secret and a permissive policy as the master.
    async fn provision_secret_and_policy(&self) {
        let master = self.master_token.clone();
        let stored = self
            .send(
                Origin::Unix,
                "POST",
                "/secret/prod/db-pass",
                Some(&master),
                Some(json!({"data": {"type": "note", "content": CANARY_SECRET}})),
            )
            .await;
        assert_eq!(stored.status, StatusCode::OK, "store secret");

        let policy = self
            .send(
                Origin::Unix,
                "POST",
                "/phylax/policies",
                Some(&master),
                Some(json!({
                    "namespace": "default",
                    "category": "prod",
                    "require_approval": false,
                    "allowed_modes": ["text", "proxy", "raw", "exec", "verify", "sign", "derive"],
                    "exec_allowlist": ["/usr/bin/env"]
                })),
            )
            .await;
        assert_eq!(policy.status, StatusCode::OK, "create policy");
    }

    /// Create a custody agent over the Unix socket and return its key, read
    /// back from the 0600 key file (the HTTP response never carries it).
    async fn provision_custody_agent(&self) -> String {
        let key_path = self.key_dir.path().join("canary-agent.key");
        let master = self.master_token.clone();
        let created = self
            .send(
                Origin::Unix,
                "POST",
                "/agents",
                Some(&master),
                Some(json!({
                    "name": "canary-agent",
                    "categories": ["prod"],
                    "key_path": key_path.to_str().expect("utf8 path"),
                })),
            )
            .await;
        assert_eq!(created.status, StatusCode::OK, "create custody agent");
        std::fs::read_to_string(&key_path)
            .expect("key file")
            .trim()
            .to_string()
    }
}

/// Fill axum path placeholders with fixture values.
fn fill_placeholders(path: &str) -> String {
    path.replace("{category}", "prod")
        .replace("{*name}", "db-pass")
        .replace("{name}", "db-pass")
        .replace("{id}", "1")
        .replace("{jti}", "canary-jti")
}

/// Generic JSON body carrying every field any route might want.
fn union_body() -> Value {
    json!({
        "category": "prod",
        "name": "db-pass",
        "text": "{{secret:prod/db-pass}}",
        "payload_b64": "eA==",
        "signature_b64": "eQ==",
        "algo": "hmac-sha256",
        "purpose": "canary",
        "length": 32,
        "argv": ["/usr/bin/env"],
        "env_var": "S",
        "url": "http://127.0.0.1:9/",
        "secret_category": "prod",
        "secret_name": "db-pass",
        "data": {"type": "note", "content": "x"},
        // The SSH CA fields are deliberately invalid: a well-formed agent
        // request would open an approval and poll for a human for up to two
        // minutes. Invalid input is rejected before any approval is created.
        "agent": "bad agent name!",
        "principal": "bad principal!",
        "ttl": "not-a-ttl",
        "public_key": "not a public key",
        "identity": "bad identity!",
        "namespace": "default",
        "require_approval": false,
        "allowed_modes": ["sign"],
        "key_path": "/nonexistent-dir/x.key",
        "categories": ["prod"]
    })
}

/// Routes whose handler is exempt from bearer auth in `auth_middleware`.
fn is_auth_exempt(method: &str, path: &str) -> bool {
    path == "/health"
        || (method == "POST" && path == "/bootstrap/kleos-bearer")
        || (method == "POST" && path == "/phylax/kleos/token")
        || (method == "POST"
            && path.starts_with("/phylax/approvals/")
            && path.ends_with("/decide-token"))
}

/// Custody mounts none of the excluded routes; legacy still mounts them.
#[test]
fn route_enumeration_matches_profile() {
    let custody = mounted_paths(RunProfile::Custody);
    let legacy = mounted_paths(RunProfile::Legacy);

    for route in EXCLUDED_UNDER_CUSTODY {
        assert!(
            !custody.iter().any(|r| r == route),
            "{route} must not be mounted under custody"
        );
        assert!(
            legacy.iter().any(|r| r == route),
            "{route} must still be mounted under legacy"
        );
    }
    for route in RETAINED_UNDER_CUSTODY {
        assert!(
            custody.iter().any(|r| r == route),
            "{route} must stay mounted under custody"
        );
    }
    // Custody only ever removes routes relative to legacy (POST /agents is
    // present in both, served by a different handler), apart from the listed
    // custody-only routes, which legacy must not mount.
    for route in &custody {
        if CUSTODY_ONLY.contains(&route.as_str()) {
            assert!(
                !legacy.contains(route),
                "{route} must not be mounted under legacy"
            );
        } else {
            assert!(legacy.contains(route), "{route} is custody-only");
        }
    }
    for route in CUSTODY_ONLY {
        assert!(
            custody.iter().any(|r| r == route),
            "{route} must be mounted under custody"
        );
    }
}

/// The live router agrees with the enumeration: excluded routes answer 404 or
/// 405 under custody even for the master over the Unix socket, and are live
/// under legacy.
#[tokio::test]
async fn excluded_routes_are_absent_from_the_live_custody_router() {
    let custody = App::new(RunProfile::Custody).await;
    let legacy = App::new(RunProfile::Legacy).await;
    legacy.provision_secret_and_policy().await;

    let probes: &[(&str, &str, Option<Value>)] = &[
        ("GET", "/secret/prod/db-pass", None),
        (
            "POST",
            "/resolve/text",
            Some(json!({"text": "{{secret:prod/db-pass}}"})),
        ),
        (
            "POST",
            "/resolve/raw",
            Some(json!({"category": "prod", "name": "db-pass"})),
        ),
        (
            "POST",
            "/resolve/derive",
            Some(json!({"category": "prod", "name": "db-pass", "purpose": "p", "length": 16})),
        ),
        ("GET", "/bootstrap/kleos-bearer?agent=x", None),
    ];

    for (method, path, body) in probes {
        let master = custody.master_token.clone();
        let reply = custody
            .send(Origin::Unix, method, path, Some(&master), body.clone())
            .await;
        assert!(
            matches!(
                reply.status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "custody {method} {path} answered {}",
            reply.status
        );
    }

    // Legacy: the same plaintext routes work for the master.
    let master = legacy.master_token.clone();
    let got = legacy
        .send(
            Origin::Tcp,
            "GET",
            "/secret/prod/db-pass",
            Some(&master),
            None,
        )
        .await;
    assert_eq!(got.status, StatusCode::OK);
    let text = legacy
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/text",
            Some(&master),
            Some(json!({"text": "{{secret:prod/db-pass}}"})),
        )
        .await;
    assert_eq!(text.status, StatusCode::OK);
    let raw = legacy
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/raw",
            Some(&master),
            Some(json!({"category": "prod", "name": "db-pass"})),
        )
        .await;
    assert_eq!(raw.status, StatusCode::OK);
}

/// Positive control: the detector flags the legacy plaintext routes, so a clean
/// custody run is meaningful.
#[tokio::test]
async fn detector_flags_legacy_plaintext_routes() {
    let canary = Canary::new(CANARY_SECRET);
    let legacy = App::new(RunProfile::Legacy).await;
    legacy.provision_secret_and_policy().await;
    let master = legacy.master_token.clone();

    let got = legacy
        .send(
            Origin::Tcp,
            "GET",
            "/secret/prod/db-pass",
            Some(&master),
            None,
        )
        .await;
    assert!(
        canary.find_leak(&got.body).is_some(),
        "GET /secret not flagged"
    );

    let raw = legacy
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/raw",
            Some(&master),
            Some(json!({"category": "prod", "name": "db-pass"})),
        )
        .await;
    assert!(
        canary.find_leak(&raw.body).is_some(),
        "/resolve/raw not flagged"
    );
}

/// Adversarial canary: with an agent key (over both listeners) and with the
/// master bearer over TCP, no mounted custody route returns the secret in any
/// supported encoding.
#[tokio::test]
async fn custody_canary_no_mounted_route_leaks_the_secret() {
    let canary = Canary::new(CANARY_SECRET);
    let app = App::new(RunProfile::Custody).await;
    app.provision_secret_and_policy().await;
    let agent_key = app.provision_custody_agent().await;
    let master = app.master_token.clone();

    let routes = mounted_paths(RunProfile::Custody);
    assert!(
        routes.len() >= 30,
        "suspiciously few routes: {}",
        routes.len()
    );

    let mut ok_responses = 0usize;
    let mut requests = 0usize;

    for route in &routes {
        let (method, template) = route.split_once(' ').expect("METHOD path");
        let path = fill_placeholders(template);
        let body = matches!(method, "POST" | "PUT").then(union_body);

        let variants: [(&str, Origin, &str); 3] = [
            ("agent/tcp", Origin::Tcp, agent_key.as_str()),
            ("agent/unix", Origin::Unix, agent_key.as_str()),
            ("master/tcp", Origin::Tcp, master.as_str()),
        ];
        for (label, origin, token) in variants {
            let reply = app
                .send(origin, method, &path, Some(token), body.clone())
                .await;
            requests += 1;
            if reply.status.is_success() {
                ok_responses += 1;
            }
            if let Some(found) = canary.find_leak(&reply.body) {
                panic!(
                    "{label} {method} {path} leaked the secret ({found}); status {}",
                    reply.status
                );
            }
            // The master bearer must be refused on TCP wherever auth applies.
            if label == "master/tcp" && !is_auth_exempt(method, &path) {
                assert_eq!(
                    reply.status,
                    StatusCode::FORBIDDEN,
                    "master over TCP must be 403 on {method} {path}"
                );
            }
        }
    }
    assert_eq!(requests, routes.len() * 3);
    assert!(
        ok_responses >= 3,
        "only {ok_responses} 2xx responses; the canary is not reaching handlers"
    );

    // Targeted, well-formed requests that actually run the non-plaintext modes.
    let sign = app
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/sign",
            Some(&agent_key),
            Some(json!({"category": "prod", "name": "db-pass",
                        "payload_b64": "eA==", "algo": "hmac-sha256"})),
        )
        .await;
    assert_eq!(sign.status, StatusCode::OK, "sign must run");
    assert!(canary.find_leak(&sign.body).is_none(), "sign leaked");

    let verify = app
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/verify",
            Some(&agent_key),
            Some(json!({"category": "prod", "name": "db-pass",
                        "payload_b64": "eA==", "signature_b64": "eQ==",
                        "algo": "hmac-sha256"})),
        )
        .await;
    assert_eq!(verify.status, StatusCode::OK, "verify must run");
    assert!(canary.find_leak(&verify.body).is_none(), "verify leaked");

    let exec = app
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/exec",
            Some(&agent_key),
            Some(json!({"category": "prod", "name": "db-pass",
                        "argv": ["/usr/bin/env"], "env_var": "S"})),
        )
        .await;
    assert_eq!(exec.status, StatusCode::OK, "exec must run");
    assert!(canary.find_leak(&exec.body).is_none(), "exec leaked");

    // The excluded routes answer without the secret too.
    for (method, path, body) in [
        ("GET", "/secret/prod/db-pass", None),
        (
            "POST",
            "/resolve/derive",
            Some(json!({"category": "prod", "name": "db-pass", "purpose": "p", "length": 16})),
        ),
        (
            "POST",
            "/resolve/text",
            Some(json!({"text": "{{secret:prod/db-pass}}"})),
        ),
        (
            "POST",
            "/resolve/raw",
            Some(json!({"category": "prod", "name": "db-pass"})),
        ),
    ] {
        let reply = app
            .send(Origin::Tcp, method, path, Some(&agent_key), body)
            .await;
        assert!(
            matches!(
                reply.status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {path} answered {}",
            reply.status
        );
        assert!(canary.find_leak(&reply.body).is_none(), "{path} leaked");
    }
}
