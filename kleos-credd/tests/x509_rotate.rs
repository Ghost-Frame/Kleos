//! `POST /custody/x509/rotate-leaf` and `POST /resolve/public`.
//!
//! Each test builds an in-memory custody credd, stores a throwaway CA and leaf
//! (generated at test time by the production issuance code), and drives the
//! HTTP routes as the master over the Unix-socket marker. Stored state is read
//! back straight from the database, since no custody route returns it.

/// Shared canary and throwaway-PKI fixtures.
mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use serde_json::{json, Value};
use tower::ServiceExt;
use x509_cert::der::Encode;

use kleos_cred::crypto::derive_key;
use kleos_cred::storage::get_secret_with_policy;
use kleos_cred::types::{ProxyPolicy, SecretData, X509Material};
use kleos_credd::auth::IsUnixSocket;
use kleos_credd::build_router;
use kleos_credd::profile::RunProfile;
use kleos_credd::state::AppState;
use kleos_credd::x509::{
    key_matches_certificate, not_after_unix, parse_certificate, parse_signing_key,
};
use kleos_lib::db::Database;

use common::x509_fixtures::{legacy_note_content, new_ca, new_client, Identity};
use common::Canary;

/// Seconds in one day.
const DAY_SECS: u64 = 24 * 60 * 60;

/// Category every fixture secret lives in.
const CAT: &str = "pki";

/// One response reduced to status and bytes.
struct Reply {
    /// Response status.
    status: StatusCode,
    /// Raw response body.
    body: Vec<u8>,
}

/// Reply helpers.
impl Reply {
    /// Parse the body as JSON (`Null` if it is not JSON).
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The body as lossy text, for assertion messages.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A custody credd plus the master bearer and a handle on its state.
struct App {
    /// Router under test.
    router: Router,
    /// Hex master bearer.
    master: String,
    /// Shared state, kept to read stored secrets back from the database.
    state: AppState,
    /// Scratch directory for agent key files.
    dir: tempfile::TempDir,
}

/// App construction and request helpers.
impl App {
    /// Build an in-memory credd for `profile`.
    async fn new(profile: RunProfile) -> Self {
        let db = Database::connect_memory().await.expect("in-memory db");
        let key = derive_key(1, b"test-master-password", None);
        let master = hex::encode(*key);
        let state = AppState::new(db, *key).with_run_profile(profile);
        Self {
            router: build_router(state.clone()),
            master,
            state,
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// Custody app.
    async fn custody() -> Self {
        Self::new(RunProfile::Custody).await
    }

    /// Send one request with `token` over the Unix-socket marker.
    async fn send_as(&self, token: &str, method: &str, path: &str, body: Option<Value>) -> Reply {
        let mut builder = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(path)
            .header("authorization", format!("Bearer {token}"));
        let body = match body {
            Some(json) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&json).expect("json"))
            }
            None => Body::empty(),
        };
        let mut req = builder.body(body).expect("request");
        req.extensions_mut().insert(IsUnixSocket(true));
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

    /// Send one request as the master.
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let master = self.master.clone();
        self.send_as(&master, method, path, body).await
    }

    /// Store `data` as `CAT/name` with an optional proxy policy.
    async fn store_data(&self, name: &str, data: Value, policy: Option<Value>) {
        let mut body = json!({ "data": data });
        if let Some(policy) = policy {
            body["proxy_policy"] = policy;
        }
        let reply = self
            .send("POST", &format!("/secret/{CAT}/{name}"), Some(body))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "store {name}: {}",
            reply.text()
        );
    }

    /// Store `data` as `category/name` with the default policy.
    async fn store_data_in(&self, category: &str, name: &str, data: Value) {
        let reply = self
            .send(
                "POST",
                &format!("/secret/{category}/{name}"),
                Some(json!({ "data": data })),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "store {name}: {}",
            reply.text()
        );
    }

    /// Store `identity` as a typed x509 bundle named `name`.
    async fn store_bundle(&self, name: &str, identity: &Identity, policy: Option<Value>) {
        self.store_data(
            name,
            json!({
                "type": "x509_bundle",
                "certificate_pem": identity.cert_pem,
                "private_key_pem": identity.key_pem,
            }),
            policy,
        )
        .await;
    }

    /// Store `identity` as a legacy base64-JSON note bundle named `name`.
    async fn store_legacy(&self, name: &str, identity: &Identity, schema_version: u64) {
        self.store_data(
            name,
            json!({
                "type": "note",
                "content": legacy_note_content(&identity.cert_pem, &identity.key_pem, schema_version),
            }),
            None,
        )
        .await;
    }

    /// POST `/custody/x509/rotate-leaf` for `CAT/ca` and `CAT/leaf` plus extras.
    async fn rotate(&self, ca: &str, leaf: &str, extra: Value) -> Reply {
        let mut body = json!({
            "ca": {"category": CAT, "name": ca},
            "leaf": {"category": CAT, "name": leaf},
        });
        if let Value::Object(map) = extra {
            for (k, v) in map {
                body[k] = v;
            }
        }
        self.send("POST", "/custody/x509/rotate-leaf", Some(body))
            .await
    }

    /// Read a stored secret straight from the database.
    async fn stored(&self, name: &str) -> (SecretData, ProxyPolicy) {
        let (_row, data, policy) =
            get_secret_with_policy(&self.state.db, 1, CAT, name, self.state.master_key.as_ref())
                .await
                .expect("stored secret");
        (data, policy)
    }

    /// The bundle parts of a stored secret.
    async fn stored_bundle(&self, name: &str) -> X509Material {
        let (data, _policy) = self.stored(name).await;
        data.as_x509_bundle()
            .expect("bundle decode")
            .expect("stored secret is a bundle")
    }

    /// Number of secrets listed.
    async fn count(&self) -> usize {
        let listed = self.send("GET", "/secrets", None).await;
        listed.json()["secrets"].as_array().map_or(0, Vec::len)
    }

    /// Create a custody agent limited to `categories`; returns its key.
    async fn agent(&self, name: &str, categories: &[&str]) -> String {
        let path = self.dir.path().join(format!("{name}.key"));
        let reply = self
            .send(
                "POST",
                "/agents",
                Some(json!({
                    "name": name,
                    "categories": categories,
                    "key_path": path.to_str().expect("utf8"),
                })),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "agent: {}", reply.text());
        std::fs::read_to_string(&path)
            .expect("key file")
            .trim()
            .to_string()
    }
}

/// Policy JSON with one allowed origin, so preservation is observable.
fn origin_policy() -> Value {
    json!({"allowed_origins": [{"scheme": "https", "host": "mtls.example.com", "port": 8443}]})
}

/// Seconds since the Unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A leaf that is still fresh is left alone when `rotate_within_days` says so:
/// nothing is written and no rollback row appears.
#[tokio::test]
async fn fresh_leaf_is_left_alone_outside_the_window() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &leaf, Some(origin_policy())).await;

    let reply = app
        .rotate("ca", "leaf", json!({"rotate_within_days": 30}))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let json = reply.json();
    assert_eq!(json["rotated"], false);
    assert_eq!(json["serial_hex"], leaf.serial_hex());
    assert_eq!(json["certificate_pem"], leaf.cert_pem);
    assert!(json["rollback_name"].is_null());
    assert!(!reply.text().contains("PRIVATE KEY"));

    assert_eq!(app.count().await, 2, "no rollback row may be written");
    let stored = app.stored_bundle("leaf").await;
    assert_eq!(stored.private_key_pem, leaf.key_pem);
    assert_eq!(stored.certificate_pem, leaf.cert_pem);
}

/// The full rotation: new certificate under the CA, old material kept under
/// the rollback name, policy preserved, and no private key on the wire.
#[tokio::test]
async fn rotation_replaces_the_leaf_and_keeps_a_rollback() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &leaf, Some(origin_policy())).await;
    let (_, policy_before) = app.stored("leaf").await;
    assert!(!policy_before.is_default());

    // Inside the window (a 90-day leaf, 100-day window): rotates.
    let reply = app
        .rotate("ca", "leaf", json!({"rotate_within_days": 100}))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    // No key material in the response, in any encoding.
    assert!(!reply.text().contains("PRIVATE KEY"));
    let new_stored = app.stored_bundle("leaf").await;
    for secret in [&ca.key_pem, &leaf.key_pem, &new_stored.private_key_pem] {
        if let Some(found) = Canary::new(secret).find_leak(&reply.body) {
            panic!("rotation response leaked a private key ({found})");
        }
    }

    let json = reply.json();
    assert_eq!(json["rotated"], true);
    let new_pem = json["certificate_pem"].as_str().expect("certificate_pem");
    let new_cert = parse_certificate(new_pem).expect("response certificate parses");

    // Same subject, issuer is the CA, signature verifies under the CA key.
    assert_eq!(
        new_cert.tbs_certificate.subject.to_string(),
        leaf.subject(),
        "subject CN is carried over"
    );
    assert_eq!(
        new_cert.tbs_certificate.issuer,
        ca.cert.tbs_certificate.subject
    );
    let tbs = new_cert.tbs_certificate.to_der().expect("tbs der");
    let signature = Signature::from_der(new_cert.signature.as_bytes().expect("signature bits"))
        .expect("ecdsa signature");
    ca.key
        .verifying_key()
        .verify(&tbs, &signature)
        .expect("signature verifies under the CA key");

    // New serial and the default 90-day lifetime.
    assert_ne!(json["serial_hex"], leaf.serial_hex());
    let remaining = not_after_unix(&new_cert) - now_secs();
    assert!(
        remaining.abs_diff(90 * DAY_SECS) < 120,
        "default lifetime is 90 days, got {remaining}s"
    );
    assert!(json["not_after"]
        .as_str()
        .expect("not_after")
        .ends_with('Z'));

    // Rollback: old certificate and key, under the specified name, no origins.
    let rollback_name = format!("leaf-rollback-{}", leaf.serial_hex());
    assert_eq!(json["rollback_name"], rollback_name);
    let (rollback_data, rollback_policy) = app.stored(&rollback_name).await;
    assert_eq!(
        rollback_data.secret_type(),
        kleos_cred::types::SecretType::X509Bundle
    );
    let rollback = rollback_data
        .as_x509_bundle()
        .expect("decode")
        .expect("rollback is a bundle");
    assert_eq!(rollback.certificate_pem, leaf.cert_pem);
    assert_eq!(rollback.private_key_pem, leaf.key_pem);
    assert!(
        rollback_policy.is_default(),
        "the retired key must not be proxyable until an operator opts in"
    );

    // The leaf now holds the new certificate and a different key that matches
    // it, with its proxy policy untouched.
    let (leaf_data, policy_after) = app.stored("leaf").await;
    assert_eq!(
        leaf_data.secret_type(),
        kleos_cred::types::SecretType::X509Bundle
    );
    assert_eq!(new_stored.certificate_pem, new_pem);
    assert_ne!(new_stored.private_key_pem, leaf.key_pem);
    let new_key = parse_signing_key(&new_stored.private_key_pem).expect("new key parses");
    assert!(key_matches_certificate(&new_cert, &new_key));
    assert_eq!(policy_after, policy_before);

    // The CA is untouched.
    let ca_stored = app.stored_bundle("ca").await;
    assert_eq!(ca_stored.private_key_pem, ca.key_pem);
    assert_eq!(app.count().await, 3);

    // A second rotation names its rollback after the now-current serial, so it
    // cannot collide with the first.
    let second = app.rotate("ca", "leaf", json!({"lifetime_days": 10})).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text());
    let second_json = second.json();
    assert_eq!(
        second_json["rollback_name"],
        format!(
            "leaf-rollback-{}",
            json["serial_hex"].as_str().expect("serial")
        )
    );
    let second_cert = parse_certificate(second_json["certificate_pem"].as_str().expect("pem"))
        .expect("second certificate parses");
    let remaining = not_after_unix(&second_cert) - now_secs();
    assert!(remaining.abs_diff(10 * DAY_SECS) < 120, "{remaining}");
    assert_eq!(app.count().await, 4);
}

/// A pre-existing secret under the rollback name blocks the rotation before
/// the leaf is touched, and is itself left alone.
#[tokio::test]
async fn rollback_name_collision_is_400_and_leaf_unchanged() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &leaf, Some(origin_policy())).await;
    let squatter = format!("leaf-rollback-{}", leaf.serial_hex());
    app.store_data(
        &squatter,
        json!({"type": "note", "content": "squatting on the rollback name"}),
        None,
    )
    .await;

    let reply = app.rotate("ca", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    assert!(reply.text().contains("rollback name already exists"));

    let stored = app.stored_bundle("leaf").await;
    assert_eq!(
        stored.private_key_pem, leaf.key_pem,
        "leaf must be unchanged"
    );
    assert_eq!(stored.certificate_pem, leaf.cert_pem);
    let (squat, _) = app.stored(&squatter).await;
    assert!(matches!(squat, SecretData::Note { ref content } if content.starts_with("squatting")));
    assert_eq!(app.count().await, 3);
}

/// Both references must be bundles.
#[tokio::test]
async fn non_bundle_secrets_are_400() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_data(
        "plain-note",
        json!({"type": "note", "content": "not a bundle"}),
        None,
    )
    .await;
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &leaf, None).await;

    let reply = app.rotate("plain-note", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    let reply = app.rotate("ca", "plain-note", json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    let reply = app.rotate("ca", "ca", json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    let reply = app.rotate("ca", "missing", json!({})).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.text());
    assert_eq!(app.count().await, 3);
}

/// A leaf issued by some other CA is refused, and not modified.
#[tokio::test]
async fn leaf_from_another_ca_is_403() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let other = new_ca("Other CA");
    let foreign = new_client(&other, "svc-client", 90);
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &foreign, None).await;

    let reply = app.rotate("ca", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
    assert!(reply.text().contains("leaf is not issued by the given CA"));
    let stored = app.stored_bundle("leaf").await;
    assert_eq!(stored.private_key_pem, foreign.key_pem);
    assert_eq!(app.count().await, 2);

    // Same issuer name but a different key: the signature check catches it.
    let impostor = new_ca("Test CA");
    let forged = new_client(&impostor, "svc-client", 90);
    app.store_bundle("leaf", &forged, None).await;
    let reply = app.rotate("ca", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
}

/// A CA whose private key is not the one its certificate certifies is refused.
#[tokio::test]
async fn ca_key_must_match_ca_certificate() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let stray = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_data(
        "ca",
        json!({
            "type": "x509_bundle",
            "certificate_pem": ca.cert_pem,
            "private_key_pem": stray.key_pem,
        }),
        None,
    )
    .await;
    app.store_bundle("leaf", &leaf, None).await;
    let reply = app.rotate("ca", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    assert!(!reply.text().contains("PRIVATE KEY"));
}

/// `lifetime_days` must be 1..=398.
#[tokio::test]
async fn lifetime_days_is_bounded() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &leaf, None).await;

    for bad in [0u64, 399, 100_000] {
        let reply = app
            .rotate("ca", "leaf", json!({"lifetime_days": bad}))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{bad}: {}",
            reply.text()
        );
    }
    assert_eq!(app.count().await, 2, "rejected lifetimes write nothing");
    let stored = app.stored_bundle("leaf").await;
    assert_eq!(stored.private_key_pem, leaf.key_pem);

    let reply = app
        .rotate("ca", "leaf", json!({"lifetime_days": 398}))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let cert = parse_certificate(reply.json()["certificate_pem"].as_str().expect("pem"))
        .expect("certificate parses");
    assert!(not_after_unix(&cert).abs_diff(now_secs() + 398 * DAY_SECS) < 120);
}

/// Legacy base64-JSON note bundles work as CA and as leaf; the result is a
/// typed bundle, and the rollback keeps the old legacy material. Any other
/// schema version is refused.
#[tokio::test]
async fn legacy_note_bundles_are_accepted() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_legacy("ca", &ca, 1).await;
    app.store_legacy("leaf", &leaf, 1).await;

    let reply = app.rotate("ca", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let json = reply.json();
    assert_eq!(json["rotated"], true);
    let (data, _) = app.stored("leaf").await;
    assert_eq!(
        data.secret_type(),
        kleos_cred::types::SecretType::X509Bundle
    );
    let rollback = app
        .stored_bundle(json["rollback_name"].as_str().expect("rollback"))
        .await;
    assert_eq!(rollback.certificate_pem, leaf.cert_pem);
    assert_eq!(rollback.private_key_pem, leaf.key_pem);
    let fresh = parse_certificate(json["certificate_pem"].as_str().expect("pem")).expect("cert");
    assert!(kleos_credd::x509::verify_issued_by(&fresh, &ca.cert));
    for secret in [&ca.key_pem, &leaf.key_pem] {
        assert!(Canary::new(secret).find_leak(&reply.body).is_none());
    }

    // schema_version 2 is not a bundle this daemon understands.
    let v2 = App::custody().await;
    v2.store_legacy("ca", &ca, 2).await;
    v2.store_legacy("leaf", &leaf, 1).await;
    let reply = v2.rotate("ca", "leaf", json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    assert!(reply.text().contains("schema_version"));
}

/// `/resolve/public` returns the public half of bundles and SSH keys only.
#[tokio::test]
async fn public_returns_only_public_halves() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_data(
        "with-chain",
        json!({
            "type": "x509_bundle",
            "certificate_pem": leaf.cert_pem,
            "private_key_pem": leaf.key_pem,
            "chain_pem": ca.cert_pem,
        }),
        None,
    )
    .await;
    app.store_legacy("legacy", &leaf, 1).await;
    app.store_data(
        "ssh",
        json!({
            "type": "ssh_key",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n",
            "public_key": "ssh-ed25519 AAAAPUBLICPART comment",
        }),
        None,
    )
    .await;
    app.store_data(
        "ssh-bare",
        json!({"type": "ssh_key", "private_key": "FAKEPRIVATE"}),
        None,
    )
    .await;
    app.store_data(
        "api",
        json!({"type": "api_key", "key": "sk-not-public-at-all"}),
        None,
    )
    .await;

    let public = |name: &str| json!({"category": CAT, "name": name});

    let reply = app
        .send("POST", "/resolve/public", Some(public("with-chain")))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let json = reply.json();
    assert_eq!(json["secret_type"], "x509_bundle");
    assert_eq!(json["certificate_pem"], leaf.cert_pem);
    assert_eq!(json["chain_pem"], ca.cert_pem);
    assert!(json["public_key"].is_null());
    assert!(Canary::new(&leaf.key_pem).find_leak(&reply.body).is_none());
    assert!(!reply.text().contains("PRIVATE KEY"));

    let reply = app
        .send("POST", "/resolve/public", Some(public("legacy")))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["certificate_pem"], leaf.cert_pem);
    assert!(reply.json()["chain_pem"].is_null());
    assert!(!reply.text().contains("PRIVATE KEY"));

    let reply = app
        .send("POST", "/resolve/public", Some(public("ssh")))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["secret_type"], "ssh_key");
    assert_eq!(
        reply.json()["public_key"],
        "ssh-ed25519 AAAAPUBLICPART comment"
    );
    assert!(!reply.text().contains("FAKEPRIVATE"));

    for name in ["ssh-bare", "api"] {
        let reply = app
            .send("POST", "/resolve/public", Some(public(name)))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            reply.text()
        );
        assert!(!reply.text().contains("sk-not-public"));
        assert!(!reply.text().contains("FAKEPRIVATE"));
    }
    let reply = app
        .send("POST", "/resolve/public", Some(public("absent")))
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

/// Agents are held to their category list on both refs of a rotation and on
/// the public lookup; denied attempts change nothing.
#[tokio::test]
async fn agent_category_access_is_enforced() {
    let app = App::custody().await;
    let ca = new_ca("Test CA");
    let leaf = new_client(&ca, "svc-client", 90);
    app.store_bundle("ca", &ca, None).await;
    app.store_bundle("leaf", &leaf, None).await;
    let outsider = app.agent("outsider", &["elsewhere"]).await;

    let body = json!({
        "ca": {"category": CAT, "name": "ca"},
        "leaf": {"category": CAT, "name": "leaf"},
    });
    let reply = app
        .send_as(&outsider, "POST", "/custody/x509/rotate-leaf", Some(body))
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
    let reply = app
        .send_as(
            &outsider,
            "POST",
            "/resolve/public",
            Some(json!({"category": CAT, "name": "leaf"})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());

    // Access to the leaf's category alone is not enough: the CA ref is checked.
    let partial = app.agent("partial", &[CAT]).await;
    app.store_data_in(
        "vault",
        "ca2",
        json!({
            "type": "x509_bundle",
            "certificate_pem": ca.cert_pem,
            "private_key_pem": ca.key_pem,
        }),
    )
    .await;
    let reply = app
        .send_as(
            &partial,
            "POST",
            "/custody/x509/rotate-leaf",
            Some(json!({
                "ca": {"category": "vault", "name": "ca2"},
                "leaf": {"category": CAT, "name": "leaf"},
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());

    // With both categories granted the same agent can rotate.
    let both = app.agent("both", &[CAT, "vault"]).await;
    let reply = app
        .send_as(
            &both,
            "POST",
            "/custody/x509/rotate-leaf",
            Some(json!({
                "ca": {"category": "vault", "name": "ca2"},
                "leaf": {"category": CAT, "name": "leaf"},
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(!reply.text().contains("PRIVATE KEY"));
}

/// Unknown request fields are rejected, and the legacy profile does not mount
/// the custody-only rotation route (but does mount the public lookup).
#[tokio::test]
async fn request_shape_and_profile_gating() {
    let app = App::custody().await;
    let reply = app
        .send(
            "POST",
            "/custody/x509/rotate-leaf",
            Some(json!({
                "ca": {"category": CAT, "name": "ca"},
                "leaf": {"category": CAT, "name": "leaf"},
                "key_path": "/tmp/nope",
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    let reply = app
        .send(
            "POST",
            "/resolve/public",
            Some(json!({"category": CAT, "name": "x", "field": "private_key"})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);

    let legacy = App::new(RunProfile::Legacy).await;
    let reply = legacy
        .send(
            "POST",
            "/custody/x509/rotate-leaf",
            Some(json!({
                "ca": {"category": CAT, "name": "ca"},
                "leaf": {"category": CAT, "name": "leaf"},
            })),
        )
        .await;
    assert!(
        matches!(
            reply.status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ),
        "legacy answered {}",
        reply.status
    );
    let reply = legacy
        .send(
            "POST",
            "/resolve/public",
            Some(json!({"category": CAT, "name": "absent"})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}
