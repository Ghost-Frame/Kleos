//! Sealed-proxy tests: per-secret origin pinning, the auth-header allowlist,
//! response redaction in every encoding, and store-time policy validation.
//!
//! Each test starts a tiny axum upstream on 127.0.0.1 that echoes what it
//! received and hands the secret back in every encoding the canary knows, in
//! the body and in headers. The proxy under test must stop all of them.
//!
//! The x509 tests at the end start a TLS upstream that demands a client
//! certificate, to prove a bundle is presented as the connection's client
//! identity (never as a header) and that its key is redacted from responses.

mod common;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use p256::pkcs8::EncodePrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use x509_cert::der::{Decode, Encode};

use kleos_cred::crypto::derive_key;
use kleos_cred::types::unwrap_pem_body;
use kleos_credd::auth::IsUnixSocket;
use kleos_credd::build_router;
use kleos_credd::profile::RunProfile;
use kleos_credd::state::{AppState, ProxyDomainAllowlist};
use kleos_lib::db::Database;

use common::x509_fixtures::{legacy_note_content, new_ca, new_client, new_server, Identity};
use common::{Canary, CANARY_SECRET};

/// One request the upstream received.
#[derive(Debug, Clone)]
struct Seen {
    /// Lowercase header name and value pairs, in arrival order.
    headers: Vec<(String, String)>,
}

/// Seen-request helpers.
impl Seen {
    /// All values of header `name` (lowercase).
    fn all(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

/// Shared state of the echo upstream.
struct UpstreamState {
    /// Canary for the secret the upstream echoes back.
    canary: Canary,
    /// The secret itself.
    secret: String,
    /// Number of requests that reached a handler.
    hits: AtomicUsize,
    /// Every request seen.
    seen: Mutex<Vec<Seen>>,
}

/// A running echo upstream.
struct Upstream {
    /// Address it listens on.
    addr: SocketAddr,
    /// Shared state (hit counter and recorded requests).
    state: Arc<UpstreamState>,
}

/// Upstream accessors.
impl Upstream {
    /// Requests that reached the upstream.
    fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }

    /// The last recorded request.
    fn last(&self) -> Seen {
        self.state
            .seen
            .lock()
            .expect("seen lock")
            .last()
            .cloned()
            .expect("upstream saw a request")
    }

    /// The `{scheme, host, port}` origin JSON for this upstream.
    fn origin(&self) -> Value {
        json!({"scheme": "http", "host": "127.0.0.1", "port": self.addr.port()})
    }

    /// A URL on this upstream.
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }
}

/// Echo handler: records the request and returns the injected credential plus
/// the secret in every known encoding, in the body and in response headers.
async fn echo(State(st): State<Arc<UpstreamState>>, headers: HeaderMap, body: Bytes) -> Response {
    st.hits.fetch_add(1, Ordering::SeqCst);
    let pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    st.seen
        .lock()
        .expect("seen lock")
        .push(Seen { headers: pairs });

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut text = format!(
        "received-authorization={auth}\nreceived-body={}\n",
        String::from_utf8_lossy(&body)
    );
    for needle in &st.canary.needles {
        text.push_str(&format!(
            "{}={}\n",
            needle.label,
            String::from_utf8_lossy(&needle.bytes)
        ));
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("x-echo-auth", auth)
        .header("x-echo-b64", STANDARD.encode(&st.secret))
        .header("set-cookie", format!("sid={}", st.secret))
        .body(Body::from(text))
        .expect("echo response")
}

/// Handler that answers with a content-encoding the proxy cannot inspect.
async fn odd_encoding(State(st): State<Arc<UpstreamState>>) -> Response {
    st.hits.fetch_add(1, Ordering::SeqCst);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-encoding", "deflate")
        .body(Body::from("not really deflate"))
        .expect("encoding response")
}

/// Start an echo upstream for `secret` on an ephemeral loopback port.
async fn start_upstream(secret: &str) -> Upstream {
    let state = Arc::new(UpstreamState {
        canary: Canary::new(secret),
        secret: secret.to_string(),
        hits: AtomicUsize::new(0),
        seen: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route("/echo", any(echo))
        .route("/odd-encoding", any(odd_encoding))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Upstream { addr, state }
}

/// A loopback port nothing listens on (bound, then released).
async fn closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// One response reduced to status and bytes.
struct Reply {
    /// Response status.
    status: StatusCode,
    /// Response body bytes.
    body: Vec<u8>,
}

/// Reply helpers.
impl Reply {
    /// Parse the body as JSON (`Null` if it is not JSON).
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// credd router plus the master bearer.
struct App {
    /// Router under test.
    router: Router,
    /// Hex master bearer.
    master: String,
}

/// App construction and request helpers.
impl App {
    /// Build an in-memory credd. `loopback` enables the SSRF test seam;
    /// `allowlist` is the legacy per-category domain allowlist.
    async fn new(
        profile: RunProfile,
        loopback: bool,
        allowlist: Option<ProxyDomainAllowlist>,
    ) -> Self {
        Self::build(profile, loopback, allowlist, None).await
    }

    /// Like [`App::new`], additionally trusting `root_ca_pem` for outbound
    /// HTTPS (the extra-root test seam) when it is `Some`.
    async fn build(
        profile: RunProfile,
        loopback: bool,
        allowlist: Option<ProxyDomainAllowlist>,
        root_ca_pem: Option<Vec<u8>>,
    ) -> Self {
        let db = Database::connect_memory().await.expect("in-memory db");
        let key = derive_key(1, b"test-master-password", None);
        let master = hex::encode(*key);
        let mut state = AppState::new(db, *key).with_run_profile(profile);
        if loopback {
            state = state.with_loopback_proxy_for_tests();
        }
        if let Some(pem) = root_ca_pem {
            state = state.with_extra_root_ca_for_tests(pem);
        }
        // Never inherit an allowlist from the developer's home directory.
        state.proxy_domain_allowlist = allowlist.map(Arc::new);
        Self {
            router: build_router(state),
            master,
        }
    }

    /// Custody app with the loopback seam on.
    async fn custody() -> Self {
        Self::new(RunProfile::Custody, true, None).await
    }

    /// Custody app with the loopback seam on that also trusts `root_ca_pem`.
    async fn custody_trusting(root_ca_pem: &str) -> Self {
        Self::build(
            RunProfile::Custody,
            true,
            None,
            Some(root_ca_pem.as_bytes().to_vec()),
        )
        .await
    }

    /// Send one master request over the Unix-socket marker.
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let mut builder = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(path)
            .header("authorization", format!("Bearer {}", self.master));
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

    /// Store an API key `name` in category `svc`, with an optional policy.
    async fn store(&self, name: &str, value: &str, policy: Option<Value>) -> Reply {
        let mut body = json!({"data": {"type": "api_key", "key": value}});
        if let Some(policy) = policy {
            body["proxy_policy"] = policy;
        }
        self.send("POST", &format!("/secret/svc/{name}"), Some(body))
            .await
    }

    /// Store `data` (a `SecretData` JSON object) as `svc/name` with a policy.
    async fn store_data(&self, name: &str, data: Value, policy: Value) -> Reply {
        self.send(
            "POST",
            &format!("/secret/svc/{name}"),
            Some(json!({"data": data, "proxy_policy": policy})),
        )
        .await
    }

    /// Store `identity` as a typed x509 bundle `svc/name`.
    async fn store_bundle(&self, name: &str, identity: &Identity, policy: Value) -> Reply {
        self.store_data(
            name,
            json!({
                "type": "x509_bundle",
                "certificate_pem": identity.cert_pem,
                "private_key_pem": identity.key_pem,
            }),
            policy,
        )
        .await
    }

    /// POST /resolve/proxy for secret `svc/name` against `url`, merging `extra`
    /// fields (method, headers, auth_header, ...) into the body.
    async fn proxy(&self, name: &str, url: &str, extra: Value) -> Reply {
        let mut body = json!({
            "url": url,
            "secret_category": "svc",
            "secret_name": name,
        });
        if let Value::Object(map) = extra {
            for (k, v) in map {
                body[k] = v;
            }
        }
        self.send("POST", "/resolve/proxy", Some(body)).await
    }
}

/// Policy JSON allowing exactly `upstream`.
fn policy_for(upstream: &Upstream) -> Value {
    json!({"allowed_origins": [upstream.origin()]})
}

/// Positive control: the canary does flag the upstream's own unredacted output,
/// so a clean proxy response is meaningful.
#[tokio::test]
async fn detector_flags_the_raw_upstream_output() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let canary = Canary::new(CANARY_SECRET);
    let direct = reqwest::Client::new()
        .get(upstream.url("/echo"))
        .header("authorization", format!("Bearer {CANARY_SECRET}"))
        .send()
        .await
        .expect("direct request")
        .text()
        .await
        .expect("direct body");
    assert!(canary.find_leak(direct.as_bytes()).is_some());
}

/// Custody: the client never sees the secret in any encoding, in the body or
/// in any header, while the upstream really did receive it.
#[tokio::test]
async fn custody_proxy_redacts_every_encoding() {
    let canary = Canary::new(CANARY_SECRET);
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    assert_eq!(
        app.store("tok", CANARY_SECRET, Some(policy_for(&upstream)))
            .await
            .status,
        StatusCode::OK
    );

    let reply = app
        .proxy(
            "tok",
            &upstream.url("/echo"),
            json!({
                "method": "POST",
                "body": "hello",
                // The caller tries to pick the encoding and to pre-set the
                // credential header; both must be dropped.
                "headers": {"Accept-Encoding": "gzip", "authorization": "Bearer attacker"},
            }),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    if let Some(found) = canary.find_leak(&reply.body) {
        panic!("secret leaked to the client ({found})");
    }

    let json = reply.json();
    assert_eq!(json["status"], 200);
    let body = json["body"].as_str().expect("body");
    assert!(body.contains("[REDACTED]"));
    assert!(body.contains("received-authorization=[REDACTED]"));
    assert!(body.contains("received-body=hello"));
    assert_eq!(json["headers"]["x-echo-auth"], "[REDACTED]");
    assert_eq!(json["headers"]["x-echo-b64"], "[REDACTED]");
    assert!(
        json["headers"].get("set-cookie").is_none(),
        "upstream cookies are never relayed"
    );

    // The upstream did get the credential, exactly once, with identity coding.
    let seen = upstream.last();
    assert_eq!(
        seen.all("authorization"),
        vec![format!("Bearer {CANARY_SECRET}")]
    );
    assert_eq!(seen.all("accept-encoding"), vec!["identity".to_string()]);
}

/// A target outside the secret's allowed origins gets 403 and no connection is
/// attempted: a listening upstream records zero hits, and a closed port yields
/// 403 rather than the connect error it would produce if dialed.
#[tokio::test]
async fn origin_not_allowed_is_403_without_connecting() {
    let allowed = start_upstream(CANARY_SECRET).await;
    let other = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store("tok", CANARY_SECRET, Some(policy_for(&allowed)))
        .await;

    // A different (listening) port on the same host.
    let reply = app.proxy("tok", &other.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        other.hits(),
        0,
        "no connection may reach a disallowed origin"
    );

    // A closed port: a dial would give 400 "proxy request failed".
    let closed = format!("http://127.0.0.1:{}/echo", closed_port().await);
    let reply = app.proxy("tok", &closed, json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // Same host and port, wrong scheme.
    let https = format!("https://127.0.0.1:{}/echo", allowed.addr.port());
    let reply = app.proxy("tok", &https, json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // Different host spelling of the same machine is a different origin.
    let localhost = format!("http://localhost:{}/echo", allowed.addr.port());
    let reply = app.proxy("tok", &localhost, json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // Userinfo cannot make a foreign host look like the allowed one.
    let tricky = format!("http://127.0.0.1@localhost:{}/echo", allowed.addr.port());
    let reply = app.proxy("tok", &tricky, json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(allowed.hits(), 0);

    // The allowed origin works.
    let reply = app.proxy("tok", &allowed.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(allowed.hits(), 1);
}

/// A secret with no stored policy (what every pre-existing row looks like)
/// cannot be proxied anywhere under custody.
#[tokio::test]
async fn secret_without_origins_is_unreachable_under_custody() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store("legacy-row", CANARY_SECRET, None).await;
    let reply = app
        .proxy("legacy-row", &upstream.url("/echo"), json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(upstream.hits(), 0);
}

/// Without the test seam the SSRF check still blocks loopback, so the seam is
/// off by default.
#[tokio::test]
async fn loopback_is_blocked_unless_the_test_seam_is_on() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::new(RunProfile::Custody, false, None).await;
    app.store("tok", CANARY_SECRET, Some(policy_for(&upstream)))
        .await;
    let reply = app.proxy("tok", &upstream.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(upstream.hits(), 0);
}

/// Only `Authorization`, `X-Api-Key` and the secret's own extras accept the
/// credential; matching is case-insensitive.
#[tokio::test]
async fn auth_header_allowlist_and_per_secret_extras() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store("plain", CANARY_SECRET, Some(policy_for(&upstream)))
        .await;
    app.store(
        "extra",
        CANARY_SECRET,
        Some(json!({
            "allowed_origins": [upstream.origin()],
            "extra_auth_headers": ["X-Custom-Token"],
        })),
    )
    .await;

    for header in [
        "X-Custom-Token",
        "Cookie",
        "Host",
        "X-Forwarded-For",
        "bad header",
    ] {
        let reply = app
            .proxy(
                "plain",
                &upstream.url("/echo"),
                json!({"auth_header": header}),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{header:?}");
    }
    assert_eq!(upstream.hits(), 0, "rejected headers never reach upstream");

    for header in ["Authorization", "AUTHORIZATION", "x-api-key", "X-Api-Key"] {
        let reply = app
            .proxy(
                "plain",
                &upstream.url("/echo"),
                json!({"auth_header": header, "auth_scheme": ""}),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{header:?}");
    }
    assert_eq!(
        upstream.last().all("x-api-key"),
        vec![CANARY_SECRET.to_string()]
    );

    // The extra header works for the secret that declares it (any case), and
    // not for the one that does not.
    let reply = app
        .proxy(
            "extra",
            &upstream.url("/echo"),
            json!({"auth_header": "x-CUSTOM-token", "auth_scheme": ""}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        upstream.last().all("x-custom-token"),
        vec![CANARY_SECRET.to_string()]
    );
    let canary = Canary::new(CANARY_SECRET);
    assert!(canary.find_leak(&reply.body).is_none());
}

/// Store-time validation: wildcard, empty, portless and otherwise malformed
/// origins, and reserved headers, are rejected and nothing is stored.
#[tokio::test]
async fn store_rejects_wildcard_and_malformed_policies() {
    let app = App::custody().await;
    let bad: Vec<(Value, StatusCode)> = vec![
        (
            json!({"allowed_origins": [{"scheme": "https", "host": "*", "port": 443}]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"allowed_origins": [{"scheme": "https", "host": "*.example.com", "port": 443}]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"allowed_origins": [{"scheme": "https", "host": "", "port": 443}]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"allowed_origins": [{"scheme": "https", "host": "a.example.com", "port": 0}]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"allowed_origins": [{"scheme": "ftp", "host": "a.example.com", "port": 21}]}),
            StatusCode::BAD_REQUEST,
        ),
        // Port is mandatory: serde rejects the body before the handler runs.
        (
            json!({"allowed_origins": [{"scheme": "https", "host": "a.example.com"}]}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"extra_auth_headers": ["Host"]}),
            StatusCode::BAD_REQUEST,
        ),
        // A typo'd key must not be silently ignored.
        (
            json!({"allowed_origin": []}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];
    for (policy, expected) in bad {
        let reply = app
            .store("rejected", CANARY_SECRET, Some(policy.clone()))
            .await;
        assert_eq!(reply.status, expected, "{policy}");
    }
    let listed = app.send("GET", "/secrets", None).await;
    assert_eq!(
        listed.json()["secrets"].as_array().map(Vec::len),
        Some(0),
        "no rejected store may leave a row behind"
    );

    // A well-formed policy is accepted and normalized.
    let ok = app
        .store(
            "accepted",
            CANARY_SECRET,
            Some(json!({"allowed_origins": [{"scheme": "HTTPS", "host": "API.Example.com", "port": 443}]})),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK);
}

/// `drop_response_body` returns status and headers with an empty body and a
/// corrected Content-Length.
#[tokio::test]
async fn drop_response_body_returns_headers_only() {
    let canary = Canary::new(CANARY_SECRET);
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store(
        "tok",
        CANARY_SECRET,
        Some(json!({"allowed_origins": [upstream.origin()], "drop_response_body": true})),
    )
    .await;
    let reply = app.proxy("tok", &upstream.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(canary.find_leak(&reply.body).is_none());
    let json = reply.json();
    assert_eq!(json["status"], 200);
    assert_eq!(json["body"], "");
    assert_eq!(json["headers"]["content-length"], "0");
    assert_eq!(json["headers"]["x-echo-auth"], "[REDACTED]");
    assert_eq!(upstream.hits(), 1);
}

/// Custody refuses secrets under three bytes: redaction cannot cover them.
#[tokio::test]
async fn short_secrets_are_refused_under_custody() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store("tiny", "ab", Some(policy_for(&upstream))).await;
    let reply = app.proxy("tiny", &upstream.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(upstream.hits(), 0);
}

/// A response with a content-encoding the proxy cannot decode fails closed.
#[tokio::test]
async fn undecodable_content_encoding_fails_closed() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store("tok", CANARY_SECRET, Some(policy_for(&upstream)))
        .await;
    let reply = app
        .proxy("tok", &upstream.url("/odd-encoding"), json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

/// Updating the value without a policy keeps the stored policy; an explicit
/// empty policy clears it.
#[tokio::test]
async fn update_preserves_policy_unless_replaced() {
    let upstream = start_upstream(CANARY_SECRET).await;
    let app = App::custody().await;
    app.store("tok", CANARY_SECRET, Some(policy_for(&upstream)))
        .await;

    let rotated = "rotated-secret-value-0123456789";
    let put = app
        .send(
            "PUT",
            "/secret/svc/tok",
            Some(json!({"data": {"type": "api_key", "key": rotated}})),
        )
        .await;
    assert_eq!(put.status, StatusCode::OK);
    let reply = app.proxy("tok", &upstream.url("/echo"), json!({})).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "policy must survive a value update"
    );
    assert_eq!(
        upstream.last().all("authorization"),
        vec![format!("Bearer {rotated}")]
    );

    let put = app
        .send(
            "PUT",
            "/secret/svc/tok",
            Some(json!({"data": {"type": "api_key", "key": rotated}, "proxy_policy": {}})),
        )
        .await;
    assert_eq!(put.status, StatusCode::OK);
    let reply = app.proxy("tok", &upstream.url("/echo"), json!({})).await;
    assert_eq!(
        reply.status,
        StatusCode::FORBIDDEN,
        "an empty policy clears origins"
    );
}

/// Legacy profile: the domain allowlist still gates, the auth-header allowlist
/// and the redactor now apply, and there is no environment opt-out.
#[tokio::test]
async fn legacy_profile_keeps_allowlist_and_gains_redaction() {
    let canary = Canary::new(CANARY_SECRET);
    let upstream = start_upstream(CANARY_SECRET).await;
    let mut allowlist: ProxyDomainAllowlist = HashMap::new();
    allowlist.insert("svc".to_string(), vec!["127.0.0.1".to_string()]);
    let app = App::new(RunProfile::Legacy, true, Some(allowlist)).await;
    // No proxy_policy at all: legacy does not use origins.
    app.store("tok", CANARY_SECRET, None).await;

    let reply = app.proxy("tok", &upstream.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        canary.find_leak(&reply.body).is_none(),
        "legacy must redact too"
    );
    assert!(reply.json()["body"]
        .as_str()
        .expect("body")
        .contains("[REDACTED]"));

    let reply = app
        .proxy(
            "tok",
            &upstream.url("/echo"),
            json!({"auth_header": "X-Evil"}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    // No allowlist configured: denied. There is no opt-out of any kind.
    let denied = App::new(RunProfile::Legacy, true, None).await;
    denied.store("tok", CANARY_SECRET, None).await;
    let before = upstream.hits();
    let reply = denied.proxy("tok", &upstream.url("/echo"), json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(upstream.hits(), before);
}

/// What a TLS upstream observed across all connections.
struct MtlsSeen {
    /// Subject of the client certificate on each completed handshake.
    peers: Mutex<Vec<String>>,
    /// Lowercased request head (request line and headers) of each request.
    heads: Mutex<Vec<String>>,
    /// Number of requests that completed a handshake and were answered.
    hits: AtomicUsize,
}

/// A running TLS upstream that requires a client certificate.
struct MtlsUpstream {
    /// Address it listens on.
    addr: SocketAddr,
    /// What it has observed.
    seen: Arc<MtlsSeen>,
}

/// TLS upstream accessors.
impl MtlsUpstream {
    /// Requests that completed a handshake.
    fn hits(&self) -> usize {
        self.seen.hits.load(Ordering::SeqCst)
    }

    /// Client certificate subjects, one per handshake.
    fn peers(&self) -> Vec<String> {
        self.seen.peers.lock().expect("peers lock").clone()
    }

    /// Lowercased request heads.
    fn heads(&self) -> Vec<String> {
        self.seen.heads.lock().expect("heads lock").clone()
    }

    /// The `{scheme, host, port}` origin JSON for this upstream.
    fn origin(&self) -> Value {
        json!({"scheme": "https", "host": "127.0.0.1", "port": self.addr.port()})
    }

    /// A URL on this upstream.
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.addr.port())
    }
}

/// Lines `label=needle` for every needle of every canary, the text a hostile
/// upstream would echo to try to leak the key.
fn echo_lines(canaries: &[&Canary]) -> String {
    let mut text = String::new();
    for canary in canaries {
        for needle in &canary.needles {
            text.push_str(&format!(
                "{}={}\n",
                needle.label,
                String::from_utf8_lossy(&needle.bytes)
            ));
        }
    }
    text
}

/// Start a TLS upstream on 127.0.0.1 presenting `server` and requiring a
/// client certificate chained to `client_ca`. Each answered request replies
/// 200 with `peer=<client subject>` followed by `echo`.
async fn start_mtls_upstream(
    server: &Identity,
    client_ca: &Identity,
    echo: String,
) -> MtlsUpstream {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            client_ca.cert.to_der().expect("ca der"),
        ))
        .expect("trust client ca");
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("client verifier");
    let key_der = server.key.to_pkcs8_der().expect("server key der");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.as_bytes().to_vec()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(
                server.cert.to_der().expect("server der"),
            )],
            key,
        )
        .expect("server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tls upstream");
    let addr = listener.local_addr().expect("tls upstream addr");
    let seen = Arc::new(MtlsSeen {
        peers: Mutex::new(Vec::new()),
        heads: Mutex::new(Vec::new()),
        hits: AtomicUsize::new(0),
    });
    let shared = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let seen = shared.clone();
            let echo = echo.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let peer = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .and_then(|der| x509_cert::Certificate::from_der(der.as_ref()).ok())
                    .map(|cert| cert.tbs_certificate.subject.to_string())
                    .unwrap_or_default();
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                seen.peers.lock().expect("peers lock").push(peer.clone());
                seen.heads
                    .lock()
                    .expect("heads lock")
                    .push(String::from_utf8_lossy(&head).to_ascii_lowercase());
                seen.hits.fetch_add(1, Ordering::SeqCst);
                let body = format!("peer={peer}\n{echo}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    MtlsUpstream { addr, seen }
}

/// Everything an mTLS proxy test needs, wired together.
struct MtlsRig {
    /// The client identity the proxy will present.
    client: Identity,
    /// The TLS upstream.
    upstream: MtlsUpstream,
    /// Custody credd trusting the test CA for outbound HTTPS.
    app: App,
    /// Canary over the client's private key PEM.
    key_canary: Canary,
    /// Canary over the unwrapped base64 body of that PEM.
    body_canary: Canary,
}

/// Build an [`MtlsRig`]. The proxy always trusts the test CA that signed the
/// upstream's server certificate; `upstream_accepts_client` decides whether
/// the upstream's client-certificate trust anchor is that same CA (accept) or
/// an unrelated one (reject).
async fn mtls_rig(upstream_accepts_client: bool) -> MtlsRig {
    let ca = new_ca("mtls test CA");
    let unrelated = new_ca("unrelated CA");
    let server = new_server(&ca, IpAddr::from([127, 0, 0, 1]));
    let client = new_client(&ca, "mtls-client-7", 30);
    let key_canary = Canary::new(&client.key_pem);
    let body = unwrap_pem_body(&client.key_pem).expect("pem body");
    let body_canary = Canary::new(&body);
    let echo = echo_lines(&[&key_canary, &body_canary]);
    let trust = if upstream_accepts_client {
        &ca
    } else {
        &unrelated
    };
    let upstream = start_mtls_upstream(&server, trust, echo).await;
    let app = App::custody_trusting(&ca.cert_pem).await;
    MtlsRig {
        client,
        upstream,
        app,
        key_canary,
        body_canary,
    }
}

/// A bundle is the connection's TLS client identity: the upstream sees the
/// client certificate, no header carries a credential, the key never reaches
/// the caller in any encoding, and header-style options are refused.
#[tokio::test]
async fn mtls_bundle_is_presented_as_client_identity_and_key_is_redacted() {
    let rig = mtls_rig(true).await;
    let policy = json!({"allowed_origins": [rig.upstream.origin()]});
    assert_eq!(
        rig.app
            .store_bundle("client-id", &rig.client, policy)
            .await
            .status,
        StatusCode::OK
    );

    let reply = rig
        .app
        .proxy("client-id", &rig.upstream.url("/echo"), json!({}))
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let json = reply.json();
    assert_eq!(json["status"], 200);
    let body = json["body"].as_str().expect("body");
    assert!(
        body.contains("peer=CN=mtls-client-7"),
        "upstream must see the client certificate subject: {body}"
    );
    assert!(body.contains("[REDACTED]"), "echoed key forms are redacted");
    assert_eq!(rig.upstream.peers(), vec!["CN=mtls-client-7".to_string()]);
    for canary in [&rig.key_canary, &rig.body_canary] {
        if let Some(found) = canary.find_leak(&reply.body) {
            panic!("private key leaked to the client ({found})");
        }
    }
    assert!(!String::from_utf8_lossy(&reply.body).contains("PRIVATE KEY"));
    let heads = rig.upstream.heads();
    assert_eq!(heads.len(), 1);
    assert!(
        !heads[0].contains("authorization:") && !heads[0].contains("x-api-key:"),
        "no credential header may be injected for a bundle: {}",
        heads[0]
    );

    // A header or scheme makes no sense for a bundle: 400, upstream untouched.
    let hits = rig.upstream.hits();
    for extra in [
        json!({"auth_header": "Authorization"}),
        json!({"auth_scheme": "Bearer"}),
        json!({"auth_header": "X-Api-Key", "auth_scheme": ""}),
    ] {
        let reply = rig
            .app
            .proxy("client-id", &rig.upstream.url("/echo"), extra)
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&reply.body).contains("TLS client identity"));
    }
    assert_eq!(rig.upstream.hits(), hits, "refused requests never connect");

    // The bundle still obeys origin pinning.
    let elsewhere = format!("https://127.0.0.1:{}/echo", closed_port().await);
    let reply = rig.app.proxy("client-id", &elsewhere, json!({})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

/// The legacy base64-JSON note bundle is presented the same way.
#[tokio::test]
async fn legacy_note_bundle_is_presented_as_client_identity() {
    let rig = mtls_rig(true).await;
    let policy = json!({"allowed_origins": [rig.upstream.origin()]});
    let stored = rig
        .app
        .store_data(
            "legacy-id",
            json!({
                "type": "note",
                "content": legacy_note_content(&rig.client.cert_pem, &rig.client.key_pem, 1),
            }),
            policy,
        )
        .await;
    assert_eq!(stored.status, StatusCode::OK);
    let reply = rig
        .app
        .proxy("legacy-id", &rig.upstream.url("/echo"), json!({}))
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert!(reply.json()["body"]
        .as_str()
        .expect("body")
        .contains("peer=CN=mtls-client-7"));
    for canary in [&rig.key_canary, &rig.body_canary] {
        assert!(canary.find_leak(&reply.body).is_none());
    }
    // The note's own content (base64 of the JSON, key inside) is not echoed,
    // and the proxy refuses header options for it too.
    let reply = rig
        .app
        .proxy(
            "legacy-id",
            &rig.upstream.url("/echo"),
            json!({"auth_header": "Authorization"}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

/// An upstream that rejects the client certificate yields a proxy error whose
/// body carries no key bytes, and the upstream never answers.
#[tokio::test]
async fn rejected_client_certificate_error_carries_no_key_bytes() {
    let rig = mtls_rig(false).await;
    let policy = json!({"allowed_origins": [rig.upstream.origin()]});
    rig.app.store_bundle("client-id", &rig.client, policy).await;

    let reply = rig
        .app
        .proxy("client-id", &rig.upstream.url("/echo"), json!({}))
        .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(
        rig.upstream.hits(),
        0,
        "the upstream must refuse the handshake"
    );
    for canary in [&rig.key_canary, &rig.body_canary] {
        if let Some(found) = canary.find_leak(&reply.body) {
            panic!("error body leaked key bytes ({found})");
        }
    }
    let text = String::from_utf8_lossy(&reply.body);
    assert!(
        !text.contains("PRIVATE KEY") && !text.contains("BEGIN"),
        "{text}"
    );
}

/// Without the extra-root seam, an upstream signed by an unknown CA fails
/// verification: certificate checking is never relaxed for bundles.
#[tokio::test]
async fn unknown_server_ca_is_not_trusted() {
    let rig = mtls_rig(true).await;
    let strict = App::custody_trusting(&new_ca("some other root").cert_pem).await;
    let policy = json!({"allowed_origins": [rig.upstream.origin()]});
    strict.store_bundle("client-id", &rig.client, policy).await;
    let reply = strict
        .proxy("client-id", &rig.upstream.url("/echo"), json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(rig.upstream.hits(), 0);
    assert!(rig.key_canary.find_leak(&reply.body).is_none());
}
