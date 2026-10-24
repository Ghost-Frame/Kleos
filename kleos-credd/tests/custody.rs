//! Custody-profile tests for the standalone credd router and startup path.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kleos_cred::crypto::derive_key;
use kleos_credd::auth::IsUnixSocket;
use kleos_credd::custody::{
    check_bind_address, check_uid, ensure_vault_file, CustodyContext, CustodyStartupError,
};
use kleos_credd::profile::RunProfile;
use kleos_credd::server::run_with_env_as;
use kleos_credd::state::AppState;
use kleos_credd::{build_router, mounted_paths};
use kleos_lib::db::Database;

/// Which listener a simulated request came from.
#[derive(Clone, Copy, Debug)]
enum Origin {
    /// `IsUnixSocket(true)`.
    Unix,
    /// `IsUnixSocket(false)`.
    Tcp,
    /// No marker at all (must be treated as TCP).
    Unmarked,
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

/// credd router plus credentials, for one run profile.
struct App {
    /// Router under test.
    router: Router,
    /// Hex master bearer.
    master_token: String,
    /// Scratch directory for key files.
    dir: tempfile::TempDir,
}

/// Request helpers.
impl App {
    /// Build an in-memory credd app for `profile`.
    async fn new(profile: RunProfile) -> Self {
        let db = Database::connect_memory().await.expect("in-memory db");
        let master_key = derive_key(1, b"test-master-password", None);
        let master_token = hex::encode(*master_key);
        let state = AppState::new(db, *master_key).with_run_profile(profile);
        Self {
            router: build_router(state),
            master_token,
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// Send one request with an origin marker and optional bearer.
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
        match origin {
            Origin::Unix => {
                req.extensions_mut().insert(IsUnixSocket(true));
            }
            Origin::Tcp => {
                req.extensions_mut().insert(IsUnixSocket(false));
            }
            Origin::Unmarked => {}
        }
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

    /// Create a custody agent as the master over the Unix socket, returning
    /// the key read from the written file.
    async fn custody_agent(&self, name: &str) -> String {
        let path = self.dir.path().join(format!("{name}.key"));
        let master = self.master_token.clone();
        let reply = self
            .send(
                Origin::Unix,
                "POST",
                "/agents",
                Some(&master),
                Some(json!({
                    "name": name,
                    "categories": ["prod"],
                    "key_path": path.to_str().expect("utf8"),
                })),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "custody agent creation");
        std::fs::read_to_string(&path)
            .expect("key file")
            .trim()
            .to_string()
    }
}

/// Remove listener env so the startup path resolves bind addresses from its
/// `listen` argument only.
fn clear_listener_env() {
    std::env::remove_var("CREDD_SOCKET");
    std::env::remove_var("CREDD_BIND");
}

/// A uid that is neither the current user nor the forbidden 1000.
fn other_uid(current: u32) -> u32 {
    if current == 4242 {
        4243
    } else {
        4242
    }
}

/// credd-level route enumeration: custody drops exactly the plaintext routes.
#[test]
fn credd_route_enumeration_matches_profile() {
    let custody = mounted_paths(RunProfile::Custody);
    let legacy = mounted_paths(RunProfile::Legacy);
    for route in [
        "GET /secret/{category}/{*name}",
        "POST /resolve/text",
        "POST /resolve/raw",
        "GET /bootstrap/kleos-bearer",
    ] {
        assert!(!custody.iter().any(|r| r == route), "{route} under custody");
        assert!(
            legacy.iter().any(|r| r == route),
            "{route} missing in legacy"
        );
    }
    for route in [
        "GET /secrets",
        "POST /resolve/proxy",
        "POST /resolve/public",
        "POST /agents",
        "GET /health",
    ] {
        assert!(
            custody.iter().any(|r| r == route),
            "{route} missing in custody"
        );
        assert!(
            legacy.iter().any(|r| r == route),
            "{route} missing in legacy"
        );
    }
    // Custody-only: mounted under custody, absent under legacy.
    let rotate = "POST /custody/x509/rotate-leaf";
    assert!(
        custody.iter().any(|r| r == rotate),
        "{rotate} missing in custody"
    );
    assert!(!legacy.iter().any(|r| r == rotate), "{rotate} under legacy");
}

/// Custody: the master bearer works on the Unix socket and is refused with 403
/// on TCP (marked or unmarked); legacy is unaffected.
#[tokio::test]
async fn master_bearer_is_refused_on_tcp_under_custody() {
    let custody = App::new(RunProfile::Custody).await;
    let master = custody.master_token.clone();

    let unix = custody
        .send(Origin::Unix, "GET", "/secrets", Some(&master), None)
        .await;
    assert_eq!(unix.status, StatusCode::OK);

    for origin in [Origin::Tcp, Origin::Unmarked] {
        let reply = custody
            .send(origin, "GET", "/secrets", Some(&master), None)
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert!(
            !String::from_utf8_lossy(&reply.body).contains(&master),
            "refusal must not echo the bearer"
        );
    }

    let legacy = App::new(RunProfile::Legacy).await;
    let master = legacy.master_token.clone();
    let reply = legacy
        .send(Origin::Tcp, "GET", "/secrets", Some(&master), None)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
}

/// Custody: an agent key is accepted over TCP and the plaintext routes are
/// absent for it.
#[tokio::test]
async fn agent_key_is_accepted_on_tcp_under_custody() {
    let app = App::new(RunProfile::Custody).await;
    let key = app.custody_agent("tcp-agent").await;

    let listed = app
        .send(Origin::Tcp, "GET", "/secrets", Some(&key), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);

    let text = app
        .send(
            Origin::Tcp,
            "POST",
            "/resolve/text",
            Some(&key),
            Some(json!({"text": "x"})),
        )
        .await;
    assert_eq!(text.status, StatusCode::NOT_FOUND);
}

/// Custody agent creation writes the key to a 0600 O_EXCL file and returns only
/// a fingerprint; the written key authenticates.
#[tokio::test]
async fn custody_agent_creation_returns_only_a_fingerprint() {
    let app = App::new(RunProfile::Custody).await;
    let path = app.dir.path().join("agent.key");
    let master = app.master_token.clone();
    let body = json!({
        "name": "fp-agent",
        "categories": ["prod"],
        "key_path": path.to_str().expect("utf8"),
    });

    let reply = app
        .send(
            Origin::Unix,
            "POST",
            "/agents",
            Some(&master),
            Some(body.clone()),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["name"], "fp-agent");
    assert_eq!(json["fingerprint"].as_str().map(str::len), Some(16));
    assert!(json.get("key").is_none(), "response must not carry the key");

    let meta = std::fs::metadata(&path).expect("key file");
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    let key = std::fs::read_to_string(&path).expect("read key");
    let key = key.trim();
    assert_eq!(key.len(), 64);
    assert!(
        !String::from_utf8_lossy(&reply.body).contains(key),
        "the key must never appear in the response"
    );

    // The written key authenticates.
    let ok = app
        .send(Origin::Tcp, "GET", "/secrets", Some(key), None)
        .await;
    assert_eq!(ok.status, StatusCode::OK);

    // O_EXCL: a second creation at the same path is refused and leaves the key
    // file untouched.
    let again = app
        .send(
            Origin::Unix,
            "POST",
            "/agents",
            Some(&master),
            Some(json!({"name": "fp-agent-2", "key_path": path.to_str().expect("utf8")})),
        )
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read_to_string(&path).expect("reread").trim(), key);
}

/// Custody agent creation is refused off the Unix socket, for non-masters, and
/// for unsafe paths.
#[tokio::test]
async fn custody_agent_creation_guards() {
    let app = App::new(RunProfile::Custody).await;
    let master = app.master_token.clone();
    let key = app.custody_agent("existing").await;
    let path = app.dir.path().join("guarded.key");
    let body = json!({"name": "guarded", "key_path": path.to_str().expect("utf8")});

    // Agent key over the Unix socket: not master.
    let not_master = app
        .send(
            Origin::Unix,
            "POST",
            "/agents",
            Some(&key),
            Some(body.clone()),
        )
        .await;
    assert_eq!(not_master.status, StatusCode::FORBIDDEN);
    // Agent key over TCP: not unix, not master.
    let tcp = app
        .send(
            Origin::Tcp,
            "POST",
            "/agents",
            Some(&key),
            Some(body.clone()),
        )
        .await;
    assert_eq!(tcp.status, StatusCode::FORBIDDEN);
    // Master over TCP: refused by auth.
    let master_tcp = app
        .send(Origin::Tcp, "POST", "/agents", Some(&master), Some(body))
        .await;
    assert_eq!(master_tcp.status, StatusCode::FORBIDDEN);
    assert!(!path.exists(), "no refused request may create the file");

    for bad in [
        "relative.key",
        "",
        "/tmp/../etc/x.key",
        "/no-such-dir/x.key",
    ] {
        let reply = app
            .send(
                Origin::Unix,
                "POST",
                "/agents",
                Some(&master),
                Some(json!({"name": "bad", "key_path": bad})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "key_path {bad:?}");
    }

    // A failed creation must not leave a usable agent behind.
    let list = app
        .send(Origin::Unix, "GET", "/agents", Some(&master), None)
        .await;
    let names: Vec<String> = list.json()["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .filter_map(|k| k["name"].as_str().map(String::from))
        .collect();
    assert_eq!(names, vec!["existing".to_string()]);
}

/// Legacy agent creation still returns the raw key, and the retired
/// `allow_raw` field is accepted and ignored.
#[tokio::test]
async fn legacy_agent_creation_still_returns_the_key() {
    let app = App::new(RunProfile::Legacy).await;
    let master = app.master_token.clone();
    let reply = app
        .send(
            Origin::Tcp,
            "POST",
            "/agents",
            Some(&master),
            Some(json!({"name": "legacy", "categories": ["prod"], "allow_raw": true})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["key"].as_str().map(str::len), Some(64));

    let list = app
        .send(Origin::Tcp, "GET", "/agents", Some(&master), None)
        .await;
    assert!(
        list.json()["keys"][0].get("allow_raw").is_none(),
        "allow_raw must not be reported any more"
    );
}

/// Drive the real startup path with an injected identity and return the typed
/// custody refusal it produced.
async fn refusal(ctx: CustodyContext, listen: &str, db_path: &Path) -> CustodyStartupError {
    clear_listener_env();
    let missing_keyfile = db_path.with_extension("no-such-keyfile");
    let err = run_with_env_as(
        &ctx,
        listen,
        db_path.to_str().expect("utf8"),
        "keyfile",
        None,
        Some(missing_keyfile),
        RunProfile::Custody,
        build_router,
    )
    .await
    .expect_err("startup must be refused");
    err.downcast::<CustodyStartupError>()
        .unwrap_or_else(|e| panic!("expected a typed custody refusal, got: {e:#}"))
}

/// uid 1000 (real or effective) is refused before anything else happens.
#[tokio::test]
async fn startup_refuses_uid_1000() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");
    for ctx in [
        CustodyContext {
            real_uid: 1000,
            effective_uid: 1000,
        },
        CustodyContext {
            real_uid: 1000,
            effective_uid: 4242,
        },
        CustodyContext {
            real_uid: 4242,
            effective_uid: 1000,
        },
    ] {
        let err = refusal(ctx, "10.50.0.1:3100", &db).await;
        assert!(
            matches!(err, CustodyStartupError::ForbiddenUid { uid: 1000 }),
            "{err:?}"
        );
    }
    assert!(!db.exists(), "a refused start must not create the vault");
}

/// Hostnames and addresses outside 10.50.0.0/24 are refused with distinct
/// variants, before the vault is touched.
#[tokio::test]
async fn startup_refuses_bad_bind_addresses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");
    let ctx = CustodyContext {
        real_uid: 4242,
        effective_uid: 4242,
    };

    for host in ["localhost:3100", "phylax.internal:3100", "[::1]:3100"] {
        let err = refusal(ctx, host, &db).await;
        assert!(
            matches!(err, CustodyStartupError::BindNotLiteralIpv4 { .. }),
            "{host}: {err:?}"
        );
    }
    for addr in [
        "127.0.0.1:3100",
        "0.0.0.0:3100",
        "10.50.1.1:3100",
        "192.168.0.5:3100",
    ] {
        let err = refusal(ctx, addr, &db).await;
        assert!(
            matches!(err, CustodyStartupError::BindOutsideMesh { .. }),
            "{addr}: {err:?}"
        );
    }
    assert!(!db.exists(), "a refused start must not create the vault");

    assert!(check_bind_address("10.50.0.7:3100").is_ok());
}

/// A vault file owned by someone else is refused (through the real startup
/// path, by injecting a different effective uid).
#[tokio::test]
async fn startup_refuses_wrong_vault_owner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");
    std::fs::write(&db, b"").expect("create vault");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let owner = std::fs::metadata(&db).expect("stat").uid();

    let other = other_uid(owner);
    let ctx = CustodyContext {
        real_uid: other,
        effective_uid: other,
    };
    let err = refusal(ctx, "10.50.0.1:3100", &db).await;
    assert!(
        matches!(err, CustodyStartupError::VaultWrongOwner { owner: o, euid, .. } if o == owner && euid == other),
        "{err:?}"
    );
}

/// A vault file with the wrong mode is refused. The direct check always runs;
/// the real startup path is exercised too when this process is not uid 1000
/// (the injected effective uid must equal the file owner, and 1000 is refused
/// earlier).
#[tokio::test]
async fn startup_refuses_wrong_vault_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");
    std::fs::write(&db, b"").expect("create vault");
    let owner = std::fs::metadata(&db).expect("stat").uid();

    for mode in [0o644, 0o640, 0o400, 0o666, 0o4600] {
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(mode)).expect("chmod");
        let err = ensure_vault_file(&db, owner).expect_err("mode must be refused");
        assert!(
            matches!(err, CustodyStartupError::VaultWrongMode { mode: m, .. } if m == mode),
            "mode {mode:o}: {err:?}"
        );
    }

    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    if owner != 1000 {
        let ctx = CustodyContext {
            real_uid: owner,
            effective_uid: owner,
        };
        let err = refusal(ctx, "10.50.0.1:3100", &db).await;
        assert!(
            matches!(err, CustodyStartupError::VaultWrongMode { .. }),
            "{err:?}"
        );
    }

    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    ensure_vault_file(&db, owner).expect("0600 owned by us is accepted");
}

/// The uid check accepts everything but 1000.
#[test]
fn uid_check_accepts_service_uids() {
    assert!(check_uid(&CustodyContext {
        real_uid: 0,
        effective_uid: 0
    })
    .is_ok());
    assert!(check_uid(&CustodyContext {
        real_uid: 4242,
        effective_uid: 4242
    })
    .is_ok());
    assert!(check_uid(&CustodyContext {
        real_uid: 999,
        effective_uid: 1001
    })
    .is_ok());
}
