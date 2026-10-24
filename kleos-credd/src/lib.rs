//! engram-credd library exports for testing.

pub mod auth;
pub mod bootstrap;
#[cfg(unix)]
pub mod custody;
pub mod handlers;
pub mod listener;
pub mod peercred;
pub mod profile;
pub mod redact;
pub mod routes;
pub mod server;
pub mod state;

use axum::{
    extract::{DefaultBodyLimit, FromRef},
    middleware, Router,
};
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use auth::{auth_middleware, preauth_rate_limit};
use handlers::{agents, bootstrap_bearer, resolve, secrets};
use profile::RunProfile;
use routes::{Exposure, RouteTable};
use state::AppState;

/// Request body limit: 1 MiB. Prevents memory exhaustion from oversized
/// secret payloads or proxy bodies.
pub const CREDD_BODY_LIMIT: usize = 1024 * 1024;

/// Per-request timeout: 30 seconds. Prevents slow-loris / hung upstream
/// from tying up handler tasks indefinitely.
pub const CREDD_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Declare the credd routes for `profile`.
///
/// This is the single source of truth for what credd serves: the router built
/// by [`credd_routes`] and the list returned by [`mounted_paths`] both come
/// from this table, so they cannot drift. Plaintext-returning routes are
/// `LegacyOnly` and are not mounted at all under the custody profile.
pub fn credd_route_table<S>(profile: RunProfile) -> RouteTable<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    use Exposure::{Always, CustodyOnly, LegacyOnly};

    RouteTable::new(profile)
        // Secret management
        .get("/secrets", Always, secrets::list_handler)
        .post("/sync", Always, secrets::sync_handler)
        // GET returns the secret plaintext: not mounted under custody.
        .get(
            "/secret/{category}/{*name}",
            LegacyOnly,
            secrets::get_handler,
        )
        .post("/secret/{category}/{*name}", Always, secrets::store_handler)
        .put(
            "/secret/{category}/{*name}",
            Always,
            secrets::update_handler,
        )
        .delete(
            "/secret/{category}/{*name}",
            Always,
            secrets::delete_handler,
        )
        // Three-tier resolve. text and raw return plaintext: legacy only.
        .post("/resolve/text", LegacyOnly, resolve::resolve_text_handler)
        .post("/resolve/proxy", Always, resolve::proxy_handler)
        .post("/resolve/raw", LegacyOnly, resolve::raw_handler)
        // Agent key management. Creation returns the raw key in the legacy
        // profile; custody swaps in a handler that writes the key to a 0600
        // file and returns only a fingerprint.
        .get("/agents", Always, agents::list_handler)
        .post("/agents", LegacyOnly, agents::create_handler)
        .post("/agents", CustodyOnly, agents::create_custody_handler)
        .delete("/agents/{name}", Always, agents::delete_handler)
        .post("/agents/{name}/revoke", Always, agents::revoke_handler)
        // Bootstrap bearer (broker per-agent Kleos bearers without on-disk
        // plaintext). The GET variant returns the bearer in the clear; only
        // the ECDH POST variant survives under custody.
        .get(
            "/bootstrap/kleos-bearer",
            LegacyOnly,
            bootstrap_bearer::get_bootstrap_kleos_bearer,
        )
        .post(
            "/bootstrap/kleos-bearer",
            Always,
            bootstrap_bearer::post_bootstrap_kleos_bearer_ecdh,
        )
        // Health check (no auth)
        .get("/health", Always, health_handler)
}

/// Wrap a route table's router in credd's auth, rate-limit, body-limit,
/// timeout, and tracing layers (outermost layer executes first).
fn apply_credd_layers<S>(router: Router<S>, state: AppState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(state, preauth_rate_limit))
        // SECURITY: request hardening -- same limits as the binary server.
        .layer(DefaultBodyLimit::max(CREDD_BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(CREDD_REQUEST_TIMEOUT_SECS),
        ))
        .layer(TraceLayer::new_for_http())
}

/// Build the credd router used by both the binary server and integration
/// tests. Tests previously used a slimmed-down version that bypassed the
/// preauth rate limiter; sharing this builder keeps brute-force regressions
/// covered. The mounted route set follows `state.run_profile`.
pub fn credd_routes<S>(state: AppState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    credd_routes_with_inner_layer(state, |router| router)
}

/// Like [`credd_routes`], but applies `inner` to the bare route table before
/// credd's own layers are added. Anything `inner` adds (for example a policy
/// middleware) therefore runs after authentication: auth, rate limiting, body
/// limit and timeout wrap it, and it can read the `AuthInfo` auth inserted.
pub fn credd_routes_with_inner_layer<S>(
    state: AppState,
    inner: impl FnOnce(Router<S>) -> Router<S>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    let table = credd_route_table::<S>(state.run_profile);
    apply_credd_layers(inner(table.into_router()), state)
}

/// List every `"METHOD path"` the credd router mounts under `profile`.
pub fn mounted_paths(profile: RunProfile) -> Vec<String> {
    credd_route_table::<AppState>(profile).mounted_paths()
}

/// Build a complete credd app with concrete AppState installed.
pub fn build_router(state: AppState) -> Router {
    credd_routes::<AppState>(state.clone()).with_state(state)
}

/// Return the unauthenticated health response body.
async fn health_handler() -> &'static str {
    "ok"
}
