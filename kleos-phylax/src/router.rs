//! Phylax route tree -- extends credd's base router with /phylax/* endpoints.
//!
//! Routes are declared once through [`RouteTable`], so the router served and
//! the list returned by [`mounted_paths`] cannot drift. Which routes exist is
//! decided by the [`RunProfile`] carried on `AppState::run_profile`.

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::Router;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers::{
    approvals, ecdh, kleos_token, leases, namespaces, policies, resolve_modes, ssh, ssh_ca,
    ssh_sign,
};
use crate::middleware::policy_check_middleware;
use crate::state::PhylaxState;
use kleos_credd::auth::{auth_middleware, preauth_rate_limit};
use kleos_credd::profile::RunProfile;
use kleos_credd::routes::{Exposure, RouteTable};
use kleos_credd::state::AppState;
use kleos_credd::{credd_route_table, CREDD_BODY_LIMIT, CREDD_REQUEST_TIMEOUT_SECS};

/// Request window for the SSH CA sign/mint routes. These can block on an
/// out-of-band human approval (push to phone, a human taps), which takes longer
/// than the global default; bound it generously while still capping the wait.
const SSH_CA_REQUEST_TIMEOUT_SECS: u64 = 120;

/// Declare the Phylax extension routes for `profile`.
///
/// Single source of truth for what the Phylax extension serves; both
/// [`phylax_routes`] and [`mounted_paths`] consume it. `/resolve/derive`
/// returns derived key material and is not mounted under the custody profile.
pub fn phylax_route_table(profile: RunProfile) -> RouteTable<PhylaxState> {
    use Exposure::{Always, LegacyOnly};

    // The SSH CA routes get a longer request window than everything else, since
    // the M3 branch polls for a human approval. Scoped to just these two routes
    // so all other endpoints keep the snappy global timeout.
    let ssh_ca_routes = RouteTable::new(profile)
        .post("/phylax/ssh-ca/sign", Always, ssh_ca::sign)
        .post("/phylax/ssh-ca/mint", Always, ssh_ca::mint)
        .map_router(|router| {
            router.layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(SSH_CA_REQUEST_TIMEOUT_SECS),
            ))
        });

    RouteTable::new(profile)
        // Approval workflows
        .post("/phylax/approvals", Always, approvals::request_approval)
        .get("/phylax/approvals", Always, approvals::list_approvals)
        .get("/phylax/approvals/{id}", Always, approvals::get_approval)
        .put("/phylax/approvals/{id}", Always, approvals::decide_approval)
        .get(
            "/phylax/approvals/{id}/wait",
            Always,
            approvals::wait_for_decision,
        )
        // Capability-token approval decision. Auth-exempt in auth_middleware:
        // the single-use token presented in the body is the capability.
        .post(
            "/phylax/approvals/{id}/decide-token",
            Always,
            approvals::decide_with_token,
        )
        // Leases
        .get("/phylax/leases", Always, leases::list_leases)
        .post("/phylax/leases/{jti}/redeem", Always, leases::redeem_lease)
        // Access policies
        .get("/phylax/policies", Always, policies::list_policies)
        .post("/phylax/policies", Always, policies::create_policy)
        .put("/phylax/policies/{id}", Always, policies::update_policy)
        .delete("/phylax/policies/{id}", Always, policies::delete_policy)
        // Namespaces
        .get("/phylax/namespaces", Always, namespaces::list_namespaces)
        // Non-plaintext resolve modes: the secret is used server-side and
        // only the operation result returns. Mounted under /resolve/ so the
        // policy middleware intercepts them like the credd resolve routes.
        .post("/resolve/verify", Always, resolve_modes::verify_payload)
        .post("/resolve/sign", Always, resolve_modes::sign_payload)
        // Returns derived key material (derived_b64): legacy only.
        .post(
            "/resolve/derive",
            LegacyOnly,
            resolve_modes::derive_key_material,
        )
        .post("/resolve/exec", Always, resolve_modes::exec_command)
        // Keyless Kleos token broker (Unix-socket + SO_PEERCRED gated; the
        // handler enforces both, and auth_middleware skips bearer auth for it).
        .post("/phylax/kleos/token", Always, kleos_token::mint_kleos_token)
        // ECDH
        .post("/phylax/ecdh/challenge", Always, ecdh::issue_challenge)
        .post("/phylax/ecdh/enroll", Always, ecdh::enroll_pubkey)
        .post("/phylax/ecdh/revoke", Always, ecdh::revoke_pubkey)
        // SSH key operations -- literal path before wildcard so it is not shadowed.
        .get("/phylax/ssh/identities", Always, ssh_sign::identities)
        // SSH signing
        .post("/phylax/ssh/{category}/{name}/sign", Always, ssh_sign::sign)
        // SSH key settings
        .get("/phylax/ssh/{category}/{name}", Always, ssh::get_settings)
        .put(
            "/phylax/ssh/{category}/{name}",
            Always,
            ssh::update_settings,
        )
        // Global request window for every route above.
        .map_router(|router| {
            router.layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(CREDD_REQUEST_TIMEOUT_SECS),
            ))
        })
        // SSH certificate authority routes carry their own longer timeout.
        .merge(ssh_ca_routes)
}

/// Build the Phylax extension routes. These are merged into the credd
/// router by the phylaxd binary. The mounted set follows
/// `phylax_state.run_profile`.
///
/// Layer order, outermost first: preauth rate limit, auth, body limit, trace,
/// then `policy_check_middleware` closest to the handlers. Policy therefore
/// sees only authenticated requests; an unauthenticated one is answered 401
/// before any policy decision.
pub fn phylax_routes(phylax_state: &PhylaxState) -> Router<PhylaxState> {
    let state = phylax_state.inner.clone();
    phylax_route_table(state.run_profile)
        .into_router()
        .route_layer(middleware::from_fn_with_state(
            phylax_state.clone(),
            policy_check_middleware,
        ))
        // Apply the same auth and preauth protections to all routes.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(state, preauth_rate_limit))
        .layer(DefaultBodyLimit::max(CREDD_BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
}

/// List every `"METHOD path"` the composed credd + Phylax router mounts under
/// `profile`.
pub fn mounted_paths(profile: RunProfile) -> Vec<String> {
    credd_route_table::<PhylaxState>(profile)
        .merge(phylax_route_table(profile))
        .mounted_paths()
}

/// Compose credd base routes and phylax extensions into a single router.
///
/// `policy_check_middleware` is installed on both route sets inside their
/// authentication layer, so /resolve/* requests can return approval responses
/// before credd plaintext handlers execute, but only after the caller has been
/// authenticated. The mounted route set follows the `run_profile` carried by
/// `state`.
pub fn compose_router(state: AppState) -> Router {
    compose_router_with_phylax_state(PhylaxState::from_app_state(state))
}

/// Compose credd base routes and Phylax extensions with an explicit Phylax state.
pub fn compose_router_with_phylax_state(phylax_state: PhylaxState) -> Router {
    let state = phylax_state.inner.clone();
    // Merge credd base routes with phylax extension routes. Each set carries
    // the policy layer between its auth layers and its handlers, so policy
    // interception on resolve endpoints runs after authentication.
    let policy_phylax_state = phylax_state.clone();
    let with_policy = move |router: Router<PhylaxState>| {
        router.route_layer(middleware::from_fn_with_state(
            policy_phylax_state,
            policy_check_middleware,
        ))
    };
    let app = kleos_credd::credd_routes_with_inner_layer::<PhylaxState>(state, with_policy)
        .merge(phylax_routes(&phylax_state));

    app.with_state(phylax_state)
}
