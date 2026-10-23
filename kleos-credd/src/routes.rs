//! Profile-aware route table.
//!
//! Every route is declared exactly once, with an explicit [`Exposure`], through
//! [`RouteTable`]. The same declaration both mounts the handler on the axum
//! router (or skips it under a profile that excludes it) and records the
//! `(method, path)` pair, so the list returned by `mounted_paths` can never
//! drift from what the router actually serves.

use std::fmt;

use axum::handler::Handler;
use axum::http::Method;
use axum::routing::{self, MethodRouter};
use axum::Router;

use crate::profile::RunProfile;

/// In which run profiles a route is mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Mounted under every profile.
    Always,
    /// Mounted only under [`RunProfile::Legacy`] (plaintext-returning routes).
    LegacyOnly,
    /// Mounted only under [`RunProfile::Custody`] (custody replacement handlers).
    CustodyOnly,
}

/// Exposure queries.
impl Exposure {
    /// True when a route with this exposure is mounted under `profile`.
    pub fn mounted_under(self, profile: RunProfile) -> bool {
        match self {
            Self::Always => true,
            Self::LegacyOnly => profile == RunProfile::Legacy,
            Self::CustodyOnly => profile == RunProfile::Custody,
        }
    }
}

/// One `(method, path)` pair that a router serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedRoute {
    /// HTTP method of the mounted handler.
    pub method: Method,
    /// Axum path template, e.g. `/secret/{category}/{*name}`.
    pub path: &'static str,
}

/// Renders as `"GET /secrets"`.
impl fmt::Display for MountedRoute {
    /// Write `METHOD path`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.path)
    }
}

/// A router under construction plus the list of routes it serves.
pub struct RouteTable<S> {
    /// Profile the table is being built for.
    profile: RunProfile,
    /// Router holding only the routes whose exposure admits `profile`.
    router: Router<S>,
    /// Every route actually mounted on `router`.
    mounted: Vec<MountedRoute>,
}

/// Route declaration, composition, and inspection.
impl<S> RouteTable<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Start an empty table for `profile`.
    pub fn new(profile: RunProfile) -> Self {
        Self {
            profile,
            router: Router::new(),
            mounted: Vec::new(),
        }
    }

    /// Mount `make()` at `path` for `method` when `exposure` admits the profile.
    fn mount(
        mut self,
        method: Method,
        path: &'static str,
        exposure: Exposure,
        make: impl FnOnce() -> MethodRouter<S>,
    ) -> Self {
        if exposure.mounted_under(self.profile) {
            self.router = self.router.route(path, make());
            self.mounted.push(MountedRoute { method, path });
        }
        self
    }

    /// Declare a `GET` route.
    pub fn get<H, T>(self, path: &'static str, exposure: Exposure, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.mount(Method::GET, path, exposure, || routing::get(handler))
    }

    /// Declare a `POST` route.
    pub fn post<H, T>(self, path: &'static str, exposure: Exposure, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.mount(Method::POST, path, exposure, || routing::post(handler))
    }

    /// Declare a `PUT` route.
    pub fn put<H, T>(self, path: &'static str, exposure: Exposure, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.mount(Method::PUT, path, exposure, || routing::put(handler))
    }

    /// Declare a `DELETE` route.
    pub fn delete<H, T>(self, path: &'static str, exposure: Exposure, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.mount(Method::DELETE, path, exposure, || routing::delete(handler))
    }

    /// Merge another table (built for the same profile) into this one.
    pub fn merge(mut self, other: RouteTable<S>) -> Self {
        debug_assert_eq!(self.profile, other.profile, "merging mismatched profiles");
        self.router = self.router.merge(other.router);
        self.mounted.extend(other.mounted);
        self
    }

    /// Apply a router transformation (layers) without touching the route list.
    pub fn map_router(mut self, f: impl FnOnce(Router<S>) -> Router<S>) -> Self {
        self.router = f(self.router);
        self
    }

    /// Routes mounted so far.
    pub fn mounted(&self) -> &[MountedRoute] {
        &self.mounted
    }

    /// Mounted routes rendered as `"METHOD path"` strings.
    pub fn mounted_paths(&self) -> Vec<String> {
        self.mounted.iter().map(ToString::to_string).collect()
    }

    /// Consume the table and return the router.
    pub fn into_router(self) -> Router<S> {
        self.router
    }
}

/// Unit tests for exposure rules.
#[cfg(test)]
mod tests {
    use super::*;

    /// Exposure admits exactly the documented profiles.
    #[test]
    fn exposure_matrix() {
        use Exposure::*;
        use RunProfile::*;
        assert!(Always.mounted_under(Legacy) && Always.mounted_under(Custody));
        assert!(LegacyOnly.mounted_under(Legacy) && !LegacyOnly.mounted_under(Custody));
        assert!(!CustodyOnly.mounted_under(Legacy) && CustodyOnly.mounted_under(Custody));
    }

    /// An excluded route is neither mounted nor recorded; an admitted one is both.
    #[test]
    fn excluded_routes_are_not_recorded() {
        async fn ok() -> &'static str {
            "ok"
        }
        let build = |profile| {
            RouteTable::<()>::new(profile)
                .get("/a", Exposure::Always, ok)
                .get("/b", Exposure::LegacyOnly, ok)
                .post("/c", Exposure::CustodyOnly, ok)
        };
        assert_eq!(
            build(RunProfile::Legacy).mounted_paths(),
            vec!["GET /a", "GET /b"]
        );
        assert_eq!(
            build(RunProfile::Custody).mounted_paths(),
            vec!["GET /a", "POST /c"]
        );
    }
}
