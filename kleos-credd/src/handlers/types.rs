//! Request and response DTOs for credd HTTP handlers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use kleos_cred::types::{ProxyPolicy, SecretData};

#[derive(Deserialize)]
pub struct ListQuery {
    pub category: Option<String>,
}

#[derive(Serialize)]
pub struct SecretListItem {
    pub service: String,
    pub key: String,
    pub secret_type: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Body of `POST`/`PUT /secret/{category}/{name}`.
#[derive(Deserialize)]
pub struct StoreRequest {
    /// The secret itself.
    pub data: SecretData,
    /// Optional per-secret proxy settings (allowed origins, extra auth
    /// headers, response-body dropping). On store, absent means the default
    /// (nothing allowed); on update, absent keeps the stored policy.
    #[serde(default)]
    pub proxy_policy: Option<ProxyPolicy>,
}

#[derive(Serialize)]
pub struct AgentKeyInfo {
    pub name: String,
    pub categories: Vec<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub is_valid: bool,
}

/// Body of `POST /agents` under the legacy profile.
///
/// A legacy `allow_raw` field in the JSON is ignored (unknown fields are not
/// denied), so existing clients keep working.
#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    #[serde(default)]
    pub categories: Vec<String>,
}

/// Body of `POST /agents` under the custody profile.
///
/// The raw key is never returned over HTTP; it is written to `key_path`
/// (absolute, mode 0600, `O_EXCL`) and only a fingerprint comes back.
#[derive(Deserialize)]
pub struct CustodyCreateKeyRequest {
    /// Agent name.
    pub name: String,
    /// Category allow-list (empty = all).
    #[serde(default)]
    pub categories: Vec<String>,
    /// Absolute path the new key is written to; must not already exist.
    pub key_path: String,
}

#[derive(Deserialize)]
pub struct ResolveTextRequest {
    pub text: String,
}

#[derive(Serialize)]
pub struct ResolveTextResponse {
    pub text: String,
    pub substitutions: usize,
}

/// Body of `POST /resolve/proxy`.
///
/// Unknown fields are rejected so the policy layer in front of the handler,
/// which parses this same struct, can never see different fields than the
/// handler acts on (a decoy `category`/`name` pair is a hard error, not a
/// silently ignored key).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRequest {
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<String>,
    pub secret_category: String,
    pub secret_name: String,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub auth_scheme: Option<String>,
}

#[derive(Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Deserialize)]
pub struct RawRequest {
    pub category: String,
    pub name: String,
}
