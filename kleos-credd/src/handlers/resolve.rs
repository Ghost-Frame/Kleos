//! Three-tier resolve handlers.
//!
//! - Substitution: Replace `{{secret:category/name}}` placeholders in text
//! - Proxy: Inject credentials into HTTP request headers/body
//! - Raw: Return decrypted secret data directly

pub use super::types::{
    ProxyRequest, ProxyResponse, RawRequest, ResolveTextRequest, ResolveTextResponse,
};

use axum::{extract::State, Json};
use serde_json::{json, Value};

use kleos_cred::audit::{log_audit, AccessTier, AuditAction};
use kleos_cred::CredError;

use crate::auth::Auth;
use crate::handlers::AppError;
use crate::redact::{Redactor, MIN_SECRET_LEN};
use crate::state::AppState;

/// Response headers that must not be relayed from the upstream service back
/// to the proxy caller. They carry upstream auth/session state (cookies,
/// challenge headers) scoped to the credd<->upstream leg only.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &[
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
    "proxy-authenticate",
    "authorization",
    "proxy-authorization",
];

/// True when an upstream response header should be dropped before forwarding.
/// Comparison is case-insensitive; reqwest already lowercases header names.
fn is_stripped_response_header(name: &str) -> bool {
    STRIPPED_RESPONSE_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

/// Request headers the proxy must never forward verbatim from the caller. These
/// are hop-by-hop or message-framing headers (RFC 7230 SS6.1 plus length /
/// encoding controls); relaying caller-controlled values enables request
/// smuggling / desync and lets the caller override the `Host` of our pinned
/// connection. `host`, `content-length`, and the auth header are set by the
/// client or our own injection, never by the caller.
const STRIPPED_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "expect",
];

/// True when a caller-supplied request header must be dropped before the proxy
/// forwards it upstream. Case-insensitive.
fn is_stripped_request_header(name: &str) -> bool {
    STRIPPED_REQUEST_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

/// Pattern for secret placeholders: {{secret:category/name}} or {{secret:category/name.field}}
fn find_placeholders(text: &str) -> Vec<(usize, usize, String, String, Option<String>)> {
    let mut results = Vec::new();
    let mut start = 0;

    while let Some(begin) = text[start..].find("{{secret:") {
        let abs_begin = start + begin;
        if let Some(end_rel) = text[abs_begin..].find("}}") {
            let abs_end = abs_begin + end_rel + 2;
            let inner = &text[abs_begin + 9..abs_end - 2]; // Skip "{{secret:" and "}}"

            // Parse category/name or category/name.field
            if let Some(slash_pos) = inner.find('/') {
                let category = &inner[..slash_pos];
                let rest = &inner[slash_pos + 1..];

                let (name, field) = if let Some(dot_pos) = rest.find('.') {
                    (&rest[..dot_pos], Some(rest[dot_pos + 1..].to_string()))
                } else {
                    (rest, None)
                };

                results.push((
                    abs_begin,
                    abs_end,
                    category.to_string(),
                    name.to_string(),
                    field,
                ));
            }

            start = abs_end;
        } else {
            break;
        }
    }

    results
}

/// Resolve secret placeholders in text.
#[tracing::instrument(skip_all, fields(handler = "credd.resolve.text"))]
pub async fn resolve_text_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(body): Json<ResolveTextRequest>,
) -> Result<Json<ResolveTextResponse>, AppError> {
    // Text substitution returns plaintext secret bytes in the response body,
    // so it is master-only. Agents (and bootstrap agents) must use proxy
    // injection, which never returns the secret value to the caller. Under
    // the custody profile this route is not mounted at all.
    if !auth.is_master() {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Resolve,
            "",
            "",
            Some(AccessTier::Substitution),
            false,
        )
        .await?;
        return Err(CredError::PermissionDenied(
            "text resolve exposes plaintext and is master-only; use proxy resolve".into(),
        )
        .into());
    }

    let placeholders = find_placeholders(&body.text);
    let mut result = body.text.clone();
    let mut offset: isize = 0;
    let mut substitutions = 0;
    let mut denied_categories: Vec<String> = Vec::new();

    for (start, end, category, name, field) in placeholders {
        if !auth.can_access_category(&category) {
            log_audit(
                &state.db,
                auth.user_id(),
                auth.agent_name(),
                AuditAction::Resolve,
                &category,
                &name,
                Some(AccessTier::Substitution),
                false,
            )
            .await?;
            denied_categories.push(category);
            continue;
        }

        let secret_result =
            super::get_secret_with_fallback(&state, auth.user_id(), &category, &name).await;

        match secret_result {
            Ok((_row, data)) => {
                let value = match field {
                    Some(ref f) => data.get_field(f).unwrap_or_default(),
                    None => data.primary_value(),
                };

                let adj_start_signed = start as isize + offset;
                let adj_end_signed = end as isize + offset;
                if adj_start_signed < 0
                    || adj_end_signed < 0
                    || adj_end_signed as usize > result.len()
                    || !result.is_char_boundary(adj_start_signed as usize)
                    || !result.is_char_boundary(adj_end_signed as usize)
                {
                    continue;
                }
                let adj_start = adj_start_signed as usize;
                let adj_end = adj_end_signed as usize;
                result.replace_range(adj_start..adj_end, &value);
                offset += value.len() as isize - (end - start) as isize;
                substitutions += 1;

                log_audit(
                    &state.db,
                    auth.user_id(),
                    auth.agent_name(),
                    AuditAction::Resolve,
                    &category,
                    &name,
                    Some(AccessTier::Substitution),
                    true,
                )
                .await?;
            }
            Err(_) => {
                log_audit(
                    &state.db,
                    auth.user_id(),
                    auth.agent_name(),
                    AuditAction::Resolve,
                    &category,
                    &name,
                    Some(AccessTier::Substitution),
                    false,
                )
                .await?;
            }
        }
    }

    // Fail the entire request if any placeholder was denied -- never return
    // partially substituted text with unresolved placeholders visible.
    if !denied_categories.is_empty() {
        denied_categories.sort();
        denied_categories.dedup();
        return Err(kleos_cred::CredError::PermissionDenied(format!(
            "access denied for categories: {}",
            denied_categories.join(", ")
        ))
        .into());
    }

    Ok(Json(ResolveTextResponse {
        text: result,
        substitutions,
    }))
}

/// True when `host` matches an allowlist `pattern`: `*` (any), `*.suffix`
/// (the suffix itself or any subdomain of it), or an exact match.
fn proxy_domain_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{}", suffix))
    } else {
        host == pattern
    }
}

/// F09: decide whether the legacy-profile proxy may forward a secret to `host`
/// for `category`.
///
/// Pure (no env, no I/O) so the deny-by-default policy is unit-testable without
/// standing up an `AppState`. Returns `Ok(())` to allow, `Err(reason)` to deny.
///
/// - With an allowlist: permit only when a pattern under `category` (or the
///   wildcard `"*"` category) matches `host`. A category with no entry denies.
/// - Without an allowlist: always deny. There is no environment opt-out; to
///   forward anywhere an operator must write an explicit `"*"` entry.
fn proxy_gate_decision(
    allowlist: Option<&crate::state::ProxyDomainAllowlist>,
    category: &str,
    host: &str,
) -> std::result::Result<(), String> {
    match allowlist {
        Some(allowlist) => {
            let allowed_domains = allowlist.get(category).or_else(|| allowlist.get("*"));
            let permitted = match allowed_domains {
                Some(domains) => domains
                    .iter()
                    .any(|pattern| proxy_domain_matches(pattern, host)),
                None => false,
            };
            if permitted {
                Ok(())
            } else {
                Err(format!(
                    "proxy target domain '{}' not in allowlist for category '{}'",
                    host, category
                ))
            }
        }
        None => Err(
            "proxy denied: no proxy domain allowlist configured (set a per-category allowlist)"
                .to_string(),
        ),
    }
}

/// The `(scheme, host, effective port)` triple a proxy target resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetOrigin {
    /// Lowercase scheme, `http` or `https`.
    scheme: String,
    /// Lowercase host as the `url` crate normalizes it (IPv6 stays bracketed).
    host: String,
    /// Explicit port, or the scheme default.
    port: u16,
}

/// Extract the origin of a proxy target. Only `http`/`https` URLs with a host
/// are proxyable.
fn target_origin(url: &url::Url) -> std::result::Result<TargetOrigin, CredError> {
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(CredError::InvalidInput(
            "proxy target must use http or https".into(),
        ));
    }
    let host = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| CredError::InvalidInput("proxy target has no host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| CredError::InvalidInput("proxy target has no usable port".into()))?;
    Ok(TargetOrigin { scheme, host, port })
}

/// True when the URL's host is a loopback IP literal (used only by the test
/// seam that lets integration tests reach a local upstream).
fn is_loopback_literal(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Copy upstream response headers for the caller, dropping upstream
/// auth/session headers and any header whose name carries a secret, and
/// redacting each remaining value on its own.
fn collect_response_headers(
    headers: &reqwest::header::HeaderMap,
    redactor: &Redactor,
) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for (name, value) in headers.iter() {
        if is_stripped_response_header(name.as_str()) {
            continue;
        }
        if redactor.contains_secret(name.as_str().as_bytes()) {
            continue;
        }
        if let Ok(text) = value.to_str() {
            let redacted = redactor.redact_slice(text.as_bytes());
            out.insert(
                name.to_string(),
                String::from_utf8_lossy(&redacted).into_owned(),
            );
        }
    }
    out
}

/// Proxy HTTP request with injected credentials.
///
/// The secret is injected into one request header, the upstream response is
/// scanned for it in every known encoding (headers value by value, body
/// streamed), and every match is replaced before anything is returned.
///
/// Gates, in order:
/// - legacy profile: the per-category domain allowlist (deny by default);
/// - category access for the caller;
/// - custody profile: the target `(scheme, host, port)` must equal one of the
///   secret's `allowed_origins` (403 before any DNS lookup or connection), and
///   secrets under 3 bytes are refused;
/// - the auth header must be `Authorization`, `X-Api-Key`, or one of the
///   secret's `extra_auth_headers` (400 otherwise), under both profiles;
/// - SSRF validation (loopback, private, link-local, cloud metadata) with the
///   resolved address pinned for the connection.
#[tracing::instrument(skip_all, fields(handler = "credd.resolve.proxy"))]
pub async fn proxy_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, AppError> {
    let custody = state.run_profile.is_custody();
    let parsed = url::Url::parse(&req.url)
        .map_err(|e| CredError::InvalidInput(format!("invalid proxy URL: {}", e)))?;
    let target = target_origin(&parsed)?;

    // SECURITY (H4) + F09: legacy per-category domain binding, deny by default.
    // It needs only the URL, so it runs before the secret is touched. Custody
    // replaces it with the per-secret origin check below.
    if !custody {
        if let Err(reason) = proxy_gate_decision(
            state.proxy_domain_allowlist.as_deref(),
            &req.secret_category,
            &target.host,
        ) {
            return Err(CredError::PermissionDenied(reason).into());
        }
    }

    if !auth.can_access_category(&req.secret_category) {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Proxy,
            &req.secret_category,
            &req.secret_name,
            Some(AccessTier::Proxy),
            false,
        )
        .await?;
        return Err(CredError::PermissionDenied(format!(
            "no access to category: {}",
            req.secret_category
        ))
        .into());
    }

    let (_row, data, policy) = super::get_secret_and_policy_with_fallback(
        &state,
        auth.user_id(),
        &req.secret_category,
        &req.secret_name,
    )
    .await?;

    // SECURITY: custody origin pinning. The secret may only be sent to an
    // origin its owner listed; checked before DNS resolution or any connection.
    if custody && !policy.origin_allowed(&target.scheme, &target.host, target.port) {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Proxy,
            &req.secret_category,
            &req.secret_name,
            Some(AccessTier::Proxy),
            false,
        )
        .await?;
        return Err(CredError::PermissionDenied(format!(
            "origin {}://{}:{} is not allowed for this secret",
            target.scheme, target.host, target.port
        ))
        .into());
    }

    let secret_value = data.primary_value();
    if custody && secret_value.len() < MIN_SECRET_LEN {
        return Err(CredError::InvalidInput(
            "secret is too short to proxy safely (response redaction needs 3+ bytes)".into(),
        )
        .into());
    }

    let method = req
        .method
        .as_deref()
        .unwrap_or("GET")
        .parse::<reqwest::Method>()
        .map_err(|e| CredError::InvalidInput(format!("invalid method: {}", e)))?;

    // SECURITY: the secret may only be injected into an allowlisted header, so
    // a caller cannot aim it at a header the upstream echoes or logs verbatim.
    let header_name = req
        .auth_header
        .clone()
        .unwrap_or_else(|| "Authorization".to_string());
    if !policy.auth_header_allowed(&header_name) {
        return Err(CredError::InvalidInput(format!(
            "auth_header '{}' is not allowed for this secret",
            header_name
        ))
        .into());
    }
    let header_value = match req.auth_scheme.as_deref() {
        Some("") => secret_value.clone(),
        Some(scheme) => format!("{} {}", scheme.trim(), secret_value),
        None => format!("Bearer {}", secret_value),
    };

    // Everything the upstream could echo back: the injected header value, the
    // bare secret, and the secret without surrounding whitespace.
    // Values under 3 bytes cannot be redacted safely; custody already refused
    // such a secret above, and the legacy profile still redacts the longer
    // header value that wraps it.
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    for candidate in [
        header_value.as_str(),
        secret_value.as_str(),
        secret_value.trim(),
    ] {
        if candidate.len() >= MIN_SECRET_LEN && !secrets.iter().any(|s| s == candidate.as_bytes()) {
            secrets.push(candidate.as_bytes().to_vec());
        }
    }
    let redactor = Redactor::new(&secrets)
        .map_err(|e| CredError::InvalidInput(format!("cannot build response redactor: {}", e)))?;
    drop(secrets);

    let injected_name = reqwest::header::HeaderName::from_bytes(header_name.as_bytes())
        .map_err(|_| CredError::InvalidInput("auth_header is not a valid header name".into()))?;
    let mut injected_value = reqwest::header::HeaderValue::from_str(&header_value)
        .map_err(|_| CredError::InvalidInput("secret cannot be sent as a header value".into()))?;
    injected_value.set_sensitive(true);

    // SECURITY (SSRF-DNS): SSRF validation -- reject requests targeting
    // loopback, private, link-local, and cloud metadata addresses. Resolves
    // DNS so domains pointing at private IPs are also caught. The proxy
    // injects secret headers so an unvalidated URL would let an attacker
    // exfiltrate credentials to internal services.
    // Capture the address the hostname validated to. reqwest re-resolves DNS
    // at request time, so without pinning an attacker could rebind the host to
    // an internal IP between this check and the request (TOCTOU rebinding). We
    // pin reqwest's resolver to this IP when building the client below, keeping
    // the original hostname for TLS SNI and certificate validation. `None`
    // means the URL already held a literal (already-validated) IP.
    let pinned_ip = if state.proxy_allow_loopback && is_loopback_literal(&parsed) {
        None
    } else {
        kleos_lib::webhooks::resolve_and_validate_url(&req.url)
            .await
            .map_err(|e| CredError::InvalidInput(format!("proxy target URL rejected: {}", e)))?
    };

    // SECURITY (SEC-H2): disable redirect following to prevent Authorization
    // header leakage to attacker-controlled hosts via redirect chains.
    let mut client_builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());

    // SECURITY (SSRF-DNS): pin the validated IP so reqwest does not re-resolve
    // the hostname and cannot be steered to an internal address by a rebind.
    if let Some(ip) = pinned_ip {
        client_builder =
            client_builder.resolve(&target.host, std::net::SocketAddr::new(ip, target.port));
    }

    let client = client_builder
        .build()
        .map_err(|e| CredError::InvalidInput(format!("client build failed: {}", e)))?;
    let mut builder = client.request(method, parsed.as_str());

    // SECURITY: forward only safe caller headers. Hop-by-hop and framing
    // headers are dropped to prevent request smuggling/desync and Host override
    // of the pinned connection. A caller header with the injected header's name
    // is dropped so the upstream never sees two competing credentials, and the
    // caller cannot choose the response encoding.
    if let Some(headers) = &req.headers {
        for (name, value) in headers {
            if is_stripped_request_header(name)
                || name.eq_ignore_ascii_case(&header_name)
                || name.eq_ignore_ascii_case("accept-encoding")
            {
                continue;
            }
            builder = builder.header(name, value);
        }
    }
    // SECURITY: ask for an unencoded response so the redactor sees plaintext.
    builder = builder.header(reqwest::header::ACCEPT_ENCODING, "identity");
    builder = builder.header(injected_name, injected_value);

    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    // SECURITY: cap response body to 10 MiB to prevent upstream from OOM-ing credd.
    const MAX_PROXY_RESPONSE: usize = 10 * 1024 * 1024;

    let response = builder
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| CredError::InvalidInput(format!("proxy request failed: {}", e)))?;

    let status = response.status().as_u16();

    // SECURITY: reqwest strips Content-Encoding after decoding gzip/brotli. Any
    // encoding still present is one we cannot scan, so fail closed rather than
    // relay bytes the redactor could not read.
    if let Some(encoding) = response.headers().get(reqwest::header::CONTENT_ENCODING) {
        let identity = encoding
            .to_str()
            .map(|v| v.trim().eq_ignore_ascii_case("identity"))
            .unwrap_or(false);
        if !identity {
            return Err(CredError::InvalidInput(
                "upstream used a content-encoding the proxy cannot inspect".into(),
            )
            .into());
        }
    }

    let mut headers = collect_response_headers(response.headers(), &redactor);

    // Check Content-Length hint before reading body.
    if let Some(cl) = response.content_length() {
        if cl as usize > MAX_PROXY_RESPONSE {
            return Err(CredError::InvalidInput(format!(
                "proxy response too large: {} bytes (max {})",
                cl, MAX_PROXY_RESPONSE
            ))
            .into());
        }
    }

    let body = if policy.drop_response_body {
        // The owner asked for status and headers only; the body is never read.
        headers.remove("content-encoding");
        headers.remove("transfer-encoding");
        headers.insert("content-length".to_string(), "0".to_string());
        String::new()
    } else {
        // Stream the body and abort as soon as the cap is crossed: the
        // Content-Length hint above only protects against honest servers, and a
        // chunked response without one would otherwise buffer fully before the
        // size check ran. Each chunk passes through the redactor.
        use futures::StreamExt;
        let mut redactor = redactor;
        let mut stream = response.bytes_stream();
        let mut read = 0usize;
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                CredError::InvalidInput(format!("proxy response read failed: {}", e))
            })?;
            read += chunk.len();
            if read > MAX_PROXY_RESPONSE {
                return Err(CredError::InvalidInput(format!(
                    "proxy response body too large: exceeds max {} bytes",
                    MAX_PROXY_RESPONSE
                ))
                .into());
            }
            buf.extend_from_slice(&redactor.feed(&chunk));
        }
        buf.extend_from_slice(&redactor.finish());
        // The relayed body is the redacted one, so any upstream length no
        // longer describes it.
        if headers.contains_key("content-length") {
            headers.insert("content-length".to_string(), buf.len().to_string());
        }
        String::from_utf8_lossy(&buf).into_owned()
    };

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Proxy,
        &req.secret_category,
        &req.secret_name,
        Some(AccessTier::Proxy),
        true,
    )
    .await?;

    Ok(Json(ProxyResponse {
        status,
        headers,
        body,
    }))
}

/// Raw secret access endpoint (returns full secret data).
#[tracing::instrument(skip_all, fields(handler = "credd.resolve.raw"))]
pub async fn raw_handler(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<RawRequest>,
) -> Result<Json<Value>, AppError> {
    // Raw retrieval is master-only; not mounted under the custody profile.
    if !auth.is_master() {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Get,
            &req.category,
            &req.name,
            Some(AccessTier::Raw),
            false,
        )
        .await?;
        return Err(CredError::PermissionDenied("raw access not permitted".into()).into());
    }

    if !auth.can_access_category(&req.category) {
        log_audit(
            &state.db,
            auth.user_id(),
            auth.agent_name(),
            AuditAction::Get,
            &req.category,
            &req.name,
            Some(AccessTier::Raw),
            false,
        )
        .await?;
        return Err(CredError::PermissionDenied(format!(
            "no access to category: {}",
            req.category
        ))
        .into());
    }

    let (_row, data) =
        super::get_secret_with_fallback(&state, auth.user_id(), &req.category, &req.name).await?;

    log_audit(
        &state.db,
        auth.user_id(),
        auth.agent_name(),
        AuditAction::Get,
        &req.category,
        &req.name,
        Some(AccessTier::Raw),
        true,
    )
    .await?;

    Ok(Json(json!({
        "category": req.category,
        "name": req.name,
        "value": data,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_placeholders() {
        let text = "key={{secret:aws/api-key}} user={{secret:db/creds.username}}";
        let placeholders = find_placeholders(text);

        assert_eq!(placeholders.len(), 2);
        assert_eq!(placeholders[0].2, "aws");
        assert_eq!(placeholders[0].3, "api-key");
        assert_eq!(placeholders[0].4, None);

        assert_eq!(placeholders[1].2, "db");
        assert_eq!(placeholders[1].3, "creds");
        assert_eq!(placeholders[1].4, Some("username".to_string()));
    }

    use std::collections::HashMap;

    /// F09: with no allowlist the proxy denies, and nothing in the environment
    /// can change that.
    #[test]
    fn proxy_gate_denies_without_allowlist() {
        let decision = proxy_gate_decision(None, "aws", "example.com");
        assert!(decision.is_err(), "no allowlist must deny");
        assert!(decision
            .unwrap_err()
            .contains("no proxy domain allowlist configured"));
    }

    /// An allowlist permits only matching hosts (exact, *. subdomain, * wildcard)
    /// and denies everything else.
    #[test]
    fn proxy_gate_enforces_allowlist_patterns() {
        let mut allowlist: HashMap<String, Vec<String>> = HashMap::new();
        allowlist.insert("aws".to_string(), vec!["*.amazonaws.com".to_string()]);
        allowlist.insert("github".to_string(), vec!["api.github.com".to_string()]);
        allowlist.insert("any".to_string(), vec!["*".to_string()]);

        // Subdomain wildcard: suffix itself and any subdomain match; siblings do not.
        assert!(proxy_gate_decision(Some(&allowlist), "aws", "amazonaws.com").is_ok());
        assert!(proxy_gate_decision(Some(&allowlist), "aws", "s3.amazonaws.com").is_ok());
        assert!(proxy_gate_decision(Some(&allowlist), "aws", "evil.com").is_err());
        // Prefix-spoofing must NOT satisfy the suffix wildcard (the ends_with
        // check requires a leading dot, so "evil-amazonaws.com" is rejected).
        assert!(proxy_gate_decision(Some(&allowlist), "aws", "evil-amazonaws.com").is_err());
        // Patterns are lowercased at load (see state.rs); the helper compares a
        // lowercased host against lowercased patterns.
        assert!(proxy_gate_decision(
            Some(&allowlist),
            "aws",
            "S3.AMAZONAWS.COM".to_lowercase().as_str()
        )
        .is_ok());

        // Exact match only.
        assert!(proxy_gate_decision(Some(&allowlist), "github", "api.github.com").is_ok());
        assert!(proxy_gate_decision(Some(&allowlist), "github", "github.com").is_err());

        // "*" pattern allows any host for that category.
        assert!(proxy_gate_decision(Some(&allowlist), "any", "whatever.example").is_ok());

        // A category absent from the allowlist (and no "*" category entry) denies.
        assert!(proxy_gate_decision(Some(&allowlist), "unknown", "api.github.com").is_err());
    }

    /// The origin triple uses lowercase scheme/host and the scheme's default
    /// port, and rejects non-http schemes.
    #[test]
    fn target_origin_normalizes_and_rejects_other_schemes() {
        let origin = |raw: &str| target_origin(&url::Url::parse(raw).unwrap());
        assert_eq!(
            origin("HTTPS://API.Example.COM/v1?x=1").unwrap(),
            TargetOrigin {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443
            }
        );
        assert_eq!(origin("http://example.com/").unwrap().port, 80);
        assert_eq!(origin("https://example.com:8443/").unwrap().port, 8443);
        // Userinfo cannot smuggle a different host into the comparison.
        assert_eq!(
            origin("https://api.example.com@evil.test/").unwrap().host,
            "evil.test"
        );
        assert_eq!(origin("http://[::1]:9/").unwrap().host, "[::1]");
        assert!(origin("ftp://example.com/").is_err());
        assert!(origin("file:///etc/passwd").is_err());
    }

    /// Only loopback IP literals count for the test seam.
    #[test]
    fn loopback_literal_detection() {
        let check = |raw: &str| is_loopback_literal(&url::Url::parse(raw).unwrap());
        assert!(check("http://127.0.0.1:9/"));
        assert!(check("http://[::1]:9/"));
        assert!(!check("http://localhost:9/"));
        assert!(!check("http://10.0.0.1/"));
        assert!(!check("https://example.com/"));
    }

    /// Response headers: upstream auth/session headers are dropped, secrets in
    /// a value are redacted per value, and a header named after the secret is
    /// dropped.
    #[test]
    fn response_headers_are_redacted_per_value() {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
        let redactor = Redactor::new(&[b"sk-live-abcdef".to_vec()]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-echo", HeaderValue::from_static("key=sk-live-abcdef;ok"));
        headers.insert("x-plain", HeaderValue::from_static("fine"));
        headers.insert(
            "set-cookie",
            HeaderValue::from_static("s=sk-live-abcdef; Path=/"),
        );
        headers.insert(
            HeaderName::from_static("sk-live-abcdef"),
            HeaderValue::from_static("name-leak"),
        );
        let out = collect_response_headers(&headers, &redactor);
        assert_eq!(
            out.get("x-echo").map(String::as_str),
            Some("key=[REDACTED];ok")
        );
        assert_eq!(out.get("x-plain").map(String::as_str), Some("fine"));
        assert!(!out.contains_key("set-cookie"));
        assert!(!out.contains_key("sk-live-abcdef"));
    }
}
