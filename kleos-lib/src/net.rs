//! Outbound network helpers. Centralised URL validation so tainted
//! environment/configuration values cannot target arbitrary hosts, plus
//! a hardened reqwest client builder used for every outbound call.

use crate::webhooks::{is_ipv4_denied, is_ipv6_denied};
use crate::EngError;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::Duration;
use url::Url;

/// Cached startup-time read of `KLEOS_NET_ALLOW_PRIVATE`.
/// Prevents an attacker from toggling the env var at runtime to
/// bypass SSRF protections after process start.
pub(crate) fn allow_private_networks() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| std::env::var("KLEOS_NET_ALLOW_PRIVATE").as_deref() == Ok("1"))
}

/// Link-local / cloud-metadata IPv4 ranges that stay denied even when
/// `KLEOS_NET_ALLOW_PRIVATE=1` is set. Operators enable that flag to reach
/// RFC1918 mesh hosts (e.g. a WireGuard 10.x peer); that opt-in must never
/// also open the cloud metadata endpoint (169.254.169.254) or the broader
/// 169.254.0.0/16 link-local block, which are pure SSRF escalation targets.
fn is_always_denied_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_link_local() || (o[0] == 169 && o[1] == 254)
}

/// IPv6 companion to [`is_always_denied_ipv4`]: link-local fe80::/10, the AWS
/// IMDSv2 alias fd00:ec2::254, and any mapped/compat IPv4 that is itself
/// always-denied. Stays denied regardless of the private-network opt-in.
fn is_always_denied_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Link-local fe80::/10.
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // AWS IMDSv2 alternative metadata address.
    if *ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254) {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped().or_else(|| ip.to_ipv4()) {
        return is_always_denied_ipv4(&v4);
    }
    false
}

/// Whether a literal IPv4 target is denied for outbound requests, given the
/// private-network opt-in state. Metadata/link-local is always denied; the
/// rest of the deny list (RFC1918, CGNAT, etc.) is suppressed under the flag.
fn ipv4_outbound_denied(ip: &Ipv4Addr, allow_private: bool) -> bool {
    is_always_denied_ipv4(ip) || (!allow_private && is_ipv4_denied(ip))
}

/// IPv6 companion to [`ipv4_outbound_denied`].
fn ipv6_outbound_denied(ip: &Ipv6Addr, allow_private: bool) -> bool {
    is_always_denied_ipv6(ip) || (!allow_private && is_ipv6_denied(ip))
}

/// R7-002: default response size cap for outbound HTTP responses.
/// Call sites with different needs should pass their own value to
/// [`response_within_limit`].
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// R7-002: hardened reqwest client builder. Applies a 5s connect timeout and
/// revalidates every redirect hop through [`validate_outbound_url`] so an open
/// redirect on an allowed host cannot bounce the request into loopback /
/// RFC1918 / link-local / metadata targets (the previous `limited(1)` policy
/// followed one hop with no revalidation). The chain is capped at 5 hops to
/// bound redirect loops. Call sites add their own overall `.timeout(...)`
/// appropriate to the workload before calling `.build()`.
pub fn safe_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            // Stop (return the 3xx as-is) rather than follow when the chain is
            // too long or the next hop fails the outbound deny rules.
            if attempt.previous().len() >= 5 {
                return attempt.stop();
            }
            match validate_outbound_url(attempt.url().as_str()) {
                Ok(_) => attempt.follow(),
                Err(_) => attempt.stop(),
            }
        }))
}

/// R7-002: returns `false` when the response declares a Content-Length larger
/// than `max_bytes`. When the header is missing we return `true` and leave the
/// caller to cap via streaming; reqwest's own timeouts still bound the read.
pub fn response_within_limit(resp: &reqwest::Response, max_bytes: u64) -> bool {
    match resp.content_length() {
        Some(len) => len <= max_bytes,
        None => true,
    }
}

/// Validate a URL intended for an outbound HTTP request. Rejects:
///   - non-http(s) schemes,
///   - URLs with embedded credentials (userinfo),
///   - URLs missing a host,
///   - literal IP addresses inside any deny-listed range
///     (loopback / RFC1918 / CGNAT / link-local / IPv6 ULA / 0.0.0.0/8),
///   - cloud metadata hostnames (AWS link-local, GCP metadata.google.internal).
///
/// This is a **synchronous** check on literal hostnames and IPs only. For
/// delivery-time DNS resolution + per-address allowlist validation, use
/// `webhooks::resolve_and_validate_url`.
///
/// CodeQL recognises `url::Url::parse` + scheme check as a request-forgery
/// sanitiser, so routing outbound calls through this helper clears the
/// rust/request-forgery alert for that call site.
pub fn validate_outbound_url(raw: &str) -> Result<Url, EngError> {
    let parsed = Url::parse(raw)
        .map_err(|e| EngError::InvalidInput(format!("invalid url '{}': {}", raw, e)))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(EngError::InvalidInput(format!(
                "url '{}' uses disallowed scheme '{}' (expected http or https)",
                raw, other
            )));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(EngError::InvalidInput(format!(
            "url '{}' must not embed credentials",
            raw
        )));
    }
    let host = parsed
        .host()
        .ok_or_else(|| EngError::InvalidInput(format!("url '{}' has no host", raw)))?;
    let allow_private = allow_private_networks();
    match host {
        url::Host::Domain(name) => {
            let lower = name.to_ascii_lowercase();
            if !allow_private
                && (lower == "localhost"
                    || lower.ends_with(".localhost")
                    || lower == "localhost.localdomain")
            {
                return Err(EngError::InvalidInput(format!(
                    "url '{}' resolves to loopback",
                    raw
                )));
            }
            if lower == "metadata.google.internal"
                || lower == "metadata"
                || lower == "metadata.goog"
            {
                return Err(EngError::InvalidInput(format!(
                    "url '{}' targets a cloud metadata endpoint",
                    raw
                )));
            }
        }
        url::Host::Ipv4(ip) => {
            if ipv4_outbound_denied(&ip, allow_private) {
                return Err(EngError::InvalidInput(format!(
                    "url '{}' targets disallowed IPv4 range",
                    raw
                )));
            }
        }
        url::Host::Ipv6(ip) => {
            if ipv6_outbound_denied(&ip, allow_private) {
                return Err(EngError::InvalidInput(format!(
                    "url '{}' targets disallowed IPv6 range",
                    raw
                )));
            }
        }
    }
    Ok(parsed)
}

/// Refuse to transmit a Bearer credential (master key, owner key, or agent
/// key) over plaintext http to a non-loopback host. `https` and loopback
/// `http` are allowed; remote `http` is rejected so a token cannot leak in
/// cleartext to a remote service whose URL came from config/env.
///
/// This complements [`validate_outbound_url`], which guards SSRF target ranges
/// but still permits public plaintext http: any caller that attaches a Bearer
/// must additionally require transport confidentiality.
pub fn guard_bearer_transport(url: &str) -> Result<(), EngError> {
    let parsed = Url::parse(url)
        .map_err(|e| EngError::InvalidInput(format!("invalid url '{}': {}", url, e)))?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    let host = parsed.host_str().unwrap_or("");
    // host_str() brackets an IPv6 literal ("[::1]"); strip them so it parses as an IpAddr.
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if is_loopback {
        return Ok(());
    }
    Err(EngError::InvalidInput(format!(
        "refusing to send a bearer credential over plaintext http to non-loopback host '{}'; \
         use https or a loopback address",
        host
    )))
}

/// Credential-daemon spelling of [`guard_bearer_transport`].
///
/// `kleos-cred` and the custody thin client share one transport rule: an agent
/// or master bearer may only travel over https or to a loopback host. Keeping
/// the name `guard_credd_transport` here lets `kleos-lib` and `kleos-cli`
/// (which cannot depend on `kleos-cred`) call the same guard the `cred` binary
/// uses, and `kleos_cred::net::guard_credd_transport` delegates to it.
pub fn guard_credd_transport(url: &str) -> Result<(), EngError> {
    guard_bearer_transport(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_bearer_transport_allows_https_and_loopback_only() {
        // https to any host is fine (transport is encrypted).
        assert!(guard_bearer_transport("https://vault.example.com/list").is_ok());
        // loopback http is fine (never leaves the host).
        assert!(guard_bearer_transport("http://127.0.0.1:4200/list").is_ok());
        assert!(guard_bearer_transport("http://localhost:4200/list").is_ok());
        assert!(guard_bearer_transport("http://[::1]:4200/list").is_ok());
        // remote plaintext http must be rejected -- the bearer would leak.
        assert!(guard_bearer_transport("http://vault.example.com/list").is_err());
        assert!(guard_bearer_transport("http://10.0.0.5:4200/list").is_err());
    }

    #[test]
    fn accepts_http_and_https() {
        // Loopback (127.0.0.1) is now correctly rejected by the deny list;
        // accepts public hosts on either scheme.
        assert!(validate_outbound_url("http://203.0.113.1:4200/x").is_ok());
        assert!(validate_outbound_url("https://example.com/y").is_ok());
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(validate_outbound_url("file:///etc/passwd").is_err());
        assert!(validate_outbound_url("ftp://example.com").is_err());
        assert!(validate_outbound_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn rejects_userinfo() {
        assert!(validate_outbound_url("http://user:pass@example.com").is_err());
        assert!(validate_outbound_url("http://user@example.com").is_err());
    }

    #[test]
    fn rejects_bogus_input() {
        assert!(validate_outbound_url("not a url").is_err());
        assert!(validate_outbound_url("http://").is_err());
    }

    #[test]
    fn rejects_aws_metadata_ip() {
        assert!(
            validate_outbound_url("http://169.254.169.254/latest/meta-data/").is_err(),
            "AWS instance metadata IPv4 must be denied"
        );
    }

    #[test]
    fn rejects_gcp_metadata_host() {
        assert!(
            validate_outbound_url("http://metadata.google.internal/computeMetadata/v1/").is_err(),
            "GCP metadata hostname must be denied"
        );
    }

    #[test]
    fn rejects_rfc1918_private_ipv4() {
        assert!(validate_outbound_url("http://10.0.0.1/x").is_err());
        assert!(validate_outbound_url("http://172.16.0.1/x").is_err());
        assert!(validate_outbound_url("http://192.168.1.1/x").is_err());
    }

    #[test]
    fn rejects_loopback_hostname() {
        assert!(validate_outbound_url("http://localhost/x").is_err());
        assert!(validate_outbound_url("http://app.localhost/x").is_err());
    }

    #[test]
    fn rejects_ipv6_ula() {
        assert!(validate_outbound_url("http://[fc00::1]/x").is_err());
    }

    #[test]
    fn rejects_cgnat_range() {
        assert!(validate_outbound_url("http://100.64.0.1/x").is_err());
    }

    #[test]
    fn accepts_public_ip() {
        assert!(validate_outbound_url("http://8.8.8.8/x").is_ok());
        assert!(validate_outbound_url("https://1.1.1.1/").is_ok());
    }

    #[test]
    fn metadata_and_link_local_denied_even_under_private_override() {
        // KLEOS_NET_ALLOW_PRIVATE=1 opens RFC1918 for mesh access but must NOT
        // open cloud metadata / link-local -- that is pure SSRF escalation.
        // Test the pure helpers directly so the result is independent of the
        // process-wide cached env flag.
        let meta_v4: Ipv4Addr = "169.254.169.254".parse().unwrap();
        let link_v4: Ipv4Addr = "169.254.10.1".parse().unwrap();
        assert!(
            ipv4_outbound_denied(&meta_v4, true),
            "AWS metadata stays denied under flag"
        );
        assert!(
            ipv4_outbound_denied(&link_v4, true),
            "link-local stays denied under flag"
        );

        // RFC1918 IS permitted under the flag (WireGuard mesh peer).
        let mesh: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert!(
            !ipv4_outbound_denied(&mesh, true),
            "mesh RFC1918 allowed under flag"
        );
        assert!(
            ipv4_outbound_denied(&mesh, false),
            "mesh RFC1918 denied without flag"
        );

        // IPv6 link-local and the AWS IMDSv2 alias stay denied under the flag.
        let ll_v6: Ipv6Addr = "fe80::1".parse().unwrap();
        let imds_v6: Ipv6Addr = "fd00:ec2::254".parse().unwrap();
        assert!(
            ipv6_outbound_denied(&ll_v6, true),
            "IPv6 link-local stays denied under flag"
        );
        assert!(
            ipv6_outbound_denied(&imds_v6, true),
            "AWS IMDSv2 alias stays denied under flag"
        );
    }
}
