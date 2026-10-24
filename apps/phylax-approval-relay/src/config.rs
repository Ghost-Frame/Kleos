//! Fail-closed runtime configuration for the approval relay.

use std::net::{IpAddr, SocketAddr};

/// Sole public origin authorized for exact-phone approval pickup.
///
/// Pinned at build time with `PHYLAX_APPROVAL_ORIGIN`. A build without it pins
/// the reserved example origin, so a production deployment that forgot to set
/// it refuses to start instead of accepting any origin.
pub const APPROVAL_PUBLIC_ORIGIN: &str = match option_env!("PHYLAX_APPROVAL_ORIGIN") {
    Some(origin) => origin,
    None => "https://approve.example.com",
};

/// Runtime configuration loaded only from process environment.
pub struct Config {
    /// Telegram bot token injected by cred.
    pub bot_token: String,
    /// Telegram chat allowed to receive notifications.
    pub chat_id: i64,
    /// Loopback or private-network Phylax origin.
    pub phylaxd_url: String,
    /// Secret authenticating Phylax to the private notification intake.
    pub notify_token: String,
    /// Private-network notification intake address.
    pub notify_bind: SocketAddr,
    /// Loopback public-API address served behind TLS ingress.
    pub phone_bind: SocketAddr,
    /// Public HTTPS origin used in Telegram links.
    pub public_base_url: String,
}

/// Validate and construct relay configuration.
impl Config {
    /// Load required values and reject unsafe public origins.
    pub fn from_env() -> anyhow::Result<Self> {
        let public_base_url = parse_public_origin(&std::env::var("PHONE_PUBLIC_BASE_URL")?)?;
        let phylaxd_url = parse_private_origin(&std::env::var("PHYLAXD_URL")?)?;
        let notify_token = parse_notify_token(&std::env::var("PHYLAX_NOTIFY_TOKEN")?)?;
        let notify_bind = parse_notify_bind(&std::env::var("NOTIFY_BIND")?)?;
        let phone_bind = parse_phone_bind(
            &std::env::var("PHONE_BIND").unwrap_or_else(|_| "127.0.0.1:8788".into()),
        )?;
        Ok(Self {
            bot_token: std::env::var("TELEGRAM_BOT_TOKEN")?,
            chat_id: std::env::var("TELEGRAM_CHAT_ID")?.parse()?,
            phylaxd_url,
            notify_token,
            notify_bind,
            phone_bind,
            public_base_url,
        })
    }
}

/// Parse the one authorized HTTPS origin and return its canonical serialization.
fn parse_public_origin(raw: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(raw)?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("PHONE_PUBLIC_BASE_URL must be an HTTPS origin");
    }
    let origin = parsed.origin().ascii_serialization();
    if origin != APPROVAL_PUBLIC_ORIGIN {
        anyhow::bail!("PHONE_PUBLIC_BASE_URL is not the authorized approval origin");
    }
    Ok(origin)
}

/// Parse a loopback or private-network HTTP origin for Phylax callbacks.
fn parse_private_origin(raw: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(raw)?;
    if parsed.scheme() != "http"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port().is_none()
    {
        anyhow::bail!("PHYLAXD_URL must be a private HTTP origin with an explicit port");
    }
    let host = parsed
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("PHYLAXD_URL must use a literal private IP address"))?;
    if !host.is_loopback() && !is_private_ipv4(host) {
        anyhow::bail!("PHYLAXD_URL must use loopback or a private IPv4 address");
    }
    Ok(parsed.origin().ascii_serialization())
}

/// Parse and constrain the notification listener to a private network address.
fn parse_notify_bind(raw: &str) -> anyhow::Result<SocketAddr> {
    let address: SocketAddr = raw.parse()?;
    if !is_private_ipv4(address.ip()) {
        anyhow::bail!("NOTIFY_BIND must use a private IPv4 address");
    }
    Ok(address)
}

/// Parse and constrain the public tunnel origin to loopback.
fn parse_phone_bind(raw: &str) -> anyhow::Result<SocketAddr> {
    let address: SocketAddr = raw.parse()?;
    if !address.ip().is_loopback() {
        anyhow::bail!("PHONE_BIND must use loopback");
    }
    Ok(address)
}

/// Validate one random 256-bit base64url notification credential.
fn parse_notify_token(raw: &str) -> anyhow::Result<String> {
    if raw.len() != 43
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        anyhow::bail!("PHYLAX_NOTIFY_TOKEN must be a 256-bit unpadded base64url value");
    }
    Ok(raw.to_owned())
}

/// Return whether an address is an RFC 1918 private IPv4 address.
///
/// Loopback, unspecified, link-local, public, and IPv6 addresses all fail, so
/// the intake can only listen on a private interface such as a VPN mesh.
fn is_private_ipv4(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(address) if address.is_private())
}

#[cfg(test)]
/// Configuration validation tests.
mod tests {
    use super::*;

    /// The exact production HTTPS origin normalizes without a trailing slash.
    #[test]
    fn public_origin_normalizes() {
        assert_eq!(
            parse_public_origin("https://approve.example.com/").unwrap(),
            APPROVAL_PUBLIC_ORIGIN
        );
    }

    /// Userinfo, paths, queries, fragments, and plaintext origins fail closed.
    #[test]
    fn public_origin_rejects_non_origins() {
        for value in [
            "http://approve.example.com",
            "https://user@approve.example.com",
            "https://approve.example.com/path",
            "https://approve.example.com/?query=1",
            "https://approve.example.com/#fragment",
            "https://approve.example.com:8443",
            "https://other.example.com",
        ] {
            assert!(parse_public_origin(value).is_err(), "accepted {value}");
        }
    }

    /// Phylax callbacks accept only explicit-port literal private origins.
    #[test]
    fn private_origin_is_network_constrained() {
        for value in [
            "http://127.0.0.1:4400",
            "http://[::1]:4400",
            "http://10.0.0.13:4400",
        ] {
            assert!(parse_private_origin(value).is_ok(), "rejected {value}");
        }
        for value in [
            "https://10.0.0.13:4400",
            "http://10.0.0.13",
            "http://10.0.0.13:4400/path",
            "http://localhost:4400",
            "http://100.64.0.13:4400",
            "http://203.0.113.2:4400",
        ] {
            assert!(parse_private_origin(value).is_err(), "accepted {value}");
        }
    }

    /// Listener validation separates the private intake and loopback API.
    #[test]
    fn listeners_are_network_constrained() {
        assert!(parse_notify_bind("10.0.0.1:8787").is_ok());
        assert!(parse_notify_bind("127.0.0.1:8787").is_err());
        assert!(parse_notify_bind("0.0.0.0:8787").is_err());
        assert!(parse_phone_bind("127.0.0.1:8788").is_ok());
        assert!(parse_phone_bind("[::1]:8788").is_ok());
        assert!(parse_phone_bind("10.0.0.1:8788").is_err());
        assert!(parse_phone_bind("0.0.0.0:8788").is_err());
    }

    /// Notification credentials require the canonical 256-bit base64url shape.
    #[test]
    fn notify_token_is_strictly_shaped() {
        assert!(parse_notify_token(&"a".repeat(43)).is_ok());
        assert!(parse_notify_token(&"a".repeat(42)).is_err());
        assert!(parse_notify_token(&format!("{}!", "a".repeat(42))).is_err());
    }
}
