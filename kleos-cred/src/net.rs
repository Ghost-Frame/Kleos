//! Network-safety helpers shared across the cred binaries.

use anyhow::Result;

/// Refuse to transmit a secret (the master key or owner key, sent as the credd
/// Bearer token) over a plaintext connection to a non-loopback host. Loopback
/// http and any https endpoint are allowed; remote http is rejected so the
/// credential cannot leak in cleartext to a remote credd.
///
/// The rule itself lives in `kleos_lib::net::guard_credd_transport` so the
/// custody thin client in `kleos-lib` and `kleos-cli` share one implementation.
pub fn guard_credd_transport(url: &str) -> Result<()> {
    kleos_lib::net::guard_credd_transport(url)
        .map_err(|e| anyhow::anyhow!("invalid credd URL `{url}`: {e}"))
}

#[cfg(test)]
mod tests {
    use super::guard_credd_transport;

    #[test]
    fn allows_loopback_http_and_https() {
        assert!(guard_credd_transport("http://127.0.0.1:4400").is_ok());
        assert!(guard_credd_transport("http://localhost:4400").is_ok());
        assert!(guard_credd_transport("http://[::1]:4400").is_ok());
        assert!(guard_credd_transport("https://credd.example.com").is_ok());
    }

    #[test]
    fn rejects_plaintext_non_loopback() {
        assert!(guard_credd_transport("http://credd.example.com").is_err());
        assert!(guard_credd_transport("http://10.0.0.5:4400").is_err());
    }
}
