//! Best-effort out-of-band approval notification.
//!
//! When an M3 approval is raised, phylaxd can POST a summary of it -- plus a
//! single-use capability token -- to an external notifier so a human can be
//! prompted to decide out of band. This is disabled (a no-op) unless
//! `PHYLAX_NOTIFY_URL` is set, carries no transport-specific logic, and never
//! fails the calling request: a notifier that is down or slow must not block or
//! break an approval, which can still be decided through the authenticated
//! `PUT /phylax/approvals/{id}` path.

use serde_json::json;
use std::net::IpAddr;

use crate::models::approval::PhoneApprovalBinding;

/// Fire-and-forget POST of an approval to the configured notifier. No-op unless
/// `PHYLAX_NOTIFY_URL` is set. Never returns an error to the caller.
#[allow(clippy::too_many_arguments)]
pub async fn notify_approval(
    approval_id: i64,
    action: &str,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    expires_at: &str,
    raw_token: &str,
) {
    send_notification(
        approval_id,
        action,
        agent_name,
        category,
        secret_name,
        expires_at,
        raw_token,
        None,
    )
    .await;
}

/// Send a phone-required notification containing only public request binding data.
#[allow(clippy::too_many_arguments)]
pub async fn notify_phone_approval(
    approval_id: i64,
    action: &str,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    expires_at: &str,
    raw_token: &str,
    binding: &PhoneApprovalBinding,
) {
    send_notification(
        approval_id,
        action,
        agent_name,
        category,
        secret_name,
        expires_at,
        raw_token,
        Some(binding),
    )
    .await;
}

/// POST one legacy or exact-phone notification without affecting authorization state.
#[allow(clippy::too_many_arguments)]
async fn send_notification(
    approval_id: i64,
    action: &str,
    agent_name: &str,
    category: &str,
    secret_name: &str,
    expires_at: &str,
    raw_token: &str,
    phone: Option<&PhoneApprovalBinding>,
) {
    let Ok(raw_url) = std::env::var("PHYLAX_NOTIFY_URL") else {
        return;
    };
    let Ok(url) = parse_notify_url(&raw_url) else {
        tracing::warn!(
            "approval notify disabled: PHYLAX_NOTIFY_URL is not a private-network address"
        );
        return;
    };
    let Ok(token) = std::env::var("PHYLAX_NOTIFY_TOKEN") else {
        tracing::warn!("approval notify disabled: PHYLAX_NOTIFY_TOKEN is missing");
        return;
    };
    if !valid_notify_token(&token) {
        tracing::warn!("approval notify disabled: PHYLAX_NOTIFY_TOKEN is malformed");
        return;
    }
    let mut body = json!({
        "approval_id": approval_id,
        "action": action,
        "agent_name": agent_name,
        "category": category,
        "secret_name": secret_name,
        "expires_at": expires_at,
        "decide_token": raw_token,
    });
    if let Some(binding) = phone {
        body["phone"] = json!({
            "version": crate::models::phone_approval::PHONE_APPROVAL_VERSION,
            "device_id": binding.device_id,
            "nonce": binding.nonce,
            "request_digest": binding.request_digest,
            "hidden_digest": binding.hidden_digest,
            "expires_at": binding.expires_at,
        });
    }
    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()
    else {
        tracing::warn!("approval notify failed to initialize (non-fatal)");
        return;
    };
    let Ok(request) = build_notify_request(&client, url, &token, &body) else {
        tracing::warn!("approval notify request construction failed (non-fatal)");
        return;
    };
    match client.execute(request).await {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            tracing::warn!(status = %response.status(), "approval notify rejected (non-fatal)");
        }
        Err(_) => {
            tracing::warn!("approval notify delivery failed (non-fatal)");
        }
    }
}

/// Parse a literal private-network HTTP endpoint ending at the notification route.
fn parse_notify_url(raw: &str) -> Result<reqwest::Url, &'static str> {
    let parsed = reqwest::Url::parse(raw).map_err(|_| "invalid URL")?;
    if parsed.scheme() != "http"
        || parsed.path() != "/notify"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_none()
    {
        return Err("unsafe URL shape");
    }
    let host = parsed
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .ok_or("host is not a literal IP")?;
    let IpAddr::V4(host) = host else {
        return Err("host is not a private IPv4 address");
    };
    if !host.is_private() {
        return Err("host is not a private IPv4 address");
    }
    Ok(parsed)
}

/// Validate a random 256-bit unpadded base64url notification credential.
fn valid_notify_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Build one authenticated notification request without exposing its credential.
fn build_notify_request(
    client: &reqwest::Client,
    url: reqwest::Url,
    token: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Request, reqwest::Error> {
    client.post(url).bearer_auth(token).json(body).build()
}

#[cfg(test)]
/// Notifier boundary tests.
mod tests {
    use super::*;
    use reqwest::header::AUTHORIZATION;

    /// Notification URLs are literal, routed, and confined to private IPv4.
    #[test]
    fn notify_url_is_private_network_only() {
        assert!(parse_notify_url("http://10.0.0.1:8787/notify").is_ok());
        for value in [
            "https://10.0.0.1:8787/notify",
            "http://10.0.0.1:8787/other",
            "http://localhost:8787/notify",
            "http://203.0.113.1:8787/notify",
            "http://127.0.0.1:8787/notify",
            "http://10.0.0.1/notify",
        ] {
            assert!(parse_notify_url(value).is_err(), "accepted {value}");
        }
    }

    /// Request construction places the credential only in the bearer header.
    #[test]
    fn notify_request_uses_bearer_authentication() {
        let client = reqwest::Client::new();
        let token = "a".repeat(43);
        let request = build_notify_request(
            &client,
            parse_notify_url("http://10.0.0.1:8787/notify").expect("notify URL"),
            &token,
            &json!({"approval_id": 42}),
        )
        .expect("notify request");
        assert_eq!(
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some(format!("Bearer {token}").as_str())
        );
        assert!(!String::from_utf8_lossy(
            request
                .body()
                .and_then(|body| body.as_bytes())
                .unwrap_or_default()
        )
        .contains(&token));
    }

    /// Notification credentials reject truncation and non-base64url bytes.
    #[test]
    fn notify_token_shape_is_strict() {
        assert!(valid_notify_token(&"a".repeat(43)));
        assert!(!valid_notify_token(&"a".repeat(42)));
        assert!(!valid_notify_token(&format!("{}!", "a".repeat(42))));
    }
}
