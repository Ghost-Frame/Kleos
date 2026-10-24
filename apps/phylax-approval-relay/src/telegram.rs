//! Send-only Telegram notification transport.

use crate::config::Config;
use serde_json::json;

/// Telegram Bot API origin.
const TELEGRAM_API: &str = "https://api.telegram.org";

/// Send public approval metadata with one HTTPS app-opening button.
pub async fn send_approval(
    client: &reqwest::Client,
    config: &Config,
    request: &crate::state::PublicApprovalRequest,
    pickup_handle: &str,
) -> anyhow::Result<()> {
    let text = format!(
        "Phylax approval request\nAction: {}\nAgent: {}\nTarget: {}/{}\n\nThe enrolled phone must sign the exact decision.",
        request.action, request.agent_name, request.category, request.target_name
    );
    let open_url = format!("{}/v1/phone/open/{}", config.public_base_url, pickup_handle);
    let reply_markup = json!({
        "inline_keyboard": [[{
            "text": "Open secure approval",
            "url": open_url
        }]]
    });
    let url = format!("{}/bot{}/sendMessage", TELEGRAM_API, config.bot_token);
    let response = client
        .post(url)
        .json(&json!({
            "chat_id": config.chat_id,
            "text": text,
            "reply_markup": reply_markup
        }))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Telegram delivery failed"))?;
    if !response.status().is_success() {
        anyhow::bail!("Telegram rejected notification");
    }
    Ok(())
}
