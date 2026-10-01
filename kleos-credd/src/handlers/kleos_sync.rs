//! Helpers for syncing credentials between credd's local DB and the Kleos v3 vault.
//!
//! CRED:v3 entries are stored as Kleos memories with category="credential" and
//! content format: `[CRED:v3] {category}/{name} = {hex(nonce || ciphertext)}`.

use kleos_cred::crypto::{decrypt, encrypt, KEY_SIZE};
use kleos_cred::types::SecretData;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::state::AppState;

const V3_PREFIX: &str = "[CRED:v3] ";

#[derive(Debug, Clone)]
pub(crate) struct KleosV3Entry {
    pub id: i64,
    pub category: String,
    pub name: String,
    pub hex_data: String,
}

#[derive(Deserialize)]
struct ListResponse {
    results: Vec<MemoryRow>,
}

#[derive(Deserialize)]
struct MemoryRow {
    id: i64,
    content: String,
}

fn kleos_url() -> Result<String, String> {
    kleos_lib::kleos_env("URL").map_err(|_| "KLEOS_URL not set".to_string())
}

fn apply_auth(
    state: &AppState,
    req: reqwest::RequestBuilder,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> reqwest::RequestBuilder {
    if let Some(signer) = &state.kleos_signer {
        if let Some(session) = signer.cached_session() {
            return req.header("X-Kleos-Session", session);
        }
        match signer.sign_request(method, path, query, body) {
            Ok(signed) => return signed.apply_headers(req),
            Err(e) => {
                warn!(error = %e, "PIV signing failed, trying bootstrap bearer");
            }
        }
    }
    if let Some(bm) = &state.bootstrap_master {
        req.header("Authorization", format!("Bearer {}", bm.as_str()))
    } else {
        req
    }
}

fn capture_session(state: &AppState, resp: &reqwest::Response) {
    if let Some(signer) = &state.kleos_signer {
        if let Some(val) = resp.headers().get("X-Kleos-Session-Issued") {
            if let Ok(s) = val.to_str() {
                signer.set_session(s.to_string());
            }
        }
    }
}

/// Fetch all [CRED:v3] entries from Kleos.
pub(crate) async fn fetch_v3_entries(state: &AppState) -> Result<Vec<KleosV3Entry>, String> {
    let base = kleos_url()?;
    let url = format!("{}/list", base.trim_end_matches('/'));

    let http = Client::new();
    let req = http
        .get(&url)
        .query(&[("category", "credential"), ("limit", "500")]);
    let req = apply_auth(
        state,
        req,
        "GET",
        "/list",
        "category=credential&limit=500",
        &[],
    );

    let resp = req
        .send()
        .await
        .map_err(|e| format!("kleos unreachable: {}", e))?;
    capture_session(state, &resp);

    if !resp.status().is_success() {
        return Err(format!("kleos /list returned {}", resp.status()));
    }

    let list: ListResponse = resp
        .json()
        .await
        .map_err(|e| format!("parse error: {}", e))?;

    let mut entries = Vec::new();
    for row in list.results {
        if let Some(rest) = row.content.strip_prefix(V3_PREFIX) {
            if let Some((path, hex_data)) = rest.split_once(" = ") {
                if let Some((cat, name)) = path.split_once('/') {
                    entries.push(KleosV3Entry {
                        id: row.id,
                        category: decode_v3_category(cat),
                        name: name.to_string(),
                        hex_data: hex_data.trim().to_string(),
                    });
                }
            }
        }
    }

    debug!("fetched {} v3 entries from Kleos", entries.len());
    Ok(entries)
}

/// Store a secret to Kleos as a [CRED:v3] memory.
/// Deletes any existing entry for the same category/name first to avoid duplicates.
pub(crate) async fn store_to_kleos(
    state: &AppState,
    category: &str,
    name: &str,
    data: &SecretData,
    master_key: &[u8; KEY_SIZE],
) {
    if let Err(e) = store_to_kleos_inner(state, category, name, data, master_key).await {
        warn!(category, name, error = %e, "failed to sync store to Kleos v3");
    }
}

/// True iff `s` is a safe v3 secret NAME: the `is_safe_ident` alphabet plus
/// inner `/` separators (no leading, trailing, or doubled `/`). A slash in the
/// name cannot shadow another entry because the category may not contain one
/// and entries are matched on the full `{category}/{name} = ` prefix, which
/// ends in ` = `; only the category must stay slash-free.
pub(crate) fn is_safe_v3_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.ends_with('/')
        && !s.contains("//")
        && s.split('/').all(is_safe_ident)
}

/// True iff `s` is a safe v3 CATEGORY: `/`-separated segments that each pass
/// `is_safe_ident` (e.g. `cloudflare/zone`). Its slashes are escaped as `%2F`
/// on the wire by `encode_v3_category`, so the stored category never contains
/// `/` and cannot collide with a name. `%` is not in the segment alphabet, so
/// decoding is unambiguous.
pub(crate) fn is_safe_v3_category(s: &str) -> bool {
    is_safe_v3_name(s)
}

/// Escape a category for the v3 content format (`/` becomes `%2F`).
pub(crate) fn encode_v3_category(category: &str) -> String {
    category.replace('/', "%2F")
}

/// Reverse `encode_v3_category`. Entries written before escaping existed never
/// contain `%`, so they decode to themselves.
pub(crate) fn decode_v3_category(stored: &str) -> String {
    stored.replace("%2F", "/")
}

/// True iff `s` is non-empty and contains only alphanumerics, `-`, `_`, or `.`.
/// Guards the V3 content format `[CRED:v3] {category}/{name} = {hex}`: a `/` in
/// category or ` = ` in name would otherwise parse as a different entry on
/// re-read (content-format injection, CREDD-1).
pub(crate) fn is_safe_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

async fn store_to_kleos_inner(
    state: &AppState,
    category: &str,
    name: &str,
    data: &SecretData,
    master_key: &[u8; KEY_SIZE],
) -> Result<(), String> {
    // Reject category/name that would corrupt the V3 content format on re-parse.
    if !is_safe_v3_category(category) {
        return Err(format!("category contains unsafe characters: {category:?}"));
    }
    if !is_safe_v3_name(name) {
        return Err(format!("name contains unsafe characters: {name:?}"));
    }

    // Delete existing entry first
    delete_from_kleos_inner(state, category, name).await.ok();

    let plaintext = serde_json::to_vec(data).map_err(|e| format!("serialize: {}", e))?;
    let ciphertext = encrypt(master_key, &plaintext).map_err(|e| format!("encrypt: {}", e))?;
    let hex_data = hex::encode(&ciphertext);
    let content = format!(
        "{}{}/{} = {}",
        V3_PREFIX,
        encode_v3_category(category),
        name,
        hex_data
    );

    let base = kleos_url()?;
    let url = format!("{}/store", base.trim_end_matches('/'));
    let body = serde_json::json!({
        "content": content,
        "category": "credential",
        "source": "credd",
        "importance": 10,
        "is_static": true,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let http = Client::new();
    let req = http.post(&url).json(&body);
    let req = apply_auth(state, req, "POST", "/store", "", &body_bytes);

    let resp = req
        .send()
        .await
        .map_err(|e| format!("kleos unreachable: {}", e))?;
    capture_session(state, &resp);

    if !resp.status().is_success() {
        return Err(format!("kleos /store returned {}", resp.status()));
    }

    debug!("synced {}/{} to Kleos v3", category, name);
    Ok(())
}

/// Delete a [CRED:v3] entry from Kleos by finding it via content prefix.
pub(crate) async fn delete_from_kleos(state: &AppState, category: &str, name: &str) {
    if let Err(e) = delete_from_kleos_inner(state, category, name).await {
        warn!(category, name, error = %e, "failed to sync delete to Kleos v3");
    }
}

async fn delete_from_kleos_inner(
    state: &AppState,
    category: &str,
    name: &str,
) -> Result<(), String> {
    let entries = fetch_v3_entries(state).await?;
    let target = entries
        .iter()
        .find(|e| e.category == category && e.name == name);

    let entry = match target {
        Some(e) => e,
        None => return Ok(()),
    };

    let base = kleos_url()?;
    let url = format!("{}/memory/{}", base.trim_end_matches('/'), entry.id);

    let http = Client::new();
    let req = http.delete(&url);
    let path = format!("/memory/{}", entry.id);
    let req = apply_auth(state, req, "DELETE", &path, "", &[]);

    let resp = req
        .send()
        .await
        .map_err(|e| format!("kleos unreachable: {}", e))?;
    capture_session(state, &resp);

    if !resp.status().is_success() {
        return Err(format!(
            "kleos DELETE /memory/{} returned {}",
            entry.id,
            resp.status()
        ));
    }

    debug!(
        "deleted {}/{} (id={}) from Kleos v3",
        category, name, entry.id
    );
    Ok(())
}

/// Decrypt a v3 hex blob into SecretData.
pub(crate) fn decrypt_v3_entry(
    hex_data: &str,
    master_key: &[u8; KEY_SIZE],
) -> Result<SecretData, String> {
    let ciphertext = hex::decode(hex_data).map_err(|e| format!("hex decode: {}", e))?;
    let plaintext = decrypt(master_key, &ciphertext).map_err(|e| format!("decrypt: {}", e))?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("json parse: {}", e))
}

/// Tests for the v3 identifier rules that guard the content format.
#[cfg(test)]
mod tests {
    use super::{
        decode_v3_category, encode_v3_category, is_safe_ident, is_safe_v3_category, is_safe_v3_name,
    };

    /// Slashed categories are escaped on write and restored on read; legacy ones are unchanged.
    #[test]
    fn categories_escape_and_roundtrip() {
        assert!(is_safe_v3_category("cloudflare/zone"));
        assert!(!is_safe_v3_category("cloudflare//zone"));
        assert!(!is_safe_v3_category("a%2Fb"));
        assert_eq!(encode_v3_category("cloudflare/zone"), "cloudflare%2Fzone");
        assert!(!encode_v3_category("cloudflare/zone").contains('/'));
        assert_eq!(decode_v3_category("cloudflare%2Fzone"), "cloudflare/zone");
        assert_eq!(decode_v3_category("engram-rust"), "engram-rust");
        // Escaped `cloudflare/zone` + `api-token` cannot collide with `cloudflare` + `zone/api-token`.
        let a = format!(
            "{}/{} = ",
            encode_v3_category("cloudflare/zone"),
            "api-token"
        );
        let b = format!(
            "{}/{} = ",
            encode_v3_category("cloudflare"),
            "zone/api-token"
        );
        assert_ne!(a, b);
    }

    /// Categories stay strict: no slash, no spaces, no separators.
    #[test]
    fn categories_reject_slashes_and_separators() {
        assert!(is_safe_ident("cloudflare"));
        assert!(!is_safe_ident("cloudflare/zone"));
        assert!(!is_safe_ident("a = b"));
        assert!(!is_safe_ident(""));
    }

    /// Names may contain inner slashes but never empty segments or separators.
    #[test]
    fn names_allow_inner_slashes_only() {
        assert!(is_safe_v3_name("zone/api-token"));
        assert!(is_safe_v3_name("example-bot/bot-secret/api-key"));
        assert!(!is_safe_v3_name("/lead"));
        assert!(!is_safe_v3_name("trail/"));
        assert!(!is_safe_v3_name("a//b"));
        assert!(!is_safe_v3_name("a = b"));
        assert!(!is_safe_v3_name("a b"));
        assert!(!is_safe_v3_name(""));
    }

    /// A slash in the name cannot collide with another entry, because the
    /// category may not contain one: `c/a` + `b` is rejected outright.
    #[test]
    fn no_category_name_collision() {
        assert!(!is_safe_ident("c/a"));
        assert!(is_safe_ident("c") && is_safe_v3_name("a/b"));
    }
}
