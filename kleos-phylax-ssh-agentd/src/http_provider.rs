// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! HTTP-backed KeyProvider that proxies list/sign requests to phylaxd.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context as _;
use kleos_phylax_ssh_agent::provider::{AgentIdentity, KeyProvider, SignError};
use reqwest::Client;
use reqwest::Url;
use serde::Deserialize;
use ssh_key::PublicKey;

/// Compute the SSH wire-format blob for a public key.
///
/// This uses exactly the same encoding as handler.rs line 71:
/// `id.public_key.to_bytes()`.
pub fn public_key_blob(key: &PublicKey) -> anyhow::Result<Vec<u8>> {
    key.to_bytes()
        .context("failed to encode public key to SSH wire format")
}

/// A single identity entry as returned by the phylaxd HTTP API.
#[derive(Debug, Deserialize)]
struct ApiIdentity {
    /// Vault category (e.g. "ssh").
    category: String,
    /// Key name within the category.
    name: String,
    /// OpenSSH public key string (e.g. "ssh-ed25519 AAAA... comment").
    public_openssh: String,
    /// Whether this key auto-signs without explicit approval.
    #[serde(default)]
    auto_sign: bool,
}

/// Response shape for GET /phylax/ssh/identities.
#[derive(Debug, Deserialize)]
struct IdentitiesResponse {
    identities: Vec<ApiIdentity>,
}

/// Response shape for POST /phylax/ssh/{category}/{name}/sign.
#[derive(Debug, Deserialize)]
struct SignResponse {
    signature_hex: String,
}

/// Cached provider state, protected by a Mutex so `identities(&self)` can be sync.
struct Cache {
    /// Ordered list of loaded identities.
    identities: Vec<AgentIdentity>,
    /// Maps SSH wire-format public key blob -> (category, name).
    blob_map: HashMap<Vec<u8>, (String, String)>,
}

impl Cache {
    fn empty() -> Self {
        Self {
            identities: Vec::new(),
            blob_map: HashMap::new(),
        }
    }
}

/// HTTP-backed KeyProvider that proxies list/sign to a running phylaxd instance.
pub struct HttpKeyProvider {
    /// phylaxd base URL, no trailing slash (e.g. `http://127.0.0.1:3100`).
    base_url: String,
    /// Bearer token sent in the `Authorization` header for every request.
    bearer: String,
    /// Shared HTTP client; cheap to clone (backed by a connection pool).
    client: Client,
    /// In-memory identity cache rebuilt on every `refresh()` call.
    cache: Mutex<Cache>,
}

impl HttpKeyProvider {
    /// Build the provider and eagerly load the identity cache.
    ///
    /// Returns an error if the initial fetch fails.
    pub async fn connect(
        base_url: impl Into<String>,
        bearer: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let base_url = base_url.into();
        let bearer = bearer.into();
        let client = Client::builder()
            // Bound requests so a stalled phylaxd cannot hang signing/listing.
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .context("failed to build HTTP client")?;

        let provider = Self {
            base_url,
            bearer,
            client,
            cache: Mutex::new(Cache::empty()),
        };

        provider.refresh().await?;
        Ok(provider)
    }

    /// Fetch current identities from phylaxd and rebuild the cache.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let url = format!("{}/phylax/ssh/identities", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.bearer)
            .send()
            .await
            .context("GET /phylax/ssh/identities failed")?;

        if !resp.status().is_success() {
            anyhow::bail!("GET /phylax/ssh/identities returned HTTP {}", resp.status());
        }

        let body: IdentitiesResponse = resp
            .json()
            .await
            .context("failed to parse identities response")?;

        let mut identities = Vec::with_capacity(body.identities.len());
        let mut blob_map = HashMap::with_capacity(body.identities.len());

        for api_id in body.identities {
            // Parse the OpenSSH public key string.
            let public_key: PublicKey = api_id.public_openssh.parse().with_context(|| {
                format!("invalid public key for {}/{}", api_id.category, api_id.name)
            })?;

            // Compute the blob using the SAME method as handler.rs line 71.
            let blob = public_key_blob(&public_key)
                .with_context(|| format!("failed to blob {}/{}", api_id.category, api_id.name))?;

            blob_map.insert(blob, (api_id.category, api_id.name.clone()));

            identities.push(AgentIdentity {
                public_key,
                comment: api_id.name,
                auto_sign: api_id.auto_sign,
            });
        }

        // Replace cache atomically.
        let mut cache = self.cache.lock().unwrap();
        cache.identities = identities;
        cache.blob_map = blob_map;

        log::debug!(
            "Refreshed SSH identity cache: {} keys loaded",
            cache.identities.len()
        );
        Ok(())
    }
}

impl KeyProvider for HttpKeyProvider {
    /// Returns a snapshot of the cached identity list (sync, no await).
    fn identities(&self) -> Vec<AgentIdentity> {
        self.cache.lock().unwrap().identities.clone()
    }

    /// Signs data by forwarding to phylaxd.
    ///
    /// Looks up the key by its SSH wire blob, then POSTs to
    /// `/phylax/ssh/{category}/{name}/sign`.
    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SignError>> + Send {
        // Resolve category/name while holding the lock (sync, no await).
        let lookup = {
            let cache = self.cache.lock().unwrap();
            cache.blob_map.get(key_blob).cloned()
        };

        let base_url = self.base_url.clone();
        let bearer = self.bearer.clone();
        let client = self.client.clone();
        let data_hex = hex::encode(data);

        async move {
            let (category, name) = lookup.ok_or(SignError::KeyNotFound)?;

            // Percent-encode category and name so traversal characters cannot
            // escape the path segment (e.g. a name containing "/" or "..").
            let url = {
                let mut u = Url::parse(&base_url)
                    .map_err(|e| SignError::SigningFailed(format!("invalid base URL: {e}")))?;
                u.path_segments_mut()
                    .map_err(|_| SignError::SigningFailed("base URL cannot-be-a-base".to_string()))?
                    .extend(&["phylax", "ssh", &category, &name, "sign"]);
                u
            };
            let body = serde_json::json!({
                "data_hex": data_hex,
                "flags": flags,
            });

            let resp = client
                .post(url)
                .bearer_auth(&bearer)
                .json(&body)
                .send()
                .await
                .map_err(|e| SignError::SigningFailed(e.to_string()))?;

            let status = resp.status();
            if status == reqwest::StatusCode::FORBIDDEN {
                return Err(SignError::Denied);
            }
            if !status.is_success() {
                return Err(SignError::SigningFailed(format!(
                    "phylaxd sign returned HTTP {status}"
                )));
            }

            let sign_resp: SignResponse = resp
                .json()
                .await
                .map_err(|e| SignError::SigningFailed(format!("parse sign response: {e}")))?;

            let sig_bytes = hex::decode(&sign_resp.signature_hex)
                .map_err(|e| SignError::SigningFailed(format!("hex decode signature: {e}")))?;

            Ok(sig_bytes)
        }
    }

    /// Clears the cached identity list on lock.
    fn on_lock(&self) -> impl std::future::Future<Output = ()> + Send {
        let mut cache = self.cache.lock().unwrap();
        cache.identities.clear();
        cache.blob_map.clear();
        log::info!("SSH agent locked -- identity cache cleared");
        std::future::ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that `public_key_blob` produces the same bytes as
    /// `PublicKey::to_bytes()` (the exact call used in handler.rs line 71),
    /// and that the blob-to-(category,name) lookup works correctly.
    #[test]
    fn build_cache_maps_blob_to_category_name() {
        // Load the fixture public key.
        let pub_key_str = include_str!("../tests/fixtures/test_ed25519.pub");
        let public_key: PublicKey = pub_key_str
            .trim()
            .parse()
            .expect("parse fixture public key");

        // Compute blob via our helper (which delegates to to_bytes()).
        let blob = public_key_blob(&public_key).expect("blob encoding");

        // Verify the blob is non-empty and starts with the SSH wire type prefix.
        // Ed25519 keys begin with a 4-byte length + "ssh-ed25519" (11 bytes).
        assert!(
            blob.len() > 15,
            "blob should contain at least type prefix + key material"
        );

        // Build a minimal blob_map as the provider does during refresh().
        let mut blob_map: HashMap<Vec<u8>, (String, String)> = HashMap::new();
        blob_map.insert(blob.clone(), ("ssh".to_string(), "test_key".to_string()));

        // Confirm the same blob retrieved via PublicKey::to_bytes() maps correctly.
        let key_bytes = public_key.to_bytes().expect("to_bytes");
        let found = blob_map
            .get(key_bytes.as_slice())
            .expect("blob must be in map");
        assert_eq!(found.0, "ssh", "category mismatch");
        assert_eq!(found.1, "test_key", "name mismatch");

        // Confirm our helper and to_bytes() produce identical output.
        assert_eq!(
            blob, key_bytes,
            "public_key_blob must equal PublicKey::to_bytes()"
        );
    }
}
