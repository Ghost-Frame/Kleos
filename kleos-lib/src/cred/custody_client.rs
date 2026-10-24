//! Thin client for a custody-profile credential daemon.
//!
//! Under the custody profile the daemon never returns secret plaintext, so the
//! client has no verb that could receive it: every response is decoded into a
//! typed struct with `deny_unknown_fields`, which means a daemon (or an
//! impostor) that adds an unexpected field such as `value` produces an error
//! instead of data the caller could print.
//!
//! Authentication is a scoped agent key only. The key comes from the
//! `CREDD_AGENT_KEY` environment variable, then from
//! `~/.config/cred/credd-agent-key.token`, and is read at call time. This
//! module never touches a master key.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

/// Environment variable naming the custody daemon (`host:port` or a full URL).
pub const CUSTODY_ENV: &str = "CRED_CUSTODY";

/// Environment variable holding the agent key bearer.
pub const AGENT_KEY_ENV: &str = "CREDD_AGENT_KEY";

/// File name of the on-disk agent key, relative to the cred config directory.
pub const AGENT_KEY_FILE_NAME: &str = "credd-agent-key.token";

/// Error text shown by `exec` under custody until the credential issuer exists.
pub const EXEC_UNAVAILABLE_MESSAGE: &str =
    "custody exec is not available until the credential issuer lands (phase 2)";

/// Process exit code used when a custody verb is unavailable.
pub const EXEC_UNAVAILABLE_EXIT_CODE: i32 = 2;

/// Largest response body the client will buffer (1 MiB).
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Overall request timeout for ordinary calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Request timeout for SSH CA calls, which may wait on a human approval.
const SSH_CA_TIMEOUT: Duration = Duration::from_secs(150);

/// Longest daemon error message echoed back to the caller.
const MAX_ERROR_MESSAGE_CHARS: usize = 200;

/// Failure modes of the custody client.
#[derive(Debug, Error)]
pub enum CustodyError {
    /// `CRED_CUSTODY` is not set and no target was supplied.
    #[error("{} is not set", CUSTODY_ENV)]
    NotConfigured,
    /// The custody target could not be parsed or failed the transport guard.
    #[error("invalid custody target: {0}")]
    InvalidTarget(String),
    /// Neither the environment variable nor the token file supplied a key.
    #[error("no agent key found: set {} or place the key in {path}", AGENT_KEY_ENV)]
    MissingAgentKey {
        /// Token file that was consulted after the environment variable.
        path: String,
    },
    /// The token file exists but could not be read.
    #[error("cannot read agent key file {path}: {source}")]
    UnreadableAgentKey {
        /// Token file path.
        path: String,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A caller-supplied argument is not acceptable.
    #[error("invalid request: {0}")]
    InvalidInput(String),
    /// The request never produced an HTTP response.
    #[error("custody request failed: {0}")]
    Transport(String),
    /// The daemon answered with a non-success status.
    #[error("custody daemon refused the request ({status}): {message}")]
    Refused {
        /// HTTP status code.
        status: u16,
        /// Sanitised, length-capped daemon message (empty when absent).
        message: String,
    },
    /// The response did not match the typed schema.
    #[error("custody response did not match the expected shape ({0})")]
    BadResponse(String),
}

/// Result alias for custody client operations.
pub type Result<T> = std::result::Result<T, CustodyError>;

/// One row of `GET /secrets`: metadata only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSummary {
    /// Category (service namespace) of the secret.
    pub service: String,
    /// Secret name within the category.
    pub key: String,
    /// Secret type label such as `api_key`.
    pub secret_type: String,
    /// Creation timestamp (may be empty for synced entries).
    pub created_at: String,
    /// Last update timestamp (may be empty for synced entries).
    pub updated_at: String,
}

/// Acknowledgement of a stored secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSecret {
    /// Row identifier assigned by the daemon.
    pub id: i64,
    /// Category the secret was stored under.
    pub category: String,
    /// Secret name.
    pub name: String,
}

/// Acknowledgement of a deleted secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedSecret {
    /// Category of the removed secret.
    pub category: String,
    /// Name of the removed secret.
    pub name: String,
    /// True when the daemon removed the row.
    pub deleted: bool,
}

/// Result of `POST /agents` under custody: identity only, never the key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyCreated {
    /// Agent name.
    pub name: String,
    /// Non-reversible 16 hex character fingerprint of the stored key hash.
    pub fingerprint: String,
    /// Creation timestamp.
    pub created_at: String,
}

/// One row of `GET /agents`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeySummary {
    /// Agent name.
    pub name: String,
    /// Category allow-list (empty means all).
    pub categories: Vec<String>,
    /// Creation timestamp.
    pub created_at: String,
    /// Revocation timestamp, if revoked.
    pub revoked_at: Option<String>,
    /// True while the key is usable.
    pub is_valid: bool,
}

/// Acknowledgement of an agent key revocation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyRevoked {
    /// Agent name.
    pub name: String,
    /// True when the daemon revoked the key.
    pub revoked: bool,
}

/// A certificate produced by signing a caller-supplied public key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCertificate {
    /// Key identity embedded in the certificate.
    pub identity: String,
    /// Principals the certificate is valid for.
    pub principal: String,
    /// Validity interval as requested.
    pub ttl: String,
    /// OpenSSH certificate text (public material).
    pub cert_public_key: String,
}

/// A certificate for a keypair minted by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintedCertificate {
    /// Agent name the keypair was minted for.
    pub agent: String,
    /// Principals the certificate is valid for.
    pub principal: String,
    /// Validity interval as requested.
    pub ttl: String,
    /// OpenSSH certificate text (public material).
    pub cert_public_key: String,
}

/// Outcome of `POST /custody/x509/rotate-leaf`: public data only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotatedLeaf {
    /// True when a new certificate was issued and stored.
    pub rotated: bool,
    /// Lowercase hex serial of the (new, or unchanged) leaf certificate.
    pub serial_hex: String,
    /// `notAfter` of that certificate, RFC 3339 UTC.
    pub not_after: String,
    /// PEM of that certificate (public material).
    pub certificate_pem: String,
    /// Name the previous material was kept under; `None` when nothing rotated.
    pub rollback_name: Option<String>,
}

/// The public half of a secret from `POST /resolve/public`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMaterial {
    /// Type label of the secret, such as `x509_bundle` or `ssh_key`.
    pub secret_type: String,
    /// Leaf certificate PEM (bundles).
    pub certificate_pem: Option<String>,
    /// Intermediate chain PEM (bundles that carry one).
    pub chain_pem: Option<String>,
    /// OpenSSH public key (SSH keys).
    pub public_key: Option<String>,
}

/// Wire wrapper of `GET /secrets`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretListResponse {
    /// Listed secrets.
    secrets: Vec<SecretSummary>,
}

/// Wire wrapper of `GET /agents`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentListResponse {
    /// Listed agent keys.
    keys: Vec<AgentKeySummary>,
}

/// Error body shape the daemon uses for refusals.
#[derive(Deserialize)]
struct ErrorBody {
    /// Human-readable refusal reason.
    error: String,
}

/// Request body of `POST /secret/{category}/{name}`.
#[derive(Serialize)]
struct StoreBody<'a> {
    /// Secret payload in the daemon's `SecretData` JSON form.
    data: &'a Value,
}

/// Request body of the custody `POST /agents`.
#[derive(Serialize)]
struct CreateAgentBody<'a> {
    /// Agent name.
    name: &'a str,
    /// Category allow-list.
    categories: &'a [String],
    /// Absolute path on the daemon host the key is written to.
    key_path: &'a str,
}

/// Request body of `POST /phylax/ssh-ca/sign`.
#[derive(Serialize)]
struct SshSignBody<'a> {
    /// Certificate key identity.
    identity: &'a str,
    /// Principal list.
    principal: &'a str,
    /// Validity interval.
    ttl: &'a str,
    /// OpenSSH public key text to certify.
    public_key: &'a str,
}

/// Request body of `POST /phylax/ssh-ca/mint`.
#[derive(Serialize)]
struct SshMintBody<'a> {
    /// Agent name.
    agent: &'a str,
    /// Principal list.
    principal: &'a str,
    /// Validity interval.
    ttl: &'a str,
}

/// One secret named in a rotation request.
#[derive(Serialize)]
struct SecretRefBody<'a> {
    /// Category the secret lives in.
    category: &'a str,
    /// Secret name within the category.
    name: &'a str,
}

/// Request body of `POST /custody/x509/rotate-leaf`.
#[derive(Serialize)]
struct RotateLeafBody<'a> {
    /// CA bundle whose key signs the replacement.
    ca: SecretRefBody<'a>,
    /// Leaf bundle to replace.
    leaf: SecretRefBody<'a>,
    /// Lifetime of the new certificate in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime_days: Option<u32>,
    /// Rotate only when the current leaf expires within this many days.
    #[serde(skip_serializing_if = "Option::is_none")]
    rotate_within_days: Option<u32>,
}

/// Request body of `POST /resolve/public`.
#[derive(Serialize)]
struct PublicBody<'a> {
    /// Category the secret lives in.
    category: &'a str,
    /// Secret name within the category.
    name: &'a str,
}

/// Authenticated client for one custody daemon.
pub struct CustodyClient {
    /// Shared HTTP client (no redirects, no proxies).
    http: reqwest::Client,
    /// Validated daemon base URL.
    base: Url,
    /// Agent key bearer, zeroized on drop.
    token: Zeroizing<String>,
}

/// Redacts the bearer so a stray `{:?}` cannot leak it.
impl fmt::Debug for CustodyClient {
    /// Print the base URL and a redacted token marker.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodyClient")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

/// True for `localhost` and loopback IP literals.
fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// The custody target named by `CRED_CUSTODY`, if set to a non-blank value.
///
/// Callers use this to choose between the custody client and a legacy code
/// path; a blank value counts as unset, matching [`CustodyClient::from_env`].
pub fn custody_target_from_env() -> Option<String> {
    std::env::var(CUSTODY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Parse and validate a custody target.
///
/// Accepts a full `http(s)://` URL or a bare `host:port`. A bare target gets
/// `http` only when the host is loopback and `https` otherwise. Credentials,
/// query strings and fragments in the target are refused, and the result must
/// pass the shared transport guard (https, or loopback http).
pub fn parse_target(raw: &str) -> Result<Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(CustodyError::InvalidTarget("target is empty".into()));
    }
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        let probe = Url::parse(&format!("https://{raw}"))
            .map_err(|e| CustodyError::InvalidTarget(format!("`{raw}`: {e}")))?;
        let scheme = match probe.host() {
            Some(host) if is_loopback_host(&host) => "http",
            _ => "https",
        };
        format!("{scheme}://{raw}")
    };
    let url = Url::parse(&candidate)
        .map_err(|e| CustodyError::InvalidTarget(format!("`{candidate}`: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CustodyError::InvalidTarget(format!(
            "unsupported scheme `{}` (use http or https)",
            url.scheme()
        )));
    }
    if url.host_str().is_none() {
        return Err(CustodyError::InvalidTarget("target has no host".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CustodyError::InvalidTarget(
            "credentials in the target URL are not allowed".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(CustodyError::InvalidTarget(
            "query strings and fragments are not allowed".into(),
        ));
    }
    crate::net::guard_credd_transport(url.as_str())
        .map_err(|e| CustodyError::InvalidTarget(e.to_string()))?;
    Ok(url)
}

/// Default location of the on-disk agent key (`<config dir>/cred/...`).
pub fn agent_key_file_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cred")
        .join(AGENT_KEY_FILE_NAME)
}

/// Resolve the agent key: `env_value` first, then the file at `file`.
///
/// The file is read at call time and only when the environment value is absent
/// or blank. An absent or empty file yields [`CustodyError::MissingAgentKey`],
/// whose message names both sources.
pub fn load_agent_key(env_value: Option<&str>, file: &Path) -> Result<Zeroizing<String>> {
    if let Some(value) = env_value.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(Zeroizing::new(value.to_string()));
    }
    let missing = || CustodyError::MissingAgentKey {
        path: file.display().to_string(),
    };
    match std::fs::read_to_string(file) {
        Ok(contents) => {
            let contents = Zeroizing::new(contents);
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                Err(missing())
            } else {
                Ok(Zeroizing::new(trimmed.to_string()))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(missing()),
        Err(source) => Err(CustodyError::UnreadableAgentKey {
            path: file.display().to_string(),
            source,
        }),
    }
}

/// Reject empty, `.` and `..` path parts so a name cannot escape its route.
fn check_segment(what: &str, part: &str) -> Result<()> {
    if part.is_empty() || part == "." || part == ".." {
        return Err(CustodyError::InvalidInput(format!(
            "{what} contains an empty, `.` or `..` path component"
        )));
    }
    if part.contains('\0') {
        return Err(CustodyError::InvalidInput(format!(
            "{what} contains a NUL byte"
        )));
    }
    Ok(())
}

/// Path segments for `/secret/{category}/{*name}`.
///
/// `category` is a single segment; `name` may contain `/` and is split into
/// segments so it matches the daemon's wildcard route.
fn secret_segments<'a>(category: &'a str, name: &'a str) -> Result<Vec<&'a str>> {
    if category.contains('/') {
        return Err(CustodyError::InvalidInput(
            "category must not contain `/`".into(),
        ));
    }
    check_segment("category", category)?;
    let mut segments = vec!["secret", category];
    for part in name.split('/') {
        check_segment("name", part)?;
        segments.push(part);
    }
    Ok(segments)
}

/// Reduce a JSON error to its category and position, never its message.
///
/// serde_json messages for type mismatches can quote the offending value, so a
/// plaintext field in a rogue response must not be echoed through them.
fn describe_decode_error(error: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    )
}

/// Decode a response body into `T`, refusing unknown fields.
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| CustodyError::BadResponse(describe_decode_error(&e)))
}

/// Extract a short, printable refusal message from an error body.
fn refusal_message(body: &[u8]) -> String {
    let Ok(parsed) = serde_json::from_slice::<ErrorBody>(body) else {
        return String::new();
    };
    parsed
        .error
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect()
}

/// Read a response body, refusing anything over [`MAX_RESPONSE_BYTES`].
async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(CustodyError::BadResponse("response too large".into()));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CustodyError::Transport(e.without_url().to_string()))?
    {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(CustodyError::BadResponse("response too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Construction and daemon calls.
impl CustodyClient {
    /// Build a client for `target` using an explicit agent key.
    pub fn with_token(target: &str, token: Zeroizing<String>) -> Result<Self> {
        let base = parse_target(target)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| CustodyError::Transport(e.without_url().to_string()))?;
        Ok(Self { http, base, token })
    }

    /// Build a client for `target`, loading the agent key from
    /// `CREDD_AGENT_KEY` and then the default token file.
    pub fn from_target(target: &str) -> Result<Self> {
        let token = load_agent_key(
            std::env::var(AGENT_KEY_ENV).ok().as_deref(),
            &agent_key_file_path(),
        )?;
        Self::with_token(target, token)
    }

    /// Build a client from `CRED_CUSTODY` and the agent key sources.
    pub fn from_env() -> Result<Self> {
        let target = custody_target_from_env().ok_or(CustodyError::NotConfigured)?;
        Self::from_target(&target)
    }

    /// Send one authenticated request and return the success body.
    async fn send<B: Serialize>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let mut url = self.base.clone();
        {
            let mut parts = url
                .path_segments_mut()
                .map_err(|()| CustodyError::InvalidTarget("target cannot carry a path".into()))?;
            parts.pop_if_empty();
            parts.extend(segments);
        }
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(self.token.as_str())
            .timeout(timeout);
        if let Some(body) = body {
            request = request.json(body);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| CustodyError::Transport(e.without_url().to_string()))?;
        let status = resp.status();
        let bytes = read_capped(resp).await?;
        if status.is_success() {
            Ok(bytes)
        } else {
            Err(CustodyError::Refused {
                status: status.as_u16(),
                message: refusal_message(&bytes),
            })
        }
    }

    /// List secret metadata, optionally filtered to one category.
    pub async fn list(&self, category: Option<&str>) -> Result<Vec<SecretSummary>> {
        let query: Vec<(&str, &str)> = category.map(|c| ("category", c)).into_iter().collect();
        let bytes = self
            .send::<()>(Method::GET, &["secrets"], &query, None, REQUEST_TIMEOUT)
            .await?;
        Ok(decode::<SecretListResponse>(&bytes)?.secrets)
    }

    /// Store a secret. `data` is the daemon's `SecretData` JSON form.
    pub async fn store(&self, category: &str, name: &str, data: &Value) -> Result<StoredSecret> {
        let segments = secret_segments(category, name)?;
        let bytes = self
            .send(
                Method::POST,
                &segments,
                &[],
                Some(&StoreBody { data }),
                REQUEST_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }

    /// Delete a secret.
    pub async fn delete(&self, category: &str, name: &str) -> Result<DeletedSecret> {
        let segments = secret_segments(category, name)?;
        let bytes = self
            .send::<()>(Method::DELETE, &segments, &[], None, REQUEST_TIMEOUT)
            .await?;
        decode(&bytes)
    }

    /// Ask the daemon to create an agent key and write it to `key_path` on the
    /// daemon host. Returns the name and fingerprint; the key never travels.
    pub async fn agent_key_generate(
        &self,
        name: &str,
        categories: &[String],
        key_path: &str,
    ) -> Result<AgentKeyCreated> {
        let bytes = self
            .send(
                Method::POST,
                &["agents"],
                &[],
                Some(&CreateAgentBody {
                    name,
                    categories,
                    key_path,
                }),
                REQUEST_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }

    /// List agent keys.
    pub async fn agent_key_list(&self) -> Result<Vec<AgentKeySummary>> {
        let bytes = self
            .send::<()>(Method::GET, &["agents"], &[], None, REQUEST_TIMEOUT)
            .await?;
        Ok(decode::<AgentListResponse>(&bytes)?.keys)
    }

    /// Revoke an agent key by name.
    pub async fn agent_key_revoke(&self, name: &str) -> Result<AgentKeyRevoked> {
        check_segment("name", name)?;
        if name.contains('/') {
            return Err(CustodyError::InvalidInput(
                "agent name must not contain `/`".into(),
            ));
        }
        let bytes = self
            .send::<()>(
                Method::POST,
                &["agents", name, "revoke"],
                &[],
                None,
                REQUEST_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }

    /// Sign `public_key` into a short-lived SSH certificate.
    pub async fn ssh_ca_sign(
        &self,
        identity: &str,
        principal: &str,
        ttl: &str,
        public_key: &str,
    ) -> Result<SignedCertificate> {
        let bytes = self
            .send(
                Method::POST,
                &["phylax", "ssh-ca", "sign"],
                &[],
                Some(&SshSignBody {
                    identity,
                    principal,
                    ttl,
                    public_key,
                }),
                SSH_CA_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }

    /// Mint an agent keypair on the daemon and certify it.
    pub async fn ssh_ca_mint(
        &self,
        agent: &str,
        principal: &str,
        ttl: &str,
    ) -> Result<MintedCertificate> {
        let bytes = self
            .send(
                Method::POST,
                &["phylax", "ssh-ca", "mint"],
                &[],
                Some(&SshMintBody {
                    agent,
                    principal,
                    ttl,
                }),
                SSH_CA_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }

    /// Rotate the x509 `leaf` (category, name) under the vault-held `ca`
    /// (category, name). With `within_days` set the daemon rotates only when
    /// the current certificate expires inside that window and otherwise
    /// reports it unchanged. The response holds public data only.
    pub async fn x509_rotate_leaf(
        &self,
        ca: (&str, &str),
        leaf: (&str, &str),
        lifetime_days: Option<u32>,
        within_days: Option<u32>,
    ) -> Result<RotatedLeaf> {
        for (what, part) in [("ca category", ca.0), ("leaf category", leaf.0)] {
            if part.contains('/') {
                return Err(CustodyError::InvalidInput(format!(
                    "{what} must not contain `/`"
                )));
            }
        }
        for (what, part) in [
            ("ca category", ca.0),
            ("ca name", ca.1),
            ("leaf category", leaf.0),
            ("leaf name", leaf.1),
        ] {
            check_segment(what, part)?;
        }
        let bytes = self
            .send(
                Method::POST,
                &["custody", "x509", "rotate-leaf"],
                &[],
                Some(&RotateLeafBody {
                    ca: SecretRefBody {
                        category: ca.0,
                        name: ca.1,
                    },
                    leaf: SecretRefBody {
                        category: leaf.0,
                        name: leaf.1,
                    },
                    lifetime_days,
                    rotate_within_days: within_days,
                }),
                REQUEST_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }

    /// Fetch the public half of a secret: the certificate and chain of an x509
    /// bundle, or the public key of an SSH key. The daemon refuses every other
    /// type, so no private material can arrive through this call.
    pub async fn public_material(&self, category: &str, name: &str) -> Result<PublicMaterial> {
        if category.contains('/') {
            return Err(CustodyError::InvalidInput(
                "category must not contain `/`".into(),
            ));
        }
        check_segment("category", category)?;
        check_segment("name", name)?;
        let bytes = self
            .send(
                Method::POST,
                &["resolve", "public"],
                &[],
                Some(&PublicBody { category, name }),
                REQUEST_TIMEOUT,
            )
            .await?;
        decode(&bytes)
    }
}

/// Unit tests for target parsing, key loading and response decoding.
#[cfg(test)]
mod tests {
    use super::*;

    /// Bare loopback targets default to http; others to https.
    #[test]
    fn bare_targets_pick_scheme_by_host() {
        assert_eq!(
            parse_target("127.0.0.1:4400").unwrap().as_str(),
            "http://127.0.0.1:4400/"
        );
        assert_eq!(parse_target("localhost:4400").unwrap().scheme(), "http");
        assert_eq!(parse_target("[::1]:4400").unwrap().scheme(), "http");
        assert_eq!(
            parse_target("phylax.example.com:4400").unwrap().scheme(),
            "https"
        );
        assert_eq!(parse_target("10.50.0.1:3100").unwrap().scheme(), "https");
    }

    /// Plaintext http to a non-loopback host is refused by the shared guard.
    #[test]
    fn plaintext_remote_is_refused() {
        assert!(matches!(
            parse_target("http://10.50.0.1:3100"),
            Err(CustodyError::InvalidTarget(_))
        ));
        assert!(parse_target("https://10.50.0.1:3100").is_ok());
        assert!(parse_target("http://127.0.0.1:3100").is_ok());
    }

    /// Malformed or credential-bearing targets are refused.
    #[test]
    fn malformed_targets_are_refused() {
        for bad in [
            "",
            "   ",
            "ftp://127.0.0.1:1",
            "https://user:pw@example.com",
            "https://example.com/?x=1",
            "https://example.com/#frag",
        ] {
            assert!(
                matches!(parse_target(bad), Err(CustodyError::InvalidTarget(_))),
                "{bad:?} should be refused"
            );
        }
    }

    /// The environment value wins and is trimmed.
    #[test]
    fn env_key_wins_over_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "file-key\n").unwrap();
        let key = load_agent_key(Some("  env-key \n"), &file).unwrap();
        assert_eq!(key.as_str(), "env-key");
    }

    /// A blank environment value falls through to the file.
    #[test]
    fn blank_env_falls_back_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "file-key\n").unwrap();
        let key = load_agent_key(Some("   "), &file).unwrap();
        assert_eq!(key.as_str(), "file-key");
    }

    /// With no key anywhere the error names both sources.
    #[test]
    fn missing_key_error_names_both_sources() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("absent-token");
        let err = load_agent_key(None, &file).unwrap_err();
        let text = err.to_string();
        assert!(text.contains(AGENT_KEY_ENV), "{text}");
        assert!(text.contains("absent-token"), "{text}");
        std::fs::write(&file, "\n").unwrap();
        assert!(matches!(
            load_agent_key(None, &file),
            Err(CustodyError::MissingAgentKey { .. })
        ));
    }

    /// A rogue plaintext field makes decoding fail without echoing the value.
    #[test]
    fn unknown_plaintext_field_is_rejected_without_echo() {
        let body = br#"{"id":1,"category":"prod","name":"db","value":"TOPSECRETVALUE"}"#;
        let err = decode::<StoredSecret>(body).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, CustodyError::BadResponse(_)));
        assert!(!text.contains("TOPSECRETVALUE"), "{text}");
        assert!(!text.contains("value"), "{text}");
    }

    /// A type mismatch carrying a string value does not echo it either.
    #[test]
    fn type_mismatch_does_not_echo_value() {
        let body = br#"{"id":"TOPSECRETVALUE","category":"p","name":"n"}"#;
        let err = decode::<StoredSecret>(body).unwrap_err();
        assert!(!err.to_string().contains("TOPSECRETVALUE"));
    }

    /// Wrapped list responses also deny unknown fields at both levels.
    #[test]
    fn list_wrapper_denies_unknown_fields() {
        let row = r#"{"service":"s","key":"k","secret_type":"t","created_at":"","updated_at":""}"#;
        let ok = format!(r#"{{"secrets":[{row}]}}"#);
        assert_eq!(
            decode::<SecretListResponse>(ok.as_bytes())
                .unwrap()
                .secrets
                .len(),
            1
        );
        let extra_top = format!(r#"{{"secrets":[{row}],"value":"x"}}"#);
        assert!(decode::<SecretListResponse>(extra_top.as_bytes()).is_err());
        let extra_row = r#"{"secrets":[{"service":"s","key":"k","secret_type":"t","created_at":"","updated_at":"","value":"x"}]}"#;
        assert!(decode::<SecretListResponse>(extra_row.as_bytes()).is_err());
    }

    /// Debug output never contains the bearer.
    #[test]
    fn debug_redacts_the_token() {
        let client =
            CustodyClient::with_token("127.0.0.1:1", Zeroizing::new("sekrit-bearer".into()))
                .unwrap();
        let shown = format!("{client:?}");
        assert!(!shown.contains("sekrit-bearer"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }

    /// Secret names may nest; traversal and empty parts are refused.
    #[test]
    fn secret_segments_validate_parts() {
        assert_eq!(
            secret_segments("prod", "db/primary").unwrap(),
            vec!["secret", "prod", "db", "primary"]
        );
        for (cat, name) in [
            ("", "n"),
            ("a/b", "n"),
            ("..", "n"),
            ("c", ""),
            ("c", "a//b"),
            ("c", "a/../b"),
            ("c", "./a"),
        ] {
            assert!(
                secret_segments(cat, name).is_err(),
                "({cat:?}, {name:?}) should be refused"
            );
        }
    }

    /// Daemon refusal text is length-capped and stripped of control chars.
    #[test]
    fn refusal_message_is_sanitised() {
        let long = "x".repeat(500);
        let body = format!(r#"{{"error":"bad\nthing {long}"}}"#);
        let msg = refusal_message(body.as_bytes());
        assert!(msg.chars().count() <= MAX_ERROR_MESSAGE_CHARS);
        assert!(!msg.contains('\n'));
        assert_eq!(refusal_message(b"not json"), "");
    }

    /// Rotation and public-material responses decode, and a rogue extra field
    /// (such as a key) is rejected without being echoed.
    #[test]
    fn x509_responses_deny_unknown_fields() {
        let ok = br#"{"rotated":true,"serial_hex":"ab","not_after":"2027-01-01T00:00:00Z","certificate_pem":"C","rollback_name":"leaf-rollback-ab"}"#;
        let rotated = decode::<RotatedLeaf>(ok).unwrap();
        assert!(rotated.rotated);
        assert_eq!(rotated.rollback_name.as_deref(), Some("leaf-rollback-ab"));
        let unchanged = br#"{"rotated":false,"serial_hex":"ab","not_after":"x","certificate_pem":"C","rollback_name":null}"#;
        assert_eq!(
            decode::<RotatedLeaf>(unchanged).unwrap().rollback_name,
            None
        );
        let rogue = br#"{"rotated":true,"serial_hex":"ab","not_after":"x","certificate_pem":"C","rollback_name":null,"private_key_pem":"TOPSECRETKEY"}"#;
        let err = decode::<RotatedLeaf>(rogue).unwrap_err();
        assert!(!err.to_string().contains("TOPSECRETKEY"), "{err}");

        let public = br#"{"secret_type":"ssh_key","certificate_pem":null,"chain_pem":null,"public_key":"ssh-ed25519 AAAA"}"#;
        assert_eq!(
            decode::<PublicMaterial>(public)
                .unwrap()
                .public_key
                .as_deref(),
            Some("ssh-ed25519 AAAA")
        );
        let rogue = br#"{"secret_type":"x","certificate_pem":null,"chain_pem":null,"public_key":null,"private_key":"TOPSECRETKEY"}"#;
        assert!(decode::<PublicMaterial>(rogue).is_err());
    }

    /// Rotation arguments that could escape their route are refused before
    /// any request is made.
    #[tokio::test]
    async fn x509_calls_refuse_unsafe_arguments() {
        let client =
            CustodyClient::with_token("127.0.0.1:1", Zeroizing::new("bearer".into())).unwrap();
        assert!(matches!(
            client
                .x509_rotate_leaf(("a/b", "ca"), ("pki", "leaf"), None, None)
                .await,
            Err(CustodyError::InvalidInput(_))
        ));
        assert!(matches!(
            client
                .x509_rotate_leaf(("pki", "ca"), ("pki", ".."), None, None)
                .await,
            Err(CustodyError::InvalidInput(_))
        ));
        assert!(matches!(
            client.public_material("pki", "").await,
            Err(CustodyError::InvalidInput(_))
        ));
        assert!(matches!(
            client.public_material("a/b", "n").await,
            Err(CustodyError::InvalidInput(_))
        ));
    }
}
