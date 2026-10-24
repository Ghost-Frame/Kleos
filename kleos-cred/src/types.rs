//! Secret data types for structured credential storage.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CredError, Result};

/// The type of secret stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    Login,
    ApiKey,
    OAuthApp,
    SshKey,
    Note,
    Environment,
    /// An X.509 certificate with its private key (and optional chain).
    X509Bundle,
}

impl SecretType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::ApiKey => "api_key",
            Self::OAuthApp => "oauth_app",
            Self::SshKey => "ssh_key",
            Self::Note => "note",
            Self::Environment => "environment",
            Self::X509Bundle => "x509_bundle",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(Self::Login),
            "api_key" => Some(Self::ApiKey),
            "oauth_app" => Some(Self::OAuthApp),
            "ssh_key" => Some(Self::SshKey),
            "note" => Some(Self::Note),
            "environment" => Some(Self::Environment),
            "x509_bundle" => Some(Self::X509Bundle),
            _ => None,
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured secret data with typed variants.
///
/// Debug is hand-implemented to redact sensitive fields -- never derive it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretData {
    Login {
        username: String,
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp_seed: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    ApiKey {
        key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    OAuthApp {
        client_id: String,
        client_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_uri: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scopes: Option<Vec<String>>,
    },
    SshKey {
        private_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    Note {
        content: String,
    },
    Environment {
        variables: HashMap<String, String>,
    },
    /// An X.509 certificate with its private key, presented by the credential
    /// proxy as a TLS client identity and never returned to callers.
    X509Bundle {
        /// PEM certificate (the leaf, public material).
        certificate_pem: String,
        /// PKCS#8 PEM private key for `certificate_pem` (secret).
        private_key_pem: String,
        /// Optional PEM intermediate chain (public material).
        #[serde(skip_serializing_if = "Option::is_none")]
        chain_pem: Option<String>,
    },
}

/// Schema version accepted for the legacy base64-JSON bundle carried in a
/// [`SecretData::Note`].
pub const LEGACY_BUNDLE_SCHEMA_VERSION: u64 = 1;

/// The parts of an X.509 bundle, whichever storage shape they came from.
///
/// Returned by [`SecretData::as_x509_bundle`]. Debug is hand-implemented so the
/// private key can never reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct X509Material {
    /// PEM certificate (the leaf, public material).
    pub certificate_pem: String,
    /// PKCS#8 PEM private key (secret).
    pub private_key_pem: String,
    /// Optional PEM intermediate chain (public material).
    pub chain_pem: Option<String>,
}

/// Redacted debug output: lengths only, never PEM text.
impl std::fmt::Debug for X509Material {
    /// Print byte lengths and a redaction marker for the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509Material")
            .field("certificate_pem", &self.certificate_pem.len())
            .field("private_key_pem", &"[REDACTED]")
            .field("chain_pem", &self.chain_pem.as_ref().map(String::len))
            .finish()
    }
}

/// On-the-wire shape of the legacy bundle: base64 (standard, padded) of this
/// JSON object stored as the `content` of a note.
#[derive(Deserialize)]
struct LegacyBundle {
    /// Format version; only [`LEGACY_BUNDLE_SCHEMA_VERSION`] is accepted.
    #[serde(default)]
    schema_version: Option<serde_json::Value>,
    /// PEM certificate.
    certificate_pem: String,
    /// PKCS#8 PEM private key.
    private_key_pem: String,
}

/// Decode a note's content as a legacy bundle.
///
/// `Ok(None)` when the content is not base64 of a JSON object carrying both PEM
/// fields (an ordinary note). `Err(InvalidInput)` when it is such a bundle but
/// its `schema_version` is not [`LEGACY_BUNDLE_SCHEMA_VERSION`].
fn decode_legacy_bundle(content: &str) -> Result<Option<X509Material>> {
    let Ok(raw) = STANDARD.decode(content.trim()) else {
        return Ok(None);
    };
    let raw = Zeroizing::new(raw);
    let Ok(bundle) = serde_json::from_slice::<LegacyBundle>(&raw) else {
        return Ok(None);
    };
    let version = bundle
        .schema_version
        .as_ref()
        .and_then(serde_json::Value::as_u64);
    if version != Some(LEGACY_BUNDLE_SCHEMA_VERSION) {
        return Err(CredError::InvalidInput(format!(
            "unsupported x509 bundle schema_version (expected {LEGACY_BUNDLE_SCHEMA_VERSION})"
        )));
    }
    Ok(Some(X509Material {
        certificate_pem: bundle.certificate_pem,
        private_key_pem: bundle.private_key_pem,
        chain_pem: None,
    }))
}

/// The base64 body of the first PEM block in `pem`, with line breaks and
/// surrounding whitespace removed.
///
/// Used to build redaction needles: a response can echo the key without its
/// armor lines or its line wrapping. Returns `None` when `pem` holds no
/// complete `BEGIN`/`END` block or the block is empty. RFC 1421 header lines
/// (those containing `:`) are skipped.
pub fn unwrap_pem_body(pem: &str) -> Option<String> {
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if !inside {
            inside = line.starts_with("-----BEGIN ") && line.ends_with("-----");
        } else if line.starts_with("-----END ") {
            return (!body.is_empty()).then_some(body);
        } else if !line.contains(':') {
            body.extend(line.chars().filter(|c| !c.is_whitespace()));
        }
    }
    None
}

impl std::fmt::Debug for SecretData {
    /// Redacted debug output -- never prints secret values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretData::{}(<redacted>)", self.type_name())
    }
}

impl SecretData {
    /// Get the type of this secret.
    pub fn secret_type(&self) -> SecretType {
        match self {
            Self::Login { .. } => SecretType::Login,
            Self::ApiKey { .. } => SecretType::ApiKey,
            Self::OAuthApp { .. } => SecretType::OAuthApp,
            Self::SshKey { .. } => SecretType::SshKey,
            Self::Note { .. } => SecretType::Note,
            Self::Environment { .. } => SecretType::Environment,
            Self::X509Bundle { .. } => SecretType::X509Bundle,
        }
    }

    /// Extract the primary secret value for substitution.
    ///
    /// Returns the most commonly needed value for each type:
    /// - Login: password
    /// - ApiKey: key
    /// - OAuthApp: client_secret
    /// - SshKey: private_key
    /// - Note: content
    /// - Environment: JSON of all variables
    /// - X509Bundle: private_key_pem
    pub fn primary_value(&self) -> String {
        match self {
            Self::Login { password, .. } => password.clone(),
            Self::ApiKey { key, .. } => key.clone(),
            Self::OAuthApp { client_secret, .. } => client_secret.clone(),
            Self::SshKey { private_key, .. } => private_key.clone(),
            Self::Note { content } => content.clone(),
            Self::Environment { variables } => serde_json::to_string(variables).unwrap_or_default(),
            Self::X509Bundle {
                private_key_pem, ..
            } => private_key_pem.clone(),
        }
    }

    /// The certificate, key and chain of this secret when it is an X.509 bundle.
    ///
    /// Accepts a real [`SecretData::X509Bundle`] and a legacy
    /// [`SecretData::Note`] whose content is base64 of
    /// `{"schema_version":1,"certificate_pem":..,"private_key_pem":..}`.
    /// Every other secret, and a note that is not such a bundle, yields
    /// `Ok(None)`. A legacy bundle with any other `schema_version` is an
    /// `InvalidInput` error rather than silently treated as an ordinary note.
    pub fn as_x509_bundle(&self) -> Result<Option<X509Material>> {
        match self {
            Self::X509Bundle {
                certificate_pem,
                private_key_pem,
                chain_pem,
            } => Ok(Some(X509Material {
                certificate_pem: certificate_pem.clone(),
                private_key_pem: private_key_pem.clone(),
                chain_pem: chain_pem.clone(),
            })),
            Self::Note { content } => decode_legacy_bundle(content),
            _ => Ok(None),
        }
    }

    /// Get a specific field from the secret.
    pub fn get_field(&self, field: &str) -> Option<String> {
        match self {
            Self::Login {
                username,
                password,
                url,
                totp_seed,
                notes,
            } => match field {
                "username" => Some(username.clone()),
                "password" => Some(password.clone()),
                "url" => url.clone(),
                "totp_seed" => totp_seed.clone(),
                "notes" => notes.clone(),
                _ => None,
            },
            Self::ApiKey {
                key,
                endpoint,
                notes,
            } => match field {
                "key" => Some(key.clone()),
                "endpoint" => endpoint.clone(),
                "notes" => notes.clone(),
                _ => None,
            },
            Self::OAuthApp {
                client_id,
                client_secret,
                redirect_uri,
                scopes,
            } => match field {
                "client_id" => Some(client_id.clone()),
                "client_secret" => Some(client_secret.clone()),
                "redirect_uri" => redirect_uri.clone(),
                "scopes" => scopes.as_ref().map(|s| s.join(",")),
                _ => None,
            },
            Self::SshKey {
                private_key,
                public_key,
                passphrase,
            } => match field {
                "private_key" => Some(private_key.clone()),
                "public_key" => public_key.clone(),
                "passphrase" => passphrase.clone(),
                _ => None,
            },
            Self::Note { content } => match field {
                "content" => Some(content.clone()),
                _ => None,
            },
            Self::Environment { variables } => variables.get(field).cloned(),
            Self::X509Bundle {
                certificate_pem,
                private_key_pem,
                chain_pem,
            } => match field {
                "certificate_pem" => Some(certificate_pem.clone()),
                "private_key_pem" => Some(private_key_pem.clone()),
                "chain_pem" => chain_pem.clone(),
                _ => None,
            },
        }
    }

    /// Get the type name as a display string.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "Login",
            Self::ApiKey { .. } => "ApiKey",
            Self::OAuthApp { .. } => "OAuthApp",
            Self::SshKey { .. } => "SshKey",
            Self::Note { .. } => "Note",
            Self::Environment { .. } => "Environment",
            Self::X509Bundle { .. } => "X509Bundle",
        }
    }

    /// Get the bare/primary value for simple output.
    /// Only returns a value for ApiKey and Note types.
    pub fn bare_value(&self) -> Option<String> {
        match self {
            Self::ApiKey { key, .. } => Some(key.clone()),
            Self::Note { content } => Some(content.clone()),
            _ => None,
        }
    }

    /// Field names for list display (values never shown).
    pub fn field_names(&self) -> Vec<String> {
        match self {
            Self::Login {
                url,
                totp_seed,
                notes,
                ..
            } => {
                let mut f = vec!["username".to_string(), "password".to_string()];
                if url.is_some() {
                    f.push("url".to_string());
                }
                if totp_seed.is_some() {
                    f.push("totp_seed".to_string());
                }
                if notes.is_some() {
                    f.push("notes".to_string());
                }
                f
            }
            Self::ApiKey {
                endpoint, notes, ..
            } => {
                let mut f = vec!["key".to_string()];
                if endpoint.is_some() {
                    f.push("endpoint".to_string());
                }
                if notes.is_some() {
                    f.push("notes".to_string());
                }
                f
            }
            Self::OAuthApp {
                redirect_uri,
                scopes,
                ..
            } => {
                let mut f = vec!["client_id".to_string(), "client_secret".to_string()];
                if redirect_uri.is_some() {
                    f.push("redirect_uri".to_string());
                }
                if scopes.is_some() {
                    f.push("scopes".to_string());
                }
                f
            }
            Self::SshKey {
                public_key,
                passphrase,
                ..
            } => {
                let mut f = vec!["private_key".to_string()];
                if public_key.is_some() {
                    f.push("public_key".to_string());
                }
                if passphrase.is_some() {
                    f.push("passphrase".to_string());
                }
                f
            }
            Self::Note { .. } => vec!["content".to_string()],
            Self::Environment { variables } => variables.keys().cloned().collect(),
            Self::X509Bundle { chain_pem, .. } => {
                let mut f = vec!["certificate_pem".to_string(), "private_key_pem".to_string()];
                if chain_pem.is_some() {
                    f.push("chain_pem".to_string());
                }
                f
            }
        }
    }

    /// One-line redacted preview for list display.
    pub fn redacted_preview(&self) -> String {
        match self {
            Self::Login { username, url, .. } => {
                let url_str = url.as_deref().unwrap_or("(no url)");
                format!("{} @ {}", username, url_str)
            }
            Self::ApiKey { key, .. } => {
                // Char-based slicing: raw byte offsets panic when a key
                // contains multi-byte UTF-8 near either end.
                let start: String = key.chars().take(2).collect();
                let end: String = key
                    .chars()
                    .rev()
                    .take(2)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                format!("{}...{}", start, end)
            }
            Self::OAuthApp { client_id, .. } => format!("client_id={}", client_id),
            Self::SshKey { .. } => "[private key]".to_string(),
            Self::Note { content } => {
                // Char-based truncation for the same multi-byte-boundary
                // panic as the ApiKey arm above.
                let preview: String = content.chars().take(40).collect();
                let preview = preview.as_str();
                format!("{}...", preview)
            }
            Self::Environment { variables } => {
                let names: Vec<_> = variables.keys().map(|k| format!("{}=***", k)).collect();
                names.join(", ")
            }
            Self::X509Bundle { .. } => "[x509 certificate and private key]".to_string(),
        }
    }
}

/// Maximum number of allowed origins one secret may carry.
pub const MAX_ALLOWED_ORIGINS: usize = 32;

/// Maximum number of extra auth headers one secret may carry.
pub const MAX_EXTRA_AUTH_HEADERS: usize = 16;

/// Auth header names every secret may be injected into without opting in.
pub const DEFAULT_AUTH_HEADERS: &[&str] = &["authorization", "x-api-key"];

/// Header names that can never be an injection target: framing and hop-by-hop
/// headers, plus the ones the proxy sets itself.
const RESERVED_HEADER_NAMES: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "accept-encoding",
    "set-cookie",
    "set-cookie2",
];

/// One exact network origin a secret may be sent to: scheme, host and port.
///
/// The port is mandatory and wildcards are not representable: a secret is only
/// ever injected into requests whose `(scheme, host, effective port)` equals
/// one of its origins. Hosts are matched exactly, so `example.com` does not
/// cover `api.example.com`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// `http` or `https` (lowercase after validation).
    pub scheme: String,
    /// Lowercase host: a DNS name, an IPv4 literal, or a bracketed IPv6 literal.
    pub host: String,
    /// TCP port, 1..=65535.
    pub port: u16,
}

/// Origin validation and matching.
impl Origin {
    /// Return a normalized copy (lowercase scheme and host) or an
    /// `InvalidInput` error. Rejects wildcards, empty hosts, other schemes and
    /// port 0.
    pub fn validated(&self) -> Result<Origin> {
        let scheme = self.scheme.trim().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(CredError::InvalidInput(format!(
                "origin scheme must be http or https, got {:?}",
                self.scheme
            )));
        }
        let host = self.host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(CredError::InvalidInput("origin host is empty".into()));
        }
        if host.contains('*') {
            return Err(CredError::InvalidInput(
                "wildcard origins are not allowed".into(),
            ));
        }
        if !valid_origin_host(&host) {
            return Err(CredError::InvalidInput(format!(
                "origin host {:?} is not a plain DNS name or IP literal",
                self.host
            )));
        }
        if self.port == 0 {
            return Err(CredError::InvalidInput(
                "origin port must be 1..=65535".into(),
            ));
        }
        Ok(Origin {
            scheme,
            host,
            port: self.port,
        })
    }

    /// True when `(scheme, host, port)` equals this origin exactly. The caller
    /// passes the lowercase scheme/host and the effective (defaulted) port.
    pub fn matches(&self, scheme: &str, host: &str, port: u16) -> bool {
        self.scheme == scheme && self.host == host && self.port == port
    }
}

/// True for a lowercase DNS name (labels of `a-z0-9-` and `.`), an IPv4
/// literal, or a bracketed IPv6 literal.
fn valid_origin_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

/// True when `name` is a syntactically valid HTTP header field name (RFC 7230
/// token).
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

/// Per-secret proxy settings, persisted inside the encrypted secret blob next
/// to the [`SecretData`] under the `proxy_policy` key.
///
/// Every field defaults, so rows written before this struct existed load as
/// "no origins, no extra headers, body returned": under the custody profile
/// that means the secret cannot be proxied anywhere until an origin is added.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyPolicy {
    /// Exact origins the secret may be injected into (custody profile).
    #[serde(default)]
    pub allowed_origins: Vec<Origin>,
    /// Header names, beyond `Authorization` and `X-Api-Key`, the secret may be
    /// injected into.
    #[serde(default)]
    pub extra_auth_headers: Vec<String>,
    /// When true the proxy returns an empty body (status and non-sensitive
    /// headers only).
    #[serde(default)]
    pub drop_response_body: bool,
}

/// Validation, normalization and queries for [`ProxyPolicy`].
impl ProxyPolicy {
    /// True when every field holds its default (nothing is persisted then).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Validate and normalize: origins lowercased and deduplicated, header
    /// names lowercased, deduplicated and checked against the reserved list.
    pub fn validated(self) -> Result<ProxyPolicy> {
        if self.allowed_origins.len() > MAX_ALLOWED_ORIGINS {
            return Err(CredError::InvalidInput(format!(
                "at most {MAX_ALLOWED_ORIGINS} allowed origins per secret"
            )));
        }
        if self.extra_auth_headers.len() > MAX_EXTRA_AUTH_HEADERS {
            return Err(CredError::InvalidInput(format!(
                "at most {MAX_EXTRA_AUTH_HEADERS} extra auth headers per secret"
            )));
        }
        let mut origins: Vec<Origin> = Vec::new();
        for origin in &self.allowed_origins {
            let origin = origin.validated()?;
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        let mut headers: Vec<String> = Vec::new();
        for header in &self.extra_auth_headers {
            let name = header.trim().to_ascii_lowercase();
            if !valid_header_name(&name) {
                return Err(CredError::InvalidInput(format!(
                    "invalid auth header name {header:?}"
                )));
            }
            if RESERVED_HEADER_NAMES.contains(&name.as_str()) {
                return Err(CredError::InvalidInput(format!(
                    "header {name:?} cannot be an auth header"
                )));
            }
            if !DEFAULT_AUTH_HEADERS.contains(&name.as_str()) && !headers.contains(&name) {
                headers.push(name);
            }
        }
        Ok(ProxyPolicy {
            allowed_origins: origins,
            extra_auth_headers: headers,
            drop_response_body: self.drop_response_body,
        })
    }

    /// True when the target `(scheme, host, port)` equals one allowed origin.
    pub fn origin_allowed(&self, scheme: &str, host: &str, port: u16) -> bool {
        self.allowed_origins
            .iter()
            .any(|o| o.matches(scheme, host, port))
    }

    /// True when the secret may be injected into header `name`
    /// (case-insensitive): `Authorization`, `X-Api-Key`, or an extra header.
    pub fn auth_header_allowed(&self, name: &str) -> bool {
        DEFAULT_AUTH_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
            || self
                .extra_auth_headers
                .iter()
                .any(|h| name.eq_ignore_ascii_case(h))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_type_roundtrip() {
        for st in [
            SecretType::Login,
            SecretType::ApiKey,
            SecretType::OAuthApp,
            SecretType::SshKey,
            SecretType::Note,
            SecretType::Environment,
            SecretType::X509Bundle,
        ] {
            assert_eq!(SecretType::parse(st.as_str()), Some(st));
        }
    }

    #[test]
    fn secret_data_serialization() {
        let data = SecretData::Login {
            username: "user".into(),
            password: "pass".into(),
            url: Some("https://example.com".into()),
            totp_seed: None,
            notes: None,
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"type\":\"login\""));
        assert!(json.contains("\"username\":\"user\""));
        assert!(!json.contains("notes")); // skip_serializing_if = None

        let restored: SecretData = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.secret_type(), SecretType::Login);
    }

    #[test]
    fn primary_value_extraction() {
        let login = SecretData::Login {
            username: "user".into(),
            password: "secret123".into(),
            url: None,
            totp_seed: None,
            notes: None,
        };
        assert_eq!(login.primary_value(), "secret123");

        let api = SecretData::ApiKey {
            key: "api-key-value".into(),
            endpoint: None,
            notes: None,
        };
        assert_eq!(api.primary_value(), "api-key-value");
    }

    #[test]
    fn field_access() {
        let login = SecretData::Login {
            username: "admin".into(),
            password: "hunter2".into(),
            url: Some("https://example.com".into()),
            totp_seed: None,
            notes: None,
        };
        assert_eq!(login.get_field("username"), Some("admin".into()));
        assert_eq!(login.get_field("password"), Some("hunter2".into()));
        assert_eq!(login.get_field("url"), Some("https://example.com".into()));
        assert_eq!(login.get_field("notes"), None);
        assert_eq!(login.get_field("nonexistent"), None);
    }

    #[test]
    fn environment_variables() {
        let env = SecretData::Environment {
            variables: HashMap::from([
                ("DB_HOST".into(), "localhost".into()),
                ("DB_PORT".into(), "5432".into()),
            ]),
        };
        assert_eq!(env.get_field("DB_HOST"), Some("localhost".into()));
        assert_eq!(env.get_field("DB_PORT"), Some("5432".into()));
        assert_eq!(env.get_field("DB_MISSING"), None);
    }

    #[test]
    fn field_names_login() {
        let login_basic = SecretData::Login {
            username: "user".into(),
            password: "pass".into(),
            url: None,
            totp_seed: None,
            notes: None,
        };
        assert_eq!(login_basic.field_names(), vec!["username", "password"]);

        let login_full = SecretData::Login {
            username: "user".into(),
            password: "pass".into(),
            url: Some("https://example.com".into()),
            totp_seed: Some("JBSWY3DPEHPK3PXP".into()),
            notes: Some("work account".into()),
        };
        assert_eq!(
            login_full.field_names(),
            vec!["username", "password", "url", "totp_seed", "notes"]
        );
    }

    #[test]
    fn field_names_api_key() {
        let api = SecretData::ApiKey {
            key: "sk-abc123".into(),
            endpoint: None,
            notes: None,
        };
        assert_eq!(api.field_names(), vec!["key"]);
    }

    #[test]
    fn redacted_preview_login() {
        let login = SecretData::Login {
            username: "alice".into(),
            password: "secret".into(),
            url: Some("https://example.com".into()),
            totp_seed: None,
            notes: None,
        };
        assert_eq!(login.redacted_preview(), "alice @ https://example.com");

        let login_no_url = SecretData::Login {
            username: "bob".into(),
            password: "secret".into(),
            url: None,
            totp_seed: None,
            notes: None,
        };
        assert_eq!(login_no_url.redacted_preview(), "bob @ (no url)");
    }

    #[test]
    fn redacted_preview_api_key() {
        let api = SecretData::ApiKey {
            key: "sk-abcdef".into(),
            endpoint: None,
            notes: None,
        };
        let preview = api.redacted_preview();
        assert!(preview.starts_with("sk"));
        assert!(preview.contains("..."));
    }

    #[test]
    fn bare_value_only_api_key_and_note() {
        let login = SecretData::Login {
            username: "user".into(),
            password: "pass".into(),
            url: None,
            totp_seed: None,
            notes: None,
        };
        assert_eq!(login.bare_value(), None);

        let api = SecretData::ApiKey {
            key: "mykey".into(),
            endpoint: None,
            notes: None,
        };
        assert_eq!(api.bare_value(), Some("mykey".to_string()));

        let note = SecretData::Note {
            content: "hello".into(),
        };
        assert_eq!(note.bare_value(), Some("hello".to_string()));

        let ssh = SecretData::SshKey {
            private_key: "-----BEGIN...".into(),
            public_key: None,
            passphrase: None,
        };
        assert_eq!(ssh.bare_value(), None);
    }

    #[test]
    fn debug_never_leaks_secrets() {
        let login = SecretData::Login {
            username: "admin".into(),
            password: "hunter2".into(),
            url: None,
            totp_seed: None,
            notes: None,
        };
        let dbg = format!("{:?}", login);
        assert!(
            !dbg.contains("hunter2"),
            "password must not appear in Debug"
        );
        assert!(!dbg.contains("admin"), "username must not appear in Debug");
        assert!(dbg.contains("<redacted>"), "must show redaction marker");

        let api = SecretData::ApiKey {
            key: "sk-secret-key-value".into(),
            endpoint: None,
            notes: None,
        };
        let dbg = format!("{:?}", api);
        assert!(
            !dbg.contains("sk-secret"),
            "API key must not appear in Debug"
        );
        assert!(dbg.contains("ApiKey"));
    }

    #[test]
    fn origin_rejects_wildcards_and_bad_hosts() {
        let ok = |scheme: &str, host: &str, port: u16| {
            Origin {
                scheme: scheme.into(),
                host: host.into(),
                port,
            }
            .validated()
        };
        assert!(ok("https", "api.example.com", 443).is_ok());
        assert!(ok("HTTPS", "API.Example.COM", 443).is_ok());
        assert!(ok("http", "[::1]", 8080).is_ok());
        assert!(ok("https", "*", 443).is_err());
        assert!(ok("https", "*.example.com", 443).is_err());
        assert!(ok("https", "", 443).is_err());
        assert!(ok("https", "  ", 443).is_err());
        assert!(ok("https", "exa mple.com", 443).is_err());
        assert!(ok("https", "example.com/path", 443).is_err());
        assert!(ok("https", "user@example.com", 443).is_err());
        assert!(ok("ftp", "example.com", 21).is_err());
        assert!(ok("https", "example.com", 0).is_err());
        let normalized = ok("HTTPS", "API.Example.COM", 443).unwrap();
        assert_eq!(normalized.scheme, "https");
        assert_eq!(normalized.host, "api.example.com");
    }

    #[test]
    fn origin_port_is_required_in_json() {
        let missing: std::result::Result<Origin, _> =
            serde_json::from_str(r#"{"scheme":"https","host":"example.com"}"#);
        assert!(missing.is_err());
    }

    #[test]
    fn policy_validation_normalizes_and_filters_headers() {
        let policy: ProxyPolicy = serde_json::from_str(
            r#"{"allowed_origins":[{"scheme":"HTTPS","host":"A.example.com","port":443},
                                   {"scheme":"https","host":"a.example.com","port":443}],
                "extra_auth_headers":["X-Custom-Token","authorization"],
                "drop_response_body":true}"#,
        )
        .unwrap();
        let policy = policy.validated().unwrap();
        assert_eq!(policy.allowed_origins.len(), 1);
        assert_eq!(
            policy.extra_auth_headers,
            vec!["x-custom-token".to_string()]
        );
        assert!(policy.drop_response_body);
        assert!(policy.origin_allowed("https", "a.example.com", 443));
        assert!(!policy.origin_allowed("https", "a.example.com", 444));
        assert!(!policy.origin_allowed("http", "a.example.com", 443));
        assert!(!policy.origin_allowed("https", "b.example.com", 443));
        assert!(policy.auth_header_allowed("AUTHORIZATION"));
        assert!(policy.auth_header_allowed("x-api-key"));
        assert!(policy.auth_header_allowed("X-CUSTOM-TOKEN"));
        assert!(!policy.auth_header_allowed("cookie"));
    }

    #[test]
    fn policy_rejects_reserved_and_malformed_headers() {
        for bad in [
            "Host",
            "content-length",
            "Set-Cookie",
            "bad header",
            "",
            "a:b",
        ] {
            let policy = ProxyPolicy {
                extra_auth_headers: vec![bad.to_string()],
                ..ProxyPolicy::default()
            };
            assert!(policy.validated().is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn policy_defaults_when_fields_are_absent() {
        let policy: ProxyPolicy = serde_json::from_str("{}").unwrap();
        assert!(policy.is_default());
        assert!(!policy.origin_allowed("https", "example.com", 443));
        let unknown: std::result::Result<ProxyPolicy, _> =
            serde_json::from_str(r#"{"allowed_origin":[]}"#);
        assert!(unknown.is_err(), "typos must not be silently ignored");
    }

    /// Fake but well-formed PEM armor around a short base64 body.
    const FAKE_KEY_PEM: &str =
        "-----BEGIN PRIVATE KEY-----\nQUJDREVG\nR0hJSktM\n-----END PRIVATE KEY-----\n";

    /// Fake certificate PEM.
    const FAKE_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----\n";

    /// Legacy note content: base64 of the schema-versioned JSON bundle.
    fn legacy_content(schema_version: u64) -> String {
        let json = serde_json::json!({
            "schema_version": schema_version,
            "certificate_pem": FAKE_CERT_PEM,
            "private_key_pem": FAKE_KEY_PEM,
        });
        STANDARD.encode(json.to_string())
    }

    /// The x509 bundle variant serializes with the snake_case tag and omits an
    /// absent chain.
    #[test]
    fn x509_bundle_serialization_and_fields() {
        let bundle = SecretData::X509Bundle {
            certificate_pem: FAKE_CERT_PEM.into(),
            private_key_pem: FAKE_KEY_PEM.into(),
            chain_pem: None,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("\"type\":\"x509_bundle\""));
        assert!(!json.contains("chain_pem"));
        let restored: SecretData = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.secret_type(), SecretType::X509Bundle);
        assert_eq!(bundle.primary_value(), FAKE_KEY_PEM);
        assert_eq!(
            bundle.get_field("certificate_pem"),
            Some(FAKE_CERT_PEM.to_string())
        );
        assert_eq!(
            bundle.get_field("private_key_pem"),
            Some(FAKE_KEY_PEM.to_string())
        );
        assert_eq!(bundle.get_field("chain_pem"), None);
        assert_eq!(
            bundle.field_names(),
            vec!["certificate_pem", "private_key_pem"]
        );
        assert_eq!(bundle.bare_value(), None);
        let dbg = format!("{bundle:?}");
        assert!(!dbg.contains("BEGIN"), "Debug must not print PEM: {dbg}");
        assert!(!bundle.redacted_preview().contains("QUJD"));
    }

    /// A real bundle yields its parts, chain included.
    #[test]
    fn as_x509_bundle_returns_real_bundle_parts() {
        let bundle = SecretData::X509Bundle {
            certificate_pem: FAKE_CERT_PEM.into(),
            private_key_pem: FAKE_KEY_PEM.into(),
            chain_pem: Some("CHAIN".into()),
        };
        let material = bundle.as_x509_bundle().unwrap().expect("bundle");
        assert_eq!(material.certificate_pem, FAKE_CERT_PEM);
        assert_eq!(material.private_key_pem, FAKE_KEY_PEM);
        assert_eq!(material.chain_pem.as_deref(), Some("CHAIN"));
        let dbg = format!("{material:?}");
        assert!(!dbg.contains("BEGIN") && !dbg.contains("QUJD"), "{dbg}");
    }

    /// A schema-1 legacy note decodes to its certificate and key.
    #[test]
    fn as_x509_bundle_decodes_legacy_note() {
        let note = SecretData::Note {
            content: legacy_content(1),
        };
        let material = note.as_x509_bundle().unwrap().expect("legacy bundle");
        assert_eq!(material.certificate_pem, FAKE_CERT_PEM);
        assert_eq!(material.private_key_pem, FAKE_KEY_PEM);
        assert_eq!(material.chain_pem, None);
        let padded_with_newline = SecretData::Note {
            content: format!("{}\n", legacy_content(1)),
        };
        assert!(padded_with_newline.as_x509_bundle().unwrap().is_some());
    }

    /// Any other schema version is rejected loudly, not treated as a note.
    #[test]
    fn as_x509_bundle_rejects_other_schema_versions() {
        for version in [0u64, 2, 99] {
            let note = SecretData::Note {
                content: legacy_content(version),
            };
            assert!(
                matches!(note.as_x509_bundle(), Err(CredError::InvalidInput(_))),
                "schema_version {version} must be rejected"
            );
        }
        let missing = serde_json::json!({
            "certificate_pem": FAKE_CERT_PEM,
            "private_key_pem": FAKE_KEY_PEM,
        });
        let note = SecretData::Note {
            content: STANDARD.encode(missing.to_string()),
        };
        assert!(matches!(
            note.as_x509_bundle(),
            Err(CredError::InvalidInput(_))
        ));
    }

    /// Ordinary notes and non-bundle secrets are not bundles.
    #[test]
    fn as_x509_bundle_ignores_everything_else() {
        let cases: Vec<String> = vec![
            "just a note".to_string(),
            String::new(),
            "e30=".to_string(),
            STANDARD.encode(r#"{"hello":"world"}"#),
            STANDARD.encode("not json at all"),
        ];
        for content in cases {
            let note = SecretData::Note {
                content: content.clone(),
            };
            assert!(note.as_x509_bundle().unwrap().is_none(), "{content:?}");
        }
        let api = SecretData::ApiKey {
            key: "k".into(),
            endpoint: None,
            notes: None,
        };
        assert!(api.as_x509_bundle().unwrap().is_none());
    }

    /// The PEM body is the base64 text without armor, line breaks or spaces.
    #[test]
    fn unwrap_pem_body_strips_armor_and_whitespace() {
        assert_eq!(
            unwrap_pem_body(FAKE_KEY_PEM).as_deref(),
            Some("QUJDREVGR0hJSktM")
        );
        assert_eq!(
            unwrap_pem_body("-----BEGIN X-----\r\n AB CD \r\nEF\r\n-----END X-----").as_deref(),
            Some("ABCDEF")
        );
        assert_eq!(
            unwrap_pem_body("-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\nQUJD\n-----END X-----\n")
                .as_deref(),
            Some("QUJD")
        );
        assert_eq!(unwrap_pem_body("no armor here"), None);
        assert_eq!(unwrap_pem_body("-----BEGIN X-----\nQUJD\n"), None);
        assert_eq!(
            unwrap_pem_body("-----BEGIN X-----\n-----END X-----\n"),
            None
        );
    }
}
