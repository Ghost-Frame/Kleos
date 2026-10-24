//! Application state for credd daemon.

use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kleos_cred::crypto::KEY_SIZE;
use kleos_lib::db::Database;
use kleos_lib::ratelimit::RateLimiter;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use tracing::warn;
use zeroize::Zeroizing;

use kleos_cred::agent_keys_file::FileAgentKeyStore;
use kleos_lib::auth_piv::RequestSigner;

use crate::profile::RunProfile;

/// Per-category domain allowlist for the credential proxy.
///
/// When present, the proxy only forwards requests to domains listed for
/// the secret's category. Categories without an entry are denied.
/// Loaded from `~/.config/cred/proxy-domains.json`.
pub type ProxyDomainAllowlist = std::collections::HashMap<String, Vec<String>>;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    /// Master encryption key wrapped in `Zeroizing` so the key material is
    /// scrubbed from memory when the last `Arc` reference is dropped.
    pub master_key: Arc<Zeroizing<[u8; KEY_SIZE]>>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Decrypted bare Kleos bearer loaded from `bootstrap.enc` at startup.
    /// `None` if the blob is absent (the `/bootstrap/kleos-bearer` endpoint
    /// returns 404 in that case). Wrapped in `Zeroizing` so the bearer is
    /// scrubbed from memory when the AppState is dropped.
    pub bootstrap_master: Option<Arc<Zeroizing<String>>>,
    /// File-backed scoped agent-key store for `/bootstrap/kleos-bearer`.
    /// Separate from the DB-backed `cred_agent_keys` table used by the
    /// three-tier resolve handlers; lives at `~/.config/cred/agent-keys.json`
    /// so a fresh shell can read it before the cred DB is unlocked.
    pub file_agent_keys: Arc<Mutex<FileAgentKeyStore>>,
    /// PIV slot 9A (AUTHENTICATION) public keys, loaded from
    /// `~/.config/cred/piv-9a-pubkeys/*.pem` (multi-key) or the legacy
    /// `~/.config/cred/piv-9a-pubkey.pem` (single-key) at startup. The
    /// ECDH bootstrap handler tries each key until one verifies.
    pub piv_9a_pubkeys: Arc<Vec<VerifyingKey>>,
    /// PIV slot 9D (KEY_MANAGEMENT) public key, loaded from
    /// `~/.config/cred/piv-9d-pubkey.pem` at startup. Informational only
    /// for the server (the YubiKey holds the corresponding private key
    /// and the ECDH op happens via `kleos_cred::piv::ecdh_agree`).
    pub piv_9d_pubkey: Option<Arc<PublicKey>>,
    /// PIV request signer for authenticating to Kleos API when resolving
    /// [CRED:v3] entries. Initialized at startup via from_env_or_file.
    pub kleos_signer: Option<Arc<RequestSigner>>,
    /// Per-category domain allowlist for proxy requests. When `Some`, the
    /// proxy denies requests to domains not listed for the category.
    pub proxy_domain_allowlist: Option<Arc<ProxyDomainAllowlist>>,
    /// Run profile the daemon was started with. Decides which routes are
    /// mounted and whether the master bearer is accepted over TCP.
    pub run_profile: RunProfile,
    /// Test seam: when true the proxy skips the SSRF check for loopback IP
    /// literals so integration tests can use a local upstream. Always false
    /// outside code that calls [`AppState::with_loopback_proxy_for_tests`];
    /// it is never read from the environment or a config file.
    pub proxy_allow_loopback: bool,
    /// Test seam: PEM of one extra root CA the proxy's outbound HTTPS client
    /// trusts, so an integration test can reach a TLS upstream signed by a
    /// throwaway CA without ever disabling certificate verification. `None`
    /// outside code that calls [`AppState::with_extra_root_ca_for_tests`]; it
    /// is never read from the environment or a config file.
    pub proxy_extra_root_ca: Option<Arc<Vec<u8>>>,
}

impl AppState {
    pub fn new(db: Database, master_key: [u8; KEY_SIZE]) -> Self {
        let (piv_9a_pubkeys, piv_9d_pubkey) = load_piv_pubkeys();
        Self {
            db: Arc::new(db),
            master_key: Arc::new(Zeroizing::new(master_key)),
            rate_limiter: Arc::new(RateLimiter::new()),
            bootstrap_master: None,
            file_agent_keys: Arc::new(Mutex::new(FileAgentKeyStore::default())),
            piv_9a_pubkeys,
            piv_9d_pubkey,
            kleos_signer: None,
            proxy_domain_allowlist: load_proxy_domain_allowlist(),
            run_profile: RunProfile::Legacy,
            proxy_allow_loopback: false,
            proxy_extra_root_ca: None,
        }
    }

    /// Return this state with `profile` installed as the run profile.
    pub fn with_run_profile(mut self, profile: RunProfile) -> Self {
        self.run_profile = profile;
        self
    }

    /// Return this state with the proxy SSRF loopback exemption enabled.
    ///
    /// Test-only seam: lets an integration test point the proxy at a
    /// `127.0.0.1` upstream. Production code must never call this.
    pub fn with_loopback_proxy_for_tests(mut self) -> Self {
        self.proxy_allow_loopback = true;
        self
    }

    /// Return this state with `pem` added to the roots the proxy trusts.
    ///
    /// Test-only seam: lets an integration test run an mTLS upstream whose
    /// certificate chains to a throwaway CA. Production code must never call
    /// this.
    pub fn with_extra_root_ca_for_tests(mut self, pem: Vec<u8>) -> Self {
        self.proxy_extra_root_ca = Some(Arc::new(pem));
        self
    }

    /// Constructor variant that includes the bootstrap bearer (loaded by
    /// main.rs after deriving the master key) and the file-backed agent
    /// key store.
    pub fn with_bootstrap(
        db: Database,
        master_key: [u8; KEY_SIZE],
        bootstrap_master: Option<Zeroizing<String>>,
        file_agent_keys: FileAgentKeyStore,
    ) -> Self {
        let (piv_9a_pubkeys, piv_9d_pubkey) = load_piv_pubkeys();
        let kleos_signer = init_kleos_signer();
        Self {
            db: Arc::new(db),
            master_key: Arc::new(Zeroizing::new(master_key)),
            rate_limiter: Arc::new(RateLimiter::new()),
            bootstrap_master: bootstrap_master.map(Arc::new),
            file_agent_keys: Arc::new(Mutex::new(file_agent_keys)),
            piv_9a_pubkeys,
            piv_9d_pubkey,
            kleos_signer,
            proxy_domain_allowlist: load_proxy_domain_allowlist(),
            run_profile: RunProfile::Legacy,
            proxy_allow_loopback: false,
            proxy_extra_root_ca: None,
        }
    }
}

/// Load per-category proxy domain allowlist from
/// `~/.config/cred/proxy-domains.json`. Format:
/// ```json
/// { "aws": ["*.amazonaws.com"], "github": ["api.github.com"], "*": ["*"] }
/// ```
/// The wildcard category `"*"` matches any category. Domain entries support
/// leading `*.` prefix for subdomain matching. Returns None if the file does
/// not exist; with no allowlist the legacy-profile proxy denies every request
/// (F09). The custody profile ignores this file and uses each secret's
/// `allowed_origins` instead.
fn load_proxy_domain_allowlist() -> Option<Arc<ProxyDomainAllowlist>> {
    let path = cred_config_dir().join("proxy-domains.json");
    if !path.exists() {
        tracing::info!(
            "no proxy domain allowlist at {}; the legacy-profile proxy denies by default",
            path.display()
        );
        return None;
    }
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str::<ProxyDomainAllowlist>(&json) {
            Ok(mut list) => {
                // The proxy lowercases the target host before matching, so
                // normalise the configured patterns too -- otherwise an operator
                // who writes `*.AMAZONAWS.COM` would have it silently never match.
                for patterns in list.values_mut() {
                    for pattern in patterns.iter_mut() {
                        *pattern = pattern.to_lowercase();
                    }
                }
                tracing::info!(
                    categories = list.len(),
                    path = %path.display(),
                    "loaded proxy domain allowlist"
                );
                Some(Arc::new(list))
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path.display(), "proxy domain allowlist parse error");
                None
            }
        },
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "proxy domain allowlist read error");
            None
        }
    }
}

/// Standard cred config dir resolution (matches kleos_cred::piv::config_dir
/// and kleos_cred::yubikey::config_dir).
fn cred_config_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| PathBuf::from("."))
        });
    base.join("cred")
}

/// Load PIV 9A pubkeys from `~/.config/cred/piv-9a-pubkeys/*.pem` (multi-key
/// directory) with fallback to the legacy `~/.config/cred/piv-9a-pubkey.pem`
/// (single file). Also loads 9D from `piv-9d-pubkey.pem` as before.
fn load_piv_pubkeys() -> (Arc<Vec<VerifyingKey>>, Option<Arc<PublicKey>>) {
    let dir = cred_config_dir();
    let mut keys_9a = Vec::new();

    // Multi-key directory (preferred)
    let keys_dir = dir.join("piv-9a-pubkeys");
    if keys_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&keys_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "pem") {
                    match std::fs::read_to_string(&path) {
                        Ok(pem) => match VerifyingKey::from_public_key_pem(&pem) {
                            Ok(k) => {
                                tracing::info!(path = %path.display(), "loaded 9A pubkey");
                                keys_9a.push(k);
                            }
                            Err(e) => {
                                warn!(path = %path.display(), error = %e, "9A pubkey unparseable")
                            }
                        },
                        Err(e) => {
                            warn!(path = %path.display(), error = %e, "9A pubkey read failed")
                        }
                    }
                }
            }
        }
    }

    // Legacy single-file fallback
    if keys_9a.is_empty() {
        let pa = dir.join("piv-9a-pubkey.pem");
        if pa.exists() {
            match std::fs::read_to_string(&pa) {
                Ok(pem) => match VerifyingKey::from_public_key_pem(&pem) {
                    Ok(k) => {
                        tracing::info!(path = %pa.display(), "loaded legacy 9A pubkey");
                        keys_9a.push(k);
                    }
                    Err(e) => {
                        warn!(path = %pa.display(), error = %e, "piv-9a pubkey unparseable; ECDH disabled")
                    }
                },
                Err(e) => warn!(path = %pa.display(), error = %e, "piv-9a pubkey read failed"),
            }
        }
    }

    if keys_9a.is_empty() {
        warn!("no PIV 9A pubkeys found; ECDH bootstrap will be unavailable");
    } else {
        tracing::info!(count = keys_9a.len(), "PIV 9A pubkeys loaded");
    }

    let key_9d = {
        let pd = dir.join("piv-9d-pubkey.pem");
        if pd.exists() {
            match std::fs::read_to_string(&pd) {
                Ok(pem) => match PublicKey::from_public_key_pem(&pem) {
                    Ok(k) => Some(Arc::new(k)),
                    Err(e) => {
                        warn!(path = %pd.display(), error = %e, "piv-9d pubkey unparseable");
                        None
                    }
                },
                Err(e) => {
                    warn!(path = %pd.display(), error = %e, "piv-9d pubkey read failed");
                    None
                }
            }
        } else {
            None
        }
    };

    (Arc::new(keys_9a), key_9d)
}

/// Build a soft-tier `RequestSigner` from `KLEOS_IDENTITY_KEY` (hex) or
/// `~/.kleos/identity.key`. This helper is used when
/// `CREDD_KLEOS_SIGNER_TIER=soft` is set to bypass PIV entirely, and is
/// also callable from tests with an explicit hex key via the env var.
fn build_soft_signer(host: &str) -> Option<Arc<RequestSigner>> {
    // Mirror the T2 branch of RequestSigner::from_env_or_file exactly.
    if let Ok(hex_key) = std::env::var("KLEOS_IDENTITY_KEY") {
        let bytes = match hex::decode(hex_key.trim()) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "KLEOS_IDENTITY_KEY bad hex; cannot build soft signer");
                return None;
            }
        };
        if bytes.len() != 32 {
            tracing::error!(
                got = bytes.len(),
                "KLEOS_IDENTITY_KEY must be 32 bytes; cannot build soft signer"
            );
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signer = RequestSigner::from_key_bytes(arr, host, "credd", "daemon");
        tracing::info!(
            tier = %signer.tier(),
            fingerprint = %signer.fingerprint(),
            "Kleos soft signer initialized from KLEOS_IDENTITY_KEY"
        );
        return Some(Arc::new(signer));
    }

    // Fall back to file path (KLEOS_IDENTITY_KEY_FILE or ~/.kleos/identity.key).
    let key_path = if let Ok(p) = std::env::var("KLEOS_IDENTITY_KEY_FILE") {
        PathBuf::from(p)
    } else {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        match home {
            Some(h) => h.join(".kleos").join("identity.key"),
            None => {
                tracing::error!("cannot determine home directory for soft signer key path");
                return None;
            }
        }
    };

    if !key_path.exists() {
        tracing::warn!(
            path = %key_path.display(),
            "soft identity key file not found; Kleos vault fallback will use bootstrap bearer"
        );
        return None;
    }

    match RequestSigner::from_file(&key_path, host, "credd", "daemon") {
        Ok(signer) => {
            tracing::info!(
                tier = %signer.tier(),
                fingerprint = %signer.fingerprint(),
                path = %key_path.display(),
                "Kleos soft signer initialized from key file"
            );
            Some(Arc::new(signer))
        }
        Err(e) => {
            tracing::error!(error = %e, path = %key_path.display(), "failed to load soft signer from key file");
            None
        }
    }
}

fn init_kleos_signer() -> Option<Arc<RequestSigner>> {
    let host = kleos_lib::kleos_env("URL").unwrap_or_else(|_| "http://localhost:4200".into());

    // When CREDD_KLEOS_SIGNER_TIER=soft, skip PIV entirely and load only
    // the soft Ed25519 identity key. This is the correct mode for headless
    // boxes where a YubiKey may be physically present but PIV is unconfigured.
    if std::env::var("CREDD_KLEOS_SIGNER_TIER").as_deref() == Ok("soft") {
        tracing::info!("CREDD_KLEOS_SIGNER_TIER=soft: bypassing PIV, using soft Ed25519 signer");
        return build_soft_signer(&host);
    }

    match RequestSigner::from_env_or_file(&host, "credd", "daemon") {
        Ok(Some(signer)) => {
            tracing::info!(
                tier = %signer.tier(),
                fingerprint = %signer.fingerprint(),
                "Kleos request signer initialized for vault fallback"
            );
            Some(Arc::new(signer))
        }
        Ok(None) => {
            tracing::warn!(
                "no PIV/software key found; Kleos vault fallback will use bootstrap bearer"
            );
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize Kleos request signer");
            None
        }
    }
}

impl Deref for AppState {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

#[cfg(test)]
/// Unit tests for signer-tier selection and the soft_signing_key accessor.
mod tests {
    use super::*;

    /// Guard that restores environment variables when dropped. Prevents
    /// cross-test env bleed when tests set/unset process-level env vars.
    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        /// Save the current value of each variable and set the new value.
        /// Pass `None` as `value` to unset the variable.
        fn set(pairs: &[(&str, Option<&str>)]) -> Self {
            let vars = pairs
                .iter()
                .map(|(k, v)| {
                    let old = std::env::var(k).ok();
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                    (k.to_string(), old)
                })
                .collect();
            Self { vars }
        }
    }

    impl Drop for EnvGuard {
        /// Restore all saved variables when the guard goes out of scope.
        fn drop(&mut self) {
            for (k, old) in &self.vars {
                match old {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// A deterministic 32-byte test key in hex (all 0x42 bytes).
    const TEST_KEY_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    #[test]
    fn soft_tier_env_produces_soft_signer_with_accessible_signing_key() {
        // Serial guard: set env vars, run, restore on drop.
        let _guard = EnvGuard::set(&[
            ("CREDD_KLEOS_SIGNER_TIER", Some("soft")),
            ("KLEOS_IDENTITY_KEY", Some(TEST_KEY_HEX)),
            // Prevent any real KLEOS_URL / ENGRAM_URL from leaking in.
            ("KLEOS_URL", Some("http://test.local:4200")),
        ]);

        let signer_opt = init_kleos_signer();
        let signer = signer_opt.expect("signer must be Some for soft tier with known key");

        assert_eq!(
            signer.tier(),
            "soft",
            "signer tier must be 'soft' when CREDD_KLEOS_SIGNER_TIER=soft"
        );

        assert!(
            signer.soft_signing_key().is_some(),
            "soft_signing_key() must return Some for a soft-tier signer"
        );
    }

    #[test]
    fn build_soft_signer_returns_soft_tier_and_key_accessor() {
        // Unit-test the helper directly, bypassing init_kleos_signer env check.
        let _guard = EnvGuard::set(&[
            ("KLEOS_IDENTITY_KEY", Some(TEST_KEY_HEX)),
            // Unset file override so the env-var path is taken.
            ("KLEOS_IDENTITY_KEY_FILE", None),
        ]);

        let signer_opt = build_soft_signer("http://test.local:4200");
        let signer =
            signer_opt.expect("build_soft_signer must return Some when KLEOS_IDENTITY_KEY is set");

        assert_eq!(signer.tier(), "soft");
        assert!(signer.soft_signing_key().is_some());

        // Verify the key bytes round-trip.
        let key_bytes = signer
            .ed25519_secret_bytes()
            .expect("ed25519_secret_bytes must be Some");
        assert_eq!(key_bytes, [0x42u8; 32]);
    }
}
