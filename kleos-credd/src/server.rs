//! HTTP server setup for credd.

use std::path::PathBuf;

use axum::Router;
use kleos_cred::agent_keys_file::FileAgentKeyStore;
use kleos_cred::crypto::{derive_key, KEY_SIZE};
use kleos_lib::config::{Config, EncryptionMode};
use kleos_lib::db::migrations::run_migrations;
use kleos_lib::db::Database;
use zeroize::Zeroizing;

use crate::build_router;
use crate::listener;
use crate::profile::RunProfile;
use crate::state::AppState;

/// Build the master encryption key from credd auth-mode inputs.
///
/// Supported modes are `yubikey` (default), `password`, and `keyfile`.
fn resolve_master_key(
    auth_mode: &str,
    master_password: Option<String>,
    keyfile: Option<PathBuf>,
) -> anyhow::Result<[u8; KEY_SIZE]> {
    match auth_mode {
        "yubikey" => {
            tracing::info!(auth_mode = "yubikey", "deriving master key from YubiKey");
            kleos_cred::yubikey::derive_master_key()
                .map_err(|e| anyhow::anyhow!("YubiKey unlock failed: {e}"))
        }
        "password" => {
            let password = match master_password {
                Some(pw) => pw,
                None => {
                    eprintln!("Enter master password: ");
                    rpassword::read_password()?
                }
            };
            tracing::info!(auth_mode = "password", "deriving master key from password");
            let derived = derive_key(1, password.as_bytes(), None);
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&derived[..]);
            Ok(key)
        }
        "keyfile" => {
            let path = keyfile.unwrap_or_else(|| {
                std::env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        std::env::var("HOME")
                            .map(|h| PathBuf::from(h).join(".config"))
                            .unwrap_or_else(|_| PathBuf::from("."))
                    })
                    .join("cred")
                    .join("master.key")
            });

            let hex_str = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("failed to read keyfile {}: {e}", path.display()))?;
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| anyhow::anyhow!("keyfile {} is not valid hex: {e}", path.display()))?;

            if bytes.len() != KEY_SIZE {
                anyhow::bail!(
                    "keyfile {} contains {} bytes, expected {}",
                    path.display(),
                    bytes.len(),
                    KEY_SIZE
                );
            }

            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        other => {
            anyhow::bail!(
                "unknown CREDD_AUTH_MODE `{other}`; expected `yubikey`, `password`, or `keyfile`"
            )
        }
    }
}

/// Resolve optional at-rest DB encryption key using the legacy credd path.
fn resolve_db_encryption_key(enc_config: &Config) -> anyhow::Result<Option<[u8; 32]>> {
    match enc_config.encryption.mode {
        EncryptionMode::None => Ok(None),
        EncryptionMode::Yubikey => {
            tracing::info!("at-rest encryption mode: yubikey -- touch slot 2 to unlock database");
            let challenge = kleos_cred::yubikey::get_or_create_challenge()
                .map_err(|e| anyhow::anyhow!("YubiKey challenge: {e}"))?;
            let response = kleos_cred::yubikey::challenge_response(&challenge)
                .map_err(|e| anyhow::anyhow!("YubiKey response: {e}"))?;
            let derived = derive_key(0, b"", Some(&response));
            let mut key = [0u8; 32];
            key.copy_from_slice(&derived[..]);
            Ok(Some(key))
        }
        // Custody: slot 1 + /var/lib/phylax/challenge, no slot-2 fallback.
        EncryptionMode::Custody => kleos_cred::encryption::resolve_at_rest_key(enc_config, None),
        _ => {
            let mode_name = format!("{:?}", enc_config.encryption.mode).to_ascii_lowercase();
            tracing::info!(mode = %mode_name, "resolving at-rest encryption key");
            let key = kleos_lib::encryption::resolve_key(enc_config)
                .map_err(|e| anyhow::anyhow!("encryption key: {e}"))?;
            Ok(key)
        }
    }
}

/// Build the runtime router from app state and serve through existing listeners.
///
/// `profile` is installed on the `AppState` before `build_router` runs, so the
/// builder (and the auth middleware) see the same profile the listeners use.
#[tracing::instrument(
    skip(master_key, bootstrap_master, file_agent_keys, encryption_key, build_router),
    fields(listen = %listen, db_path = %db_path, profile = ?profile)
)]
// Run credd using a caller-provided router builder for composed daemons.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_router_builder<B>(
    listen: &str,
    db_path: &str,
    master_key: [u8; KEY_SIZE],
    bootstrap_master: Option<Zeroizing<String>>,
    file_agent_keys: FileAgentKeyStore,
    encryption_key: Option<[u8; 32]>,
    profile: RunProfile,
    build_router: B,
) -> anyhow::Result<()>
where
    B: FnOnce(AppState) -> Router,
{
    // Connect to database with optional at-rest encryption and apply schema updates.
    let db = Database::connect_encrypted(db_path, encryption_key).await?;
    db.write(|conn| run_migrations(conn)).await?;

    let state = AppState::with_bootstrap(db, master_key, bootstrap_master, file_agent_keys)
        .with_run_profile(profile);
    let app = build_router(state);

    // If neither CREDD_SOCKET nor CREDD_BIND is set, treat --listen as CREDD_BIND
    // so old single-listener CLI behavior remains unchanged.
    if std::env::var("CREDD_SOCKET").is_err() && std::env::var("CREDD_BIND").is_err() {
        std::env::set_var("CREDD_BIND", listen);
    }

    listener::serve_with_profile(app, profile).await
}

/// Resolve the TCP listen string the listeners will actually use.
///
/// Mirrors [`run_with_router_builder`] and `listener::serve`: an explicit
/// `CREDD_BIND` wins; with neither `CREDD_SOCKET` nor `CREDD_BIND` set, `listen`
/// is the bind; with only `CREDD_SOCKET` set there is no TCP listener.
pub fn effective_tcp_bind(
    listen: &str,
    socket_env: Option<&str>,
    bind_env: Option<&str>,
) -> Option<String> {
    match (socket_env, bind_env) {
        (_, Some(bind)) => Some(bind.to_string()),
        (None, None) => Some(listen.to_string()),
        (Some(_), None) => None,
    }
}

/// Run the custody startup checks for a daemon about to serve `listen` with the
/// vault at `db_path`, with the process identity and listener env injected.
#[cfg(unix)]
pub fn custody_preflight_with(
    ctx: &crate::custody::CustodyContext,
    listen: &str,
    db_path: &str,
    socket_env: Option<&str>,
    bind_env: Option<&str>,
) -> Result<(), crate::custody::CustodyStartupError> {
    let tcp_bind = effective_tcp_bind(listen, socket_env, bind_env);
    crate::custody::preflight(ctx, std::path::Path::new(db_path), tcp_bind.as_deref())
}

/// Resolve startup inputs (auth mode + encryption mode) and run with a caller
/// supplied router builder.
///
/// Under [`RunProfile::Custody`] the custody preflight (uid, bind address,
/// vault file owner and mode) runs first, before any key material is touched,
/// and a refusal is returned as a typed
/// [`CustodyStartupError`](crate::custody::CustodyStartupError) inside the
/// `anyhow::Error`. The vault encryption mode is forced to
/// [`EncryptionMode::Custody`] regardless of env or the persisted marker.
#[tracing::instrument(
    skip(master_password, keyfile, build_router),
    fields(listen = %listen, db_path = %db_path, auth_mode = %auth_mode, profile = ?profile)
)]
// Resolve environment-backed startup inputs before serving a composed router.
pub async fn run_with_env<B>(
    listen: &str,
    db_path: &str,
    auth_mode: &str,
    master_password: Option<String>,
    keyfile: Option<PathBuf>,
    profile: RunProfile,
    build_router: B,
) -> anyhow::Result<()>
where
    B: FnOnce(AppState) -> Router,
{
    #[cfg(unix)]
    let ctx = crate::custody::CustodyContext::current();
    #[cfg(not(unix))]
    let ctx = ();
    run_with_env_as(
        &ctx,
        listen,
        db_path,
        auth_mode,
        master_password,
        keyfile,
        profile,
        build_router,
    )
    .await
}

/// Process identity handed to the custody preflight.
#[cfg(unix)]
pub type PreflightIdentity = crate::custody::CustodyContext;
/// Placeholder identity on platforms without the custody preflight.
#[cfg(not(unix))]
pub type PreflightIdentity = ();

/// [`run_with_env`] with the process identity injected, so tests can drive the
/// real startup path as a different uid. Production code calls `run_with_env`.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_env_as<B>(
    ctx: &PreflightIdentity,
    listen: &str,
    db_path: &str,
    auth_mode: &str,
    master_password: Option<String>,
    keyfile: Option<PathBuf>,
    profile: RunProfile,
    build_router: B,
) -> anyhow::Result<()>
where
    B: FnOnce(AppState) -> Router,
{
    if profile.is_custody() {
        #[cfg(unix)]
        custody_preflight_with(
            ctx,
            listen,
            db_path,
            std::env::var("CREDD_SOCKET").ok().as_deref(),
            std::env::var("CREDD_BIND").ok().as_deref(),
        )?;
        #[cfg(not(unix))]
        {
            let _ = ctx;
            anyhow::bail!("the custody profile requires a Unix platform");
        }
    }

    let master_key = resolve_master_key(auth_mode, master_password, keyfile)?;
    let mut enc_config = Config::from_env();
    // When ENGRAM_ENCRYPTION_MODE is not in the environment (the daemon was
    // started by systemd before encryption was enabled, or the unit was never
    // updated), fall back to the persisted ~/.config/cred/encryption-mode
    // marker so we never silently open an already-encrypted vault as plaintext.
    // Mirrors the cred CLI's resolution exactly.
    if std::env::var("ENGRAM_ENCRYPTION_MODE").is_err() {
        if let Some(mode) = kleos_cred::encryption::read_persisted_encryption_mode() {
            enc_config.encryption.mode = mode;
        }
    }
    // Custody never trusts env or a persisted marker for the vault key source.
    if profile.is_custody() {
        enc_config.encryption.mode = EncryptionMode::Custody;
    }
    let encryption_key = resolve_db_encryption_key(&enc_config)?;
    // Persist the resolved mode so a later restart without ENGRAM_ENCRYPTION_MODE
    // still opens the encrypted vault correctly instead of silently as plaintext.
    // Mirrors the cred CLI. Best-effort. Custody does not persist: it has no
    // home directory and always forces its own mode.
    if !profile.is_custody() && enc_config.encryption.mode != EncryptionMode::None {
        if let Err(e) = kleos_cred::encryption::persist_encryption_mode(&enc_config.encryption.mode)
        {
            tracing::warn!(error = %e, "could not persist encryption-mode marker");
        }
    }
    let bootstrap_master = crate::bootstrap::load_bootstrap_blob(&master_key).await?;
    if bootstrap_master.is_some() {
        tracing::info!(
            "loaded bootstrap.enc from {}",
            crate::bootstrap::blob_path().display()
        );
    }

    let file_agent_keys = FileAgentKeyStore::load()?;

    run_with_router_builder(
        listen,
        db_path,
        master_key,
        bootstrap_master,
        file_agent_keys,
        encryption_key,
        profile,
        build_router,
    )
    .await
}

/// Run the credd HTTP server.
///
/// `master_key` is the 32-byte AES-256-GCM key credd uses to encrypt and
/// authenticate cred entries. The caller (main.rs) derives it from a YubiKey
/// challenge-response (default) or a password (opt-in), so this function does
/// not care how it was produced.
///
/// `bootstrap_master` is the bare per-host Kleos bearer decrypted from
/// `bootstrap.enc` at startup, or `None` if no blob is present. Used by the
/// `/bootstrap/kleos-bearer` endpoint to fetch per-agent bearers from Kleos.
///
/// `listen` is honored as a fallback `CREDD_BIND` if neither `CREDD_SOCKET`
/// nor `CREDD_BIND` env vars are set; otherwise the env wins. This preserves
/// the `--listen 127.0.0.1:4400` CLI argument behaviour for callers that
/// don't use env-based config.
#[tracing::instrument(
    skip(master_key, bootstrap_master, file_agent_keys, encryption_key),
    fields(listen = %listen, db_path = %db_path)
)]
// Serve the standalone credd router using pre-resolved runtime inputs.
pub async fn run(
    listen: &str,
    db_path: &str,
    master_key: [u8; KEY_SIZE],
    bootstrap_master: Option<Zeroizing<String>>,
    file_agent_keys: FileAgentKeyStore,
    encryption_key: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    run_with_router_builder(
        listen,
        db_path,
        master_key,
        bootstrap_master,
        file_agent_keys,
        encryption_key,
        RunProfile::Legacy,
        build_router,
    )
    .await
}
