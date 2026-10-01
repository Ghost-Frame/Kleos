//! Cred CLI - YubiKey-encrypted credential manager.
//!
//! Compatible with private cred's data format when using legacy mode.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
#[allow(deprecated)]
use kleos_cred::crypto::{
    decrypt as crypto_decrypt, decrypt_recovery, derive_key_legacy, encrypt as crypto_encrypt,
    encrypt_recovery, generate_hmac_secret, KEY_SIZE,
};
use kleos_cred::storage;
use kleos_cred::types::SecretData;
use kleos_cred::yubikey;
use kleos_lib::db::Database;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
use zeroize::{Zeroize, Zeroizing};

/// Single canonical user_id for the local cred SQLite store.
///
/// The cred CLI is host-local and single-user: only the YubiKey holder can
/// unlock the vault. Memory #12624 captured a regression where `cmd_store`,
/// `cmd_get`, and friends used `user_id=0` while `cmd_bootstrap_wrap` used
/// `user_id=1`, so secrets stored via `cred store ...` were invisible to
/// `cred bootstrap wrap ...`.
///
/// `1` is chosen to match the rest of the Kleos system, where user_id=1 is
/// the canonical local-system user. A startup migration in
/// [`migrate_legacy_user_id_zero_rows`] lifts any pre-existing user_id=0
/// rows to user_id=1 the first time a fixed binary runs.
const CRED_USER_ID: i64 = 1;
const CRED_GET_SESSION_TOKEN_ENV: &str = "CRED_GET_SESSION_TOKEN";
const CRED_GET_SESSION_TTL_SECS_ENV: &str = "CRED_GET_SESSION_TTL_SECS";
const CRED_AGENT_CONTEXT_ENV: &str = "CRED_AGENT_CONTEXT";
const AI_AGENT_ENV: &str = "AI_AGENT";
const DEFAULT_CRED_GET_SESSION_TTL_SECS: i64 = 8 * 60 * 60;

/// YubiKey-encrypted credential manager.
#[derive(Parser)]
#[command(name = "cred", version, about)]
struct Cli {
    /// How cred derives its master key. `yubikey` (default) does an HMAC-SHA1
    /// challenge against slot 2. `password` reads --master-password / stdin
    /// and derives via the same Argon2id KDF. `keyfile` reads the pre-derived
    /// 32-byte key (hex-encoded) from a file -- for unattended servers.
    #[arg(long, default_value = "yubikey", env = "CRED_AUTH_MODE", global = true)]
    auth_mode: String,

    /// Master password (only used when --auth-mode=password).
    #[arg(long, env = "CRED_MASTER_PASSWORD", global = true)]
    master_password: Option<String>,

    /// Path to keyfile containing hex-encoded 32-byte master key
    /// (only used when --auth-mode=keyfile).
    #[arg(long, env = "CRED_KEYFILE", global = true)]
    keyfile: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize: generate HMAC secret, program YubiKey, create recovery kit
    Init,
    /// Store a secret (prompts interactively)
    Store {
        /// Service name (e.g., grafana, postgres)
        service: String,
        /// Key name (e.g., admin, api-key)
        key: String,
        /// Secret type: api-key, login, oauth-app, ssh-key, note, environment
        #[arg(short = 't', long, default_value = "api-key")]
        secret_type: String,
    },
    /// Retrieve a secret
    Get {
        /// Service name
        service: String,
        /// Key name
        key: String,
        /// Extract a specific field (e.g., password, username, key)
        #[arg(short, long)]
        field: Option<String>,
        /// Print raw value only (for piping)
        #[arg(short, long)]
        raw: bool,
        /// Hash the output value (e.g., argon2)
        #[arg(long)]
        hash: Option<String>,
    },
    /// List all stored secrets (values redacted)
    List {
        /// Filter by service name
        #[arg(short, long)]
        service: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Service name
        service: String,
        /// Key name
        key: String,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Recover: decrypt recovery file and program a new YubiKey
    Recover {
        /// Path to recovery.enc file
        #[arg(short, long, default_value = "~/.config/cred/recovery.enc")]
        from: String,
    },
    /// Bulk import secrets from stdin (service<TAB>key<TAB>value)
    Import {
        /// Dry run: show what would be imported without storing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Initialize a random per-deployment KDF salt (opt into KDF v2).
    /// Writes ~/.config/cred/kdf_salt (mode 0600). Export CRED_KDF_SALT_FILE
    /// pointing at it in every cred/credd/phylaxd environment to take effect.
    KdfSaltInit,
    /// Export all secrets as JSON (for backup/migration)
    Export {
        /// Write the JSON export to this file (created mode 0600) instead of
        /// printing plaintext secrets to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Manage agent keys for service authentication
    AgentKey {
        #[command(subcommand)]
        action: AgentKeyAction,
    },
    /// Run a command with a secret injected as env var or stdin.
    /// cred itself prints nothing of its own to stdout, so the secret never
    /// reaches a captured tool result. This is the agent-safe way to use creds.
    ///
    /// Examples:
    ///   cred exec kleos my-agent --env API_KEY -- \
    ///       curl -H "Authorization: Bearer $API_KEY" http://host/x
    ///   cred exec ssh some-host --field private_key --stdin -- ssh-add -
    Exec {
        /// Service name
        service: String,
        /// Key name
        key: String,
        /// Extract a specific field (default: bare value for ApiKey/Note)
        #[arg(short, long)]
        field: Option<String>,
        /// Env var name to inject the secret as (default: CRED_VALUE)
        #[arg(short = 'e', long, conflicts_with = "stdin")]
        env: Option<String>,
        /// Pipe secret to child stdin instead of an env var
        #[arg(long)]
        stdin: bool,
        /// Hash the value before injection (e.g., argon2)
        #[arg(long)]
        hash: Option<String>,
        /// Command and args to run. Use `--` to separate from cred's flags.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Mint or revoke short-lived session grants for `cred get`.
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },
    /// Interactive TUI for browsing and managing secrets
    Tui,
    /// Export the derived master key to a keyfile for unattended use.
    /// Run this once interactively (yubikey or password mode), then use
    /// CRED_AUTH_MODE=keyfile on the server. The keyfile is 64 hex chars
    /// (32 bytes), saved mode 0600.
    ExportKey {
        /// Output path (default: ~/.config/cred/master.key)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Manage the YubiKey-encrypted bootstrap blob (credd's master Kleos key)
    Bootstrap {
        #[command(subcommand)]
        cmd: BootstrapCmd,
    },
    /// Re-encrypt every stored secret and bootstrap.enc from the current
    /// master key (--auth-mode) to the key derived by --to. Stop phylaxd and
    /// credd first. Prints counts only, never secret values.
    Rekey {
        /// Target auth mode: yubikey, password, or keyfile.
        #[arg(long)]
        to: String,
        /// Keyfile for the target key when --to keyfile.
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
        /// Prove every row decrypts with the current key and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move this host's vault to another challenge file (same YubiKey secret):
    /// re-keys the encrypted vault file, every secret, and bootstrap.enc, then
    /// installs the new challenge. Stop phylaxd/credd first. Original files
    /// are kept as *.pre-rekey. Prints counts only.
    RekeyChallenge {
        /// The 32-byte challenge file to adopt (e.g. a challenge shared by several hosts).
        #[arg(long)]
        new_challenge: PathBuf,
        /// Verify everything on a temporary copy and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Copy secrets this vault lacks from another vault file that uses the
    /// same secret key; report (never overwrite) names whose values differ.
    MergeFrom {
        /// The other vault file (e.g. a copy of another host's cred.db).
        #[arg(long)]
        other: PathBuf,
        /// Report what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Import central CRED:v3 entries missing locally. Reads
    /// `kleos-cli list --category credential --json` on stdin.
    V3Import {
        /// Hex keyfile that decrypts the central entries to import. Defaults
        /// to this host's own key, which pulls entries written by any host
        /// sharing it.
        #[arg(long)]
        source_keyfile: Option<PathBuf>,
        /// Report what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print every local secret as a central CRED:v3 memory content line,
    /// encrypted with this host's secret key (ciphertext only), for
    /// `kleos-cli store --category credential --is-static`.
    V3Export,
    /// Report which keys can open the central CRED:v3 entries. Reads the JSON
    /// from `kleos-cli list --category credential --json` on stdin and prints
    /// only counts and entry names, never values.
    V3Audit {
        /// Extra hex keyfiles to test besides the current key (repeatable).
        #[arg(long = "also-keyfile")]
        also_keyfiles: Vec<PathBuf>,
        /// Extra 32-byte challenge files (from other machines) to test through
        /// the attached YubiKey's slot-2 secret (repeatable).
        #[arg(long = "also-challenge")]
        also_challenges: Vec<PathBuf>,
        /// List entry names per group instead of per-service counts.
        #[arg(long)]
        names: bool,
    },
    /// Passphrase-protected backup of the vault master key, for recovering
    /// the vault onto a replacement YubiKey. Passphrases are read from the
    /// terminal only; nothing secret is printed.
    RecoveryKit {
        #[command(subcommand)]
        cmd: RecoveryKitCmd,
    },
    /// Manage YubiKey PIV slots for ECDH bootstrap auth.
    /// See kleos-cred/src/piv.rs for the implementation.
    Piv {
        #[command(subcommand)]
        cmd: PivCmd,
    },
    /// SSH Certificate Authority backed by YubiKey PIV slot 9C.
    /// Sign agent public keys into short-lived SSH certificates.
    SshCa {
        #[command(subcommand)]
        cmd: SshCaCmd,
    },
}

#[derive(Subcommand)]
enum PivCmd {
    /// Generate ECDH (slot 9D KEY_MANAGEMENT) and signing (slot 9A
    /// AUTHENTICATION) P-256 keypairs on the YubiKey, generate
    /// self-signed certs, and export both public keys to
    /// ~/.config/cred/piv-{9a,9d}-pubkey.pem.
    Setup {
        /// Touch policy. `never` is fully automated; `cached` requires
        /// physical touch with a 15s cache. Use `never` for systemd /
        /// service contexts and `cached` for interactive use.
        #[arg(long, default_value = "never")]
        touch_policy: String,
    },
    /// Provision SSH CA key in PIV slot 9C (DIGITAL SIGNATURE).
    /// Generates P-256 keypair, self-signed cert, exports pubkey in
    /// PEM and SSH formats to ~/.config/cred/.
    SetupSshCa {
        /// Touch policy for SSH CA signing operations.
        #[arg(long, default_value = "never")]
        touch_policy: String,
    },
    /// Show which PIV slots have keys provisioned plus SHA-256 pubkey
    /// fingerprints.
    Status,
}

#[derive(Subcommand)]
enum SshCaCmd {
    /// Sign an agent's public key into a short-lived SSH certificate.
    /// Uses ssh-keygen -s with PKCS#11 backed by YubiKey slot 9C.
    Sign {
        /// Key identity string (typically agent name).
        #[arg(short = 'I', long)]
        identity: String,
        /// Valid principal(s), comma-separated.
        #[arg(short = 'n', long, default_value = "operator")]
        principal: String,
        /// Validity period (e.g. +1h, +30m, +5m).
        #[arg(short = 'V', long, default_value = "+1h")]
        ttl: String,
        /// Ask phylaxd to perform SSH CA signing instead of local PKCS#11.
        #[arg(long)]
        via_phylax: bool,
        /// Path to the agent's public key to sign.
        pubkey: PathBuf,
    },
    /// Generate an ephemeral ed25519 keypair and sign it into a
    /// short-lived SSH certificate. Prints key + cert paths.
    Mint {
        /// Agent name (used as key ID and filename).
        #[arg(long)]
        agent: String,
        /// Valid principal(s), comma-separated.
        #[arg(short = 'n', long, default_value = "operator")]
        principal: String,
        /// Validity period (e.g. +1h, +30m, +5m).
        #[arg(long, default_value = "+1h")]
        ttl: String,
        /// Output directory (default: ~/.ssh/agent/).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Ask phylaxd to mint/sign instead of local PKCS#11.
        #[arg(long)]
        via_phylax: bool,
    },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Mint a short-lived token that allows `cred get` in managed session hooks.
    Start {
        /// Token lifetime in seconds.
        #[arg(long)]
        ttl_secs: Option<i64>,
        /// Print as `export CRED_GET_SESSION_TOKEN=...` for shell scripts.
        #[arg(long)]
        shell: bool,
    },
    /// Revoke the current or provided `cred get` session token.
    End {
        /// Token to revoke. Defaults to `$CRED_GET_SESSION_TOKEN`.
        #[arg(long)]
        token: Option<String>,
    },
}

/// Recovery-kit operations for the vault master key.
#[derive(Subcommand)]
enum RecoveryKitCmd {
    /// Wrap the current master key (from --auth-mode) into a new kit file.
    Create {
        /// Output path; must not exist. Store the file off this machine.
        #[arg(long)]
        out: PathBuf,
    },
    /// Check that a kit and its passphrase open this vault.
    Verify {
        /// Kit file to check.
        #[arg(long)]
        from: PathBuf,
    },
    /// Turn a kit back into a 0600 hex keyfile for `--auth-mode keyfile`.
    Restore {
        /// Kit file to read.
        #[arg(long)]
        from: PathBuf,
        /// Keyfile path to create; must not exist.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum BootstrapCmd {
    /// Wrap an existing cred store entry into bootstrap.enc.
    /// Used once per host to seal credd's privileged Kleos key. Default
    /// output is `~/.config/cred/bootstrap.enc`.
    Wrap {
        /// Service (category) name in the cred DB.
        service: String,
        /// Key (name) in the cred DB.
        key: String,
        /// Optional output path (default: ~/.config/cred/bootstrap.enc).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Unwrap bootstrap.enc and print the bare key to stdout.
    /// Manual escape hatch only -- credd is the normal consumer.
    Unwrap {
        /// Optional input path (default: ~/.config/cred/bootstrap.enc).
        #[arg(long)]
        from: Option<PathBuf>,
        /// Print bare value with no trailing newline (for piping).
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Subcommand)]
enum AgentKeyAction {
    /// Generate a new agent key.
    ///
    /// Without `--scope`, keys land in the DB-backed `cred_agent_keys`
    /// table (used by the three-tier resolve handlers).
    ///
    /// With one or more `--scope bootstrap/<slot>` flags, the key lands in
    /// the file-backed store at ~/.config/cred/agent-keys.json (used by the
    /// /bootstrap/kleos-bearer endpoint). The two stores serve different
    /// auth surfaces; mixing scope types in a single token is rejected.
    Generate {
        /// Agent name/identifier
        name: String,
        /// Description of what this key is for
        #[arg(short, long, default_value = "")]
        description: String,
        /// Scope strings: `bootstrap/<slot>`, `bootstrap/*`, or `*`.
        /// Repeat for multiple. Presence of any scope routes to the
        /// file-backed bootstrap store.
        #[arg(long)]
        scope: Vec<String>,
    },
    /// List all agent keys (DB-backed only; use `cred bootstrap unwrap`
    /// or read ~/.config/cred/agent-keys.json for file-backed tokens).
    List,
    /// Revoke a DB-backed agent key.
    Revoke {
        /// Agent name to revoke
        name: String,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct GetSessionGrant {
    token_hash: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
struct GetSessionGrantStore {
    grants: Vec<GetSessionGrant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GetAccessContext {
    Interactive,
    ManagedSession,
    Agent,
}

fn config_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "cred")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| {
            directories::BaseDirs::new()
                .map(|d| d.home_dir().join(".config").join("cred"))
                .unwrap_or_else(|| PathBuf::from(".").join(".config").join("cred"))
        })
}

fn db_path() -> PathBuf {
    config_dir().join("cred.db")
}

/// Default path of the persisted KDF salt file (KDF v2).
fn kdf_salt_path() -> PathBuf {
    config_dir().join("kdf_salt")
}

/// Create the random KDF salt (opt into KDF v2) and print activation guidance.
/// Idempotent: never overwrites an existing salt. DB- and key-free so it can
/// run on a fresh host before `cred init`.
fn cmd_kdf_salt_init() -> Result<()> {
    let path = kdf_salt_path();
    let existed = path.exists();
    let hex = kleos_cred::crypto::init_kdf_salt_file(&path)?;
    if existed {
        eprintln!(
            "KDF salt already present at {} (left unchanged).",
            path.display()
        );
    } else {
        eprintln!(
            "Wrote a new random KDF salt to {} (mode 0600).",
            path.display()
        );
    }
    eprintln!();
    eprintln!("To activate KDF v2, export this in EVERY cred/credd/phylaxd environment:");
    eprintln!(
        "    export {}={}",
        kleos_cred::crypto::KDF_SALT_FILE_ENV,
        path.display()
    );
    eprintln!();
    eprintln!("WARNING: secrets already stored WITHOUT a salt (legacy KDF v1) were derived with");
    eprintln!("a different key and will NOT decrypt once the salt is active. Enable this on a");
    eprintln!("fresh vault, or re-import secrets after enabling. The salt is not secret, but");
    eprintln!("back it up -- losing it makes v2-encrypted secrets unrecoverable.");
    // Emit the hex salt on stdout so it can be captured/backed up.
    println!("{hex}");
    Ok(())
}

fn get_session_grants_path() -> PathBuf {
    config_dir().join("get-session-grants.json")
}

fn shellexpand(path: &str) -> String {
    shellexpand::tilde(path).into_owned()
}

/// YubiKey unlock that also returns the raw slot-2 challenge-response, so the
/// caller can derive the at-rest SQLCipher key from the SAME HMAC without a
/// second device round-trip (one device hit per invocation -- no added contention).
#[allow(deprecated)]
fn derive_master_key_yubikey_with_response() -> Result<([u8; KEY_SIZE], Zeroizing<Vec<u8>>)> {
    let challenge = yubikey::get_or_create_challenge().context("failed to get challenge file")?;

    let response = yubikey::challenge_response(&challenge)
        .context("failed to get YubiKey challenge-response -- is the YubiKey plugged in?")?;

    let key = derive_key_legacy(&response);
    Ok((key, Zeroizing::new(response.to_vec())))
}

/// Derive master key from YubiKey using legacy (private cred compatible) KDF.
fn derive_master_key_yubikey() -> Result<[u8; KEY_SIZE]> {
    Ok(derive_master_key_yubikey_with_response()?.0)
}

fn derive_master_key(
    auth_mode: &str,
    master_password: Option<&str>,
    keyfile: Option<&Path>,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    match auth_mode {
        "yubikey" => derive_master_key_yubikey().map(Zeroizing::new),
        "password" => {
            let password = match master_password {
                Some(pw) => pw.to_string(),
                None => {
                    eprintln!("Enter master password: ");
                    rpassword::read_password()?
                }
            };
            Ok(kleos_cred::crypto::derive_key(1, password.as_bytes(), None))
        }
        "keyfile" => {
            let path = keyfile
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| config_dir().join("master.key"));
            let hex_str = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read keyfile {}", path.display()))?;
            let bytes = hex::decode(hex_str.trim())
                .with_context(|| format!("keyfile {} is not valid hex", path.display()))?;
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
            Ok(Zeroizing::new(key))
        }
        other => {
            anyhow::bail!(
                "unknown CRED_AUTH_MODE `{other}`; expected `yubikey`, `password`, or `keyfile`"
            );
        }
    }
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Pure access-context policy, split out so the rules are unit-testable without
/// touching process env or the real terminal.
///
/// `cred get` prints a plaintext secret. The old policy only recognised agents
/// by env signals and otherwise fell through to `Interactive` (print freely),
/// so any subprocess that did not set a known agent var leaked the secret. The
/// robust signal is interactivity: a human runs `cred get` attached to a real
/// terminal (stdout is a TTY); an agent or script captures stdout through a
/// pipe. Captured stdout therefore requires a session grant -- fail closed --
/// while a real terminal still prints. Authorized non-interactive use mints a
/// grant via `cred session start`.
fn classify_get_access_context(
    agent_env: bool,
    managed_env: bool,
    stdout_is_tty: bool,
) -> GetAccessContext {
    if agent_env {
        return GetAccessContext::Agent;
    }
    if managed_env || !stdout_is_tty {
        return GetAccessContext::ManagedSession;
    }
    GetAccessContext::Interactive
}

fn detect_get_access_context() -> GetAccessContext {
    let agent_env = env_truthy(AI_AGENT_ENV) || env_truthy(CRED_AGENT_CONTEXT_ENV);
    let managed_env = std::env::var("CLAUDE_CODE_ENTRYPOINT").is_ok()
        || std::env::var("CLAUDE_SESSION_ID").is_ok()
        || std::env::var("KLEOS_SESSION_ID").is_ok();
    classify_get_access_context(agent_env, managed_env, io::stdout().is_terminal())
}

fn default_get_session_ttl_secs() -> i64 {
    std::env::var(CRED_GET_SESSION_TTL_SECS_ENV)
        .ok()
        .and_then(|raw| raw.parse::<i64>().ok())
        .filter(|ttl| *ttl > 0)
        .unwrap_or(DEFAULT_CRED_GET_SESSION_TTL_SECS)
}

fn hash_get_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn load_get_session_grants(path: &Path) -> Result<GetSessionGrantStore> {
    if !path.exists() {
        return Ok(GetSessionGrantStore::default());
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn save_get_session_grants(path: &Path, store: &GetSessionGrantStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let body = serde_json::to_vec_pretty(store)?;
    std::fs::write(&tmp, body)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn prune_expired_get_session_grants(store: &mut GetSessionGrantStore, now: i64) -> bool {
    let before = store.grants.len();
    store.grants.retain(|grant| grant.expires_at > now);
    before != store.grants.len()
}

fn mint_get_session_grant(path: &Path, ttl_secs: i64) -> Result<String> {
    anyhow::ensure!(ttl_secs > 0, "--ttl-secs must be greater than zero");

    let now = chrono::Utc::now().timestamp();
    let mut token_bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut token_bytes)
        .expect("OS CSPRNG must be available");
    let token = hex::encode(token_bytes);
    token_bytes.zeroize();

    let mut store = load_get_session_grants(path)?;
    prune_expired_get_session_grants(&mut store, now);
    store.grants.push(GetSessionGrant {
        token_hash: hash_get_session_token(&token),
        issued_at: now,
        expires_at: now + ttl_secs,
    });
    save_get_session_grants(path, &store)?;

    Ok(token)
}

fn revoke_get_session_grant(path: &Path, token: &str) -> Result<bool> {
    let now = chrono::Utc::now().timestamp();
    let mut store = load_get_session_grants(path)?;
    let token_hash = hash_get_session_token(token);
    let before = store.grants.len();
    store
        .grants
        .retain(|grant| grant.expires_at > now && grant.token_hash != token_hash);
    let changed = before != store.grants.len();
    save_get_session_grants(path, &store)?;
    Ok(changed)
}

fn has_valid_get_session_grant(path: &Path, token: &str) -> Result<bool> {
    let now = chrono::Utc::now().timestamp();
    let mut store = load_get_session_grants(path)?;
    let token_hash = hash_get_session_token(token);
    let pruned = prune_expired_get_session_grants(&mut store, now);
    let valid = store.grants.iter().any(|grant| {
        // Constant-time hash compare so grant validation does not leak which
        // bytes of a presented token's hash matched via timing.
        grant.expires_at > now
            && bool::from(grant.token_hash.as_bytes().ct_eq(token_hash.as_bytes()))
    });
    if pruned {
        save_get_session_grants(path, &store)?;
    }
    Ok(valid)
}

fn enforce_get_access_policy(
    context: GetAccessContext,
    has_valid_session_grant: bool,
) -> Result<()> {
    match context {
        GetAccessContext::Agent => anyhow::bail!(
            "cred get is disabled in agent contexts; use `cred exec` or `cred list` instead"
        ),
        GetAccessContext::ManagedSession if !has_valid_session_grant => anyhow::bail!(
            "cred get requires a valid session grant in managed sessions; run `cred session start --shell` during SessionStart and export {}",
            CRED_GET_SESSION_TOKEN_ENV
        ),
        _ => Ok(()),
    }
}

fn require_get_session_grant_if_needed() -> Result<()> {
    let context = detect_get_access_context();
    let has_valid_session_grant = match context {
        GetAccessContext::ManagedSession => match std::env::var(CRED_GET_SESSION_TOKEN_ENV) {
            Ok(token) => has_valid_get_session_grant(&get_session_grants_path(), &token)?,
            Err(_) => false,
        },
        _ => false,
    };

    enforce_get_access_policy(context, has_valid_session_grant)
}

async fn cmd_session(cmd: SessionCmd) -> Result<()> {
    if detect_get_access_context() == GetAccessContext::Agent {
        anyhow::bail!("cred session is unavailable in agent contexts");
    }

    match cmd {
        SessionCmd::Start { ttl_secs, shell } => {
            let ttl_secs = ttl_secs.unwrap_or_else(default_get_session_ttl_secs);
            let token = mint_get_session_grant(&get_session_grants_path(), ttl_secs)?;
            if shell {
                println!("export {}='{}'", CRED_GET_SESSION_TOKEN_ENV, token);
            } else {
                println!("{}", token);
            }
            Ok(())
        }
        SessionCmd::End { token } => {
            let token = match token.or_else(|| std::env::var(CRED_GET_SESSION_TOKEN_ENV).ok()) {
                Some(token) => token,
                None => anyhow::bail!(
                    "no session token provided; pass --token or export {}",
                    CRED_GET_SESSION_TOKEN_ENV
                ),
            };
            let revoked = revoke_get_session_grant(&get_session_grants_path(), &token)?;
            if revoked {
                eprintln!("revoked cred get session token");
            } else {
                eprintln!("cred get session token was already absent or expired");
            }
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init().await,
        Commands::KdfSaltInit => cmd_kdf_salt_init(),
        Commands::Recover { from } => cmd_recover(&from).await,
        Commands::Session { cmd } => cmd_session(cmd).await,
        Commands::Piv { cmd } => cmd_piv(cmd).await,
        Commands::SshCa { cmd } => cmd_ssh_ca(cmd).await,
        Commands::Rekey {
            to,
            new_keyfile,
            dry_run,
        } => cmd_rekey(
            &cli.auth_mode,
            cli.master_password.as_deref(),
            cli.keyfile.as_deref(),
            &to,
            new_keyfile.as_deref(),
            dry_run,
        ),
        Commands::RekeyChallenge {
            new_challenge,
            dry_run,
        } => cmd_rekey_challenge(&cli.auth_mode, &new_challenge, dry_run),
        Commands::MergeFrom { other, dry_run } => cmd_merge_from(&other, dry_run),
        Commands::V3Export => cmd_v3_export(),
        Commands::V3Import {
            source_keyfile,
            dry_run,
        } => cmd_v3_import(source_keyfile.as_deref(), dry_run),
        Commands::V3Audit {
            also_keyfiles,
            also_challenges,
            names,
        } => cmd_v3_audit(
            &cli.auth_mode,
            cli.master_password.as_deref(),
            cli.keyfile.as_deref(),
            &also_keyfiles,
            &also_challenges,
            names,
        ),
        Commands::RecoveryKit { cmd } => cmd_recovery_kit(
            &cli.auth_mode,
            cli.master_password.as_deref(),
            cli.keyfile.as_deref(),
            cmd,
        ),
        cmd => {
            // Resolve encryption config. ENGRAM_ENCRYPTION_MODE wins; when it is
            // absent (e.g. an agent process launched before the vault was
            // encrypted), fall back to the persisted ~/.config/cred/encryption-mode
            // file so cred can still open the encrypted DB without the env var.
            let mut enc_config = kleos_lib::config::Config::from_env();
            if std::env::var("ENGRAM_ENCRYPTION_MODE").is_err() {
                if let Some(mode) = kleos_cred::encryption::read_persisted_encryption_mode() {
                    enc_config.encryption.mode = mode;
                }
            }

            let mode_label = match cli.auth_mode.as_str() {
                "yubikey" => "YubiKey",
                "password" => "password",
                "keyfile" => "keyfile",
                other => other,
            };
            eprintln!("unlocking with {}...", mode_label);

            // Derive the per-secret master key. In yubikey mode, capture the raw
            // challenge-response so the at-rest key reuses the SAME HMAC (one
            // device hit per invocation, no added YubiKey contention).
            let (key, at_rest_key) = if cli.auth_mode == "yubikey" {
                let (master, response) = derive_master_key_yubikey_with_response()?;
                let at_rest =
                    kleos_cred::encryption::resolve_at_rest_key(&enc_config, Some(&response[..]))?;
                (Zeroizing::new(master), at_rest)
            } else {
                let master = derive_master_key(
                    &cli.auth_mode,
                    cli.master_password.as_deref(),
                    cli.keyfile.as_deref(),
                )?;
                let at_rest = kleos_cred::encryption::resolve_at_rest_key(&enc_config, None)?;
                (master, at_rest)
            };
            eprintln!("unlocked.");

            // Open with optional at-rest SQLCipher encryption. `None` => plaintext
            // (backward compatible); the first encrypted open of a still-plaintext
            // file auto-migrates it via the kleos-lib migrator.
            let db = Database::connect_encrypted(&db_path().to_string_lossy(), at_rest_key)
                .await
                .context("failed to open database")?;

            // Persist the resolved mode so a later daemon/agent started without
            // ENGRAM_ENCRYPTION_MODE opens the now-encrypted vault correctly
            // instead of silently as plaintext. Best-effort, idempotent.
            if enc_config.encryption.mode != kleos_lib::config::EncryptionMode::None {
                if let Err(e) =
                    kleos_cred::encryption::persist_encryption_mode(&enc_config.encryption.mode)
                {
                    eprintln!("warning: could not persist encryption-mode marker: {e}");
                }
            }

            // Lift any pre-fix user_id=0 rows produced by older binaries.
            // No-op on already-migrated stores. Tolerated to fail silently
            // when the table does not yet exist (fresh host before `cred
            // init`); the user's actual command will surface the real
            // error in that case.
            match migrate_legacy_user_id_zero_rows(&db).await {
                Ok(n) if n > 0 => eprintln!(
                    "migrated {} legacy cred entries from user_id=0 to user_id=1",
                    n
                ),
                Ok(_) => {}
                Err(_) => {
                    // Most likely the table does not yet exist (fresh host
                    // before `cred init`). The user's actual command will
                    // surface the real failure; suppress noise here.
                }
            }

            match cmd {
                Commands::Store {
                    service,
                    key: secret_key,
                    secret_type,
                } => cmd_store(&db, &key, &service, &secret_key, &secret_type).await,
                Commands::Get {
                    service,
                    key: secret_key,
                    field,
                    raw,
                    hash,
                } => {
                    cmd_get(
                        &db,
                        &key,
                        &service,
                        &secret_key,
                        field.as_deref(),
                        raw,
                        hash.as_deref(),
                    )
                    .await
                }
                Commands::List { service } => cmd_list(&db, &key, service.as_deref()).await,
                Commands::Delete {
                    service,
                    key: secret_key,
                    yes,
                } => cmd_delete(&db, &key, &service, &secret_key, yes).await,
                Commands::Import { dry_run } => cmd_import(&db, &key, dry_run).await,
                Commands::Export { output } => cmd_export(&db, &key, output).await,
                Commands::AgentKey { action } => cmd_agent_key(&db, action).await,
                Commands::Exec {
                    service,
                    key: secret_key,
                    field,
                    env,
                    stdin,
                    hash,
                    command,
                } => {
                    cmd_exec(
                        &db,
                        &key,
                        &service,
                        &secret_key,
                        field.as_deref(),
                        env.as_deref(),
                        stdin,
                        hash.as_deref(),
                        command,
                    )
                    .await
                }
                Commands::Tui => cmd_tui(&db, &key).await,
                Commands::ExportKey { out } => cmd_export_key(&key, out).await,
                Commands::Bootstrap { cmd: bcmd } => match bcmd {
                    BootstrapCmd::Wrap {
                        service,
                        key: secret_key,
                        out,
                    } => cmd_bootstrap_wrap(&db, &key, &service, &secret_key, out).await,
                    BootstrapCmd::Unwrap { from, raw } => {
                        cmd_bootstrap_unwrap(&key, from, raw).await
                    }
                },
                Commands::Init
                | Commands::KdfSaltInit
                | Commands::Recover { .. }
                | Commands::Session { .. }
                | Commands::Piv { .. }
                | Commands::SshCa { .. }
                | Commands::Rekey { .. }
                | Commands::RecoveryKit { .. }
                | Commands::V3Audit { .. }
                | Commands::RekeyChallenge { .. }
                | Commands::MergeFrom { .. }
                | Commands::V3Import { .. }
                | Commands::V3Export => unreachable!(),
            }
        }
    }
}

/// Move the vault to a new challenge file: vault file, secrets, bootstrap, challenge.
fn cmd_rekey_challenge(auth_mode: &str, new_challenge_path: &Path, dry_run: bool) -> Result<()> {
    use kleos_cred::rekey::{
        count_decryptable_in, install_challenge, rekey_bootstrap, rekey_vault_file,
        BootstrapOutcome,
    };

    if auth_mode != "yubikey" {
        anyhow::bail!("rekey-challenge applies only to yubikey mode (current: {auth_mode})");
    }
    let current_path = yubikey::active_challenge_path()
        .context("this host has no challenge file; refusing to create one")?;
    let current =
        std::fs::read(&current_path).with_context(|| format!("read {}", current_path.display()))?;
    let target = std::fs::read(new_challenge_path)
        .with_context(|| format!("read {}", new_challenge_path.display()))?;
    if current.len() != yubikey::CHALLENGE_SIZE || target.len() != yubikey::CHALLENGE_SIZE {
        anyhow::bail!("challenge files must be {} bytes", yubikey::CHALLENGE_SIZE);
    }
    if current == target {
        anyhow::bail!(
            "{} already holds that challenge; nothing to do",
            current_path.display()
        );
    }
    let at_rest_mode = std::env::var("ENGRAM_ENCRYPTION_MODE")
        .ok()
        .map(|m| m.to_ascii_lowercase())
        .or_else(|| {
            kleos_cred::encryption::read_persisted_encryption_mode()
                .map(|m| format!("{m:?}").to_ascii_lowercase())
        })
        .unwrap_or_else(|| "none".into());
    let at_rest_yubikey = match at_rest_mode.as_str() {
        "yubikey" => true,
        "none" => false,
        other => anyhow::bail!("unsupported at-rest mode {other}; only none or yubikey"),
    };

    eprintln!("deriving current and target keys through the YubiKey...");
    let old_response = Zeroizing::new(yubikey::challenge_response(&current)?);
    let new_response = Zeroizing::new(yubikey::challenge_response(&target)?);
    #[allow(deprecated)]
    let old_key = Zeroizing::new(derive_key_legacy(&old_response[..]));
    #[allow(deprecated)]
    let new_key = Zeroizing::new(derive_key_legacy(&new_response[..]));
    let (old_at_rest, new_at_rest) = if at_rest_yubikey {
        (
            Some(at_rest_key_from_response(&old_response[..])?),
            Some(at_rest_key_from_response(&new_response[..])?),
        )
    } else {
        (None, None)
    };

    let db = db_path();
    let report = rekey_vault_file(
        &db,
        old_at_rest.as_deref(),
        new_at_rest.as_deref(),
        &old_key,
        &new_key,
        dry_run,
    )?;
    eprintln!(
        "vault: {} secrets ({} re-encrypted, {} already on the target key), at-rest {}",
        report.rows,
        report.rotated,
        report.already_new,
        if at_rest_yubikey {
            "SQLCipher re-keyed"
        } else {
            "plaintext file"
        }
    );
    let bootstrap = rekey_bootstrap(&bootstrap_default_path(), &old_key, &new_key, dry_run)?;
    match &bootstrap {
        BootstrapOutcome::Absent => eprintln!("bootstrap.enc: absent"),
        BootstrapOutcome::Verified => eprintln!("bootstrap.enc: decrypts with the current key"),
        BootstrapOutcome::Rewrapped { backup } => eprintln!(
            "bootstrap.enc: rewrapped (original at {})",
            backup.display()
        ),
    }
    if dry_run {
        eprintln!("dry run complete: verified on a temporary copy; nothing changed");
        return Ok(());
    }
    let challenge_backup = install_challenge(&current_path, &target)?;
    let (ok, total) = count_decryptable_in(&db, new_at_rest.as_deref(), &new_key)?;
    eprintln!(
        "installed new challenge at {} (old kept at {}); vault original kept at {}",
        current_path.display(),
        challenge_backup.display(),
        report
            .backup
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    );
    eprintln!("verify: {ok}/{total} secrets decrypt with the new key");
    if ok != total {
        anyhow::bail!("post-rekey verification failed");
    }
    Ok(())
}

/// Derive the YubiKey-mode SQLCipher at-rest key from a slot-2 response.
///
/// Delegates to `encryption::resolve_at_rest_key` so the derivation has a
/// single source of truth shared with the normal open path.
fn at_rest_key_from_response(response: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let mut config = kleos_lib::config::Config::from_env();
    config.encryption.mode = kleos_lib::config::EncryptionMode::Yubikey;
    let key = kleos_cred::encryption::resolve_at_rest_key(&config, Some(response))?
        .context("yubikey at-rest mode produced no key")?;
    Ok(Zeroizing::new(key))
}

/// This host's vault keys: (secret master key, optional SQLCipher at-rest key).
type VaultKeys = (Zeroizing<[u8; KEY_SIZE]>, Option<Zeroizing<[u8; KEY_SIZE]>>);

/// Derive this host's vault keys from its active challenge through the YubiKey.
fn local_vault_keys() -> Result<VaultKeys> {
    let path = yubikey::active_challenge_path().context("this host has no challenge file")?;
    let challenge = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let response = Zeroizing::new(yubikey::challenge_response(&challenge)?);
    #[allow(deprecated)]
    let master = Zeroizing::new(derive_key_legacy(&response[..]));
    let at_rest_yubikey = std::env::var("ENGRAM_ENCRYPTION_MODE")
        .map(|m| m.eq_ignore_ascii_case("yubikey"))
        .unwrap_or_else(|_| {
            kleos_cred::encryption::read_persisted_encryption_mode()
                .map(|m| format!("{m:?}").eq_ignore_ascii_case("yubikey"))
                .unwrap_or(false)
        });
    let at_rest = if at_rest_yubikey {
        Some(at_rest_key_from_response(&response[..])?)
    } else {
        None
    };
    Ok((master, at_rest))
}

/// Print a merge report: counts plus names, never values.
fn print_merge_report(report: &kleos_cred::rekey::MergeReport, dry_run: bool) {
    let verb = if dry_run { "would import" } else { "imported" };
    eprintln!(
        "{verb} {}, identical {}, differing {}, undecryptable {}",
        report.imported.len(),
        report.identical,
        report.differing.len(),
        report.undecryptable.len()
    );
    for (label, names) in [
        (verb, &report.imported),
        ("DIFFERS (left as is)", &report.differing),
        ("undecryptable", &report.undecryptable),
    ] {
        for name in names {
            eprintln!("    {label}: {name}");
        }
    }
}

/// Merge another same-key vault file into this host's vault.
fn cmd_merge_from(other: &Path, dry_run: bool) -> Result<()> {
    let (master, at_rest) = local_vault_keys()?;
    let report = kleos_cred::rekey::merge_vault(
        &db_path(),
        at_rest.as_deref(),
        other,
        at_rest.as_deref(),
        &master,
        dry_run,
    )?;
    print_merge_report(&report, dry_run);
    Ok(())
}

/// Print local secrets as central v3 contents (ciphertext only) on stdout.
fn cmd_v3_export() -> Result<()> {
    let (master, at_rest) = local_vault_keys()?;
    let (contents, skipped) =
        kleos_cred::rekey::export_v3_contents(&db_path(), at_rest.as_deref(), &master)?;
    let mut out = io::stdout().lock();
    for line in &contents {
        writeln!(out, "{line}")?;
    }
    eprintln!(
        "exported {} entries; skipped {}",
        contents.len(),
        skipped.len()
    );
    for name in &skipped {
        eprintln!("    skipped: {name}");
    }
    Ok(())
}

/// Import central v3 entries that are missing locally.
fn cmd_v3_import(source_keyfile: Option<&Path>, dry_run: bool) -> Result<()> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).context("stdin is not a Kleos /list JSON response")?;
    let (entries, _) = kleos_cred::rekey::parse_v3_listing(&json);
    let (master, at_rest) = local_vault_keys()?;
    let source = match source_keyfile {
        Some(path) => derive_master_key("keyfile", None, Some(path))?,
        None => master.clone(),
    };
    let report = kleos_cred::rekey::import_v3_entries(
        &db_path(),
        at_rest.as_deref(),
        &master,
        &entries,
        &source,
        dry_run,
    )?;
    print_merge_report(&report, dry_run);
    Ok(())
}

/// Summarize which candidate keys open the central CRED:v3 entries on stdin.
fn cmd_v3_audit(
    auth_mode: &str,
    master_password: Option<&str>,
    keyfile: Option<&Path>,
    also_keyfiles: &[PathBuf],
    also_challenges: &[PathBuf],
    names: bool,
) -> Result<()> {
    use kleos_cred::rekey::{parse_v3_listing, v3_opens_with};
    use std::collections::BTreeMap;

    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).context("stdin is not a Kleos /list JSON response")?;
    let (entries, malformed) = parse_v3_listing(&json);

    let mut keys: Vec<(String, Zeroizing<[u8; KEY_SIZE]>)> = vec![(
        format!("current ({auth_mode})"),
        derive_master_key(auth_mode, master_password, keyfile)?,
    )];
    for path in also_keyfiles {
        keys.push((
            path.display().to_string(),
            derive_master_key("keyfile", None, Some(path))?,
        ));
    }
    for path in also_challenges {
        let challenge = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if challenge.len() != yubikey::CHALLENGE_SIZE {
            anyhow::bail!(
                "{} is not a {}-byte challenge file",
                path.display(),
                yubikey::CHALLENGE_SIZE
            );
        }
        let response = Zeroizing::new(yubikey::challenge_response(&challenge)?);
        #[allow(deprecated)]
        let key = Zeroizing::new(derive_key_legacy(&response[..]));
        keys.push((format!("yubikey + challenge {}", path.display()), key));
    }

    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &entries {
        let label = keys
            .iter()
            .find(|(_, key)| v3_opens_with(key, &entry.blob))
            .map(|(label, _)| label.clone())
            .unwrap_or_else(|| "NO KEY TESTED".to_string());
        groups.entry(label).or_default().push(match entry.id {
            Some(id) => format!("{}/{} #{id}", entry.category, entry.name),
            None => format!("{}/{}", entry.category, entry.name),
        });
    }
    // Value check: for every entry an extra key opens, compare its plaintext with
    // the entry the current key opens for the same name (fingerprints only).
    if keys.len() > 1 {
        let current = &keys[0].1;
        let mut current_values: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
        for entry in &entries {
            if let Ok(plain) = kleos_cred::crypto::decrypt(current, &entry.blob) {
                current_values.insert(
                    (entry.category.clone(), entry.name.clone()),
                    Sha256::digest(&plain).to_vec(),
                );
            }
        }
        let (mut same, mut differ, mut no_current) = (0usize, Vec::new(), Vec::new());
        for entry in &entries {
            for (label, key) in keys.iter().skip(1) {
                if let Ok(plain) = kleos_cred::crypto::decrypt(key, &entry.blob) {
                    let tag = format!(
                        "{}/{} #{} ({label})",
                        entry.category,
                        entry.name,
                        entry.id.unwrap_or(0)
                    );
                    match current_values.get(&(entry.category.clone(), entry.name.clone())) {
                        Some(digest) if *digest == Sha256::digest(&plain).to_vec() => same += 1,
                        Some(_) => differ.push(tag),
                        None => no_current.push(tag),
                    }
                    break;
                }
            }
        }
        eprintln!(
            "value check vs current key: identical {same}, DIFFERENT {}, no current-key copy {}",
            differ.len(),
            no_current.len()
        );
        for tag in differ.iter().chain(no_current.iter()) {
            eprintln!("    check: {tag}");
        }
    }
    let unique: std::collections::BTreeSet<_> =
        entries.iter().map(|e| (&e.category, &e.name)).collect();
    eprintln!(
        "central v3 entries: {} ({} unique names, {} non-v3/malformed memories)",
        entries.len(),
        unique.len(),
        malformed
    );
    for (label, members) in &groups {
        eprintln!("opens with {label}: {}", members.len());
        if names {
            for member in members {
                eprintln!("    {member}");
            }
        } else {
            let mut services: BTreeMap<&str, usize> = BTreeMap::new();
            for member in members {
                *services
                    .entry(member.split('/').next().unwrap_or("?"))
                    .or_default() += 1;
            }
            let summary: Vec<String> = services.iter().map(|(s, n)| format!("{s}:{n}")).collect();
            eprintln!("    {}", summary.join(" "));
        }
    }
    Ok(())
}

/// Read a passphrase from the controlling terminal, refusing piped input.
fn read_terminal_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        anyhow::bail!("recovery passphrases must be typed at an interactive terminal");
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Create, verify, or restore a passphrase-wrapped master-key recovery kit.
fn cmd_recovery_kit(
    auth_mode: &str,
    master_password: Option<&str>,
    keyfile: Option<&Path>,
    cmd: RecoveryKitCmd,
) -> Result<()> {
    use kleos_cred::rekey::{
        keys_match, unwrap_master_key, wrap_master_key, write_new_private_file,
    };

    match cmd {
        RecoveryKitCmd::Create { out } => {
            if out.exists() {
                anyhow::bail!("{} already exists; refusing to overwrite", out.display());
            }
            let master = derive_master_key(auth_mode, master_password, keyfile)?;
            let passphrase = read_terminal_passphrase("recovery passphrase (12+ chars): ")?;
            let confirm = read_terminal_passphrase("confirm passphrase: ")?;
            if passphrase.as_str() != confirm.as_str() {
                anyhow::bail!("passphrases do not match");
            }
            let blob = wrap_master_key(&passphrase, &master)?;
            if !keys_match(&*unwrap_master_key(&passphrase, &blob)?, &master) {
                anyhow::bail!("recovery kit self-check failed");
            }
            write_new_private_file(&out, &blob)?;
            eprintln!(
                "recovery kit written to {} (0600); self-check passed",
                out.display()
            );
            eprintln!("copy it OFF this machine (password manager or offline USB) and delete the local copy");
            Ok(())
        }
        RecoveryKitCmd::Verify { from } => {
            let blob = std::fs::read(&from).with_context(|| format!("read {}", from.display()))?;
            let passphrase = read_terminal_passphrase("recovery passphrase: ")?;
            let recovered = unwrap_master_key(&passphrase, &blob)?;
            let master = derive_master_key(auth_mode, master_password, keyfile)?;
            if keys_match(&recovered, &master) {
                eprintln!("MATCH: this kit opens the current vault");
                Ok(())
            } else {
                anyhow::bail!("MISMATCH: this kit does not hold the current vault key")
            }
        }
        RecoveryKitCmd::Restore { from, out } => {
            let blob = std::fs::read(&from).with_context(|| format!("read {}", from.display()))?;
            let passphrase = read_terminal_passphrase("recovery passphrase: ")?;
            let recovered = unwrap_master_key(&passphrase, &blob)?;
            let hex_key = Zeroizing::new(hex::encode(recovered.as_slice()));
            write_new_private_file(&out, hex_key.as_bytes())?;
            eprintln!("keyfile written to {} (0600)", out.display());
            eprintln!("next: cred --auth-mode keyfile --keyfile {} rekey --to yubikey, then delete the keyfile", out.display());
            Ok(())
        }
    }
}

/// Rotate the local vault from the current master key to the `--to` key.
///
/// Opens SQLite directly (no Kleos migrations), refuses at-rest encrypted
/// caches, and reports only counts and failing row identifiers.
fn cmd_rekey(
    auth_mode: &str,
    master_password: Option<&str>,
    keyfile: Option<&Path>,
    to: &str,
    new_keyfile: Option<&Path>,
    dry_run: bool,
) -> Result<()> {
    use kleos_cred::rekey::{count_decryptable, rekey_bootstrap, rekey_database, BootstrapOutcome};

    if std::env::var("ENGRAM_ENCRYPTION_MODE").is_ok()
        || kleos_cred::encryption::read_persisted_encryption_mode().is_some()
    {
        anyhow::bail!("rekey supports only a plaintext-at-rest cache; this vault is configured for at-rest encryption");
    }
    eprintln!("deriving current key ({auth_mode})...");
    let old_key = derive_master_key(auth_mode, master_password, keyfile)?;
    eprintln!("deriving target key ({to})...");
    let new_key = derive_master_key(to, None, new_keyfile)?;

    let db = db_path();
    let report = rekey_database(&db, &old_key, &new_key, dry_run)?;
    // Match credd/phylaxd: CREDD_BOOTSTRAP_BLOB overrides the default location.
    let bootstrap_path = std::env::var("CREDD_BOOTSTRAP_BLOB")
        .ok()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(bootstrap_default_path);
    let bootstrap = rekey_bootstrap(&bootstrap_path, &old_key, &new_key, dry_run)?;
    if dry_run {
        eprintln!(
            "dry run: {} secrets would be re-encrypted, {} are already under the target key, {} total; nothing changed",
            report.rotated, report.already_new, report.rows
        );
    } else {
        let (new_ok, total) = count_decryptable(&db, &new_key)?;
        let (old_ok, _) = count_decryptable(&db, &old_key)?;
        eprintln!(
            "re-encrypted {} secrets ({} already under the target key); verify: {new_ok}/{total} decrypt with the new key, {old_ok} with the old key",
            report.rotated, report.already_new
        );
        if new_ok != total || old_ok != 0 {
            anyhow::bail!("post-rekey verification failed");
        }
    }
    match bootstrap {
        BootstrapOutcome::Absent => eprintln!("bootstrap.enc: absent"),
        BootstrapOutcome::Verified => eprintln!("bootstrap.enc: decrypts with the current key"),
        BootstrapOutcome::Rewrapped { backup } => {
            eprintln!(
                "bootstrap.enc: rewrapped; original kept at {}",
                backup.display()
            )
        }
    }
    Ok(())
}

async fn cmd_export_key(master_key: &[u8; KEY_SIZE], out: Option<PathBuf>) -> Result<()> {
    let path = out.unwrap_or_else(|| config_dir().join("master.key"));
    let dir = path
        .parent()
        .context("keyfile path has no parent directory")?;
    std::fs::create_dir_all(dir)?;

    let hex_key = hex::encode(master_key);
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, format!("{}\n", hex_key))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, &path)?;
    eprintln!("master key exported to {} (mode 0600)", path.display());
    eprintln!(
        "use CRED_AUTH_MODE=keyfile CRED_KEYFILE={} for unattended access",
        path.display()
    );
    Ok(())
}

async fn cmd_init() -> Result<()> {
    eprintln!("cred init - YubiKey credential manager setup");
    eprintln!();

    // Check for existing setup
    let config = config_dir();
    let challenge_path = config.join("challenge");

    if challenge_path.exists() {
        eprintln!("WARNING: cred is already initialized.");
        eprintln!("challenge file exists at: {}", challenge_path.display());
        print!("Continue anyway? This will overwrite existing setup. [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("aborted.");
            return Ok(());
        }
    }

    // Create config directory
    std::fs::create_dir_all(&config)?;

    // Generate HMAC secret
    eprintln!("generating 20-byte HMAC-SHA1 secret...");
    let secret = generate_hmac_secret();
    let secret_hex = hex::encode(secret);

    // SECURITY: refuse to print the HMAC secret to a non-terminal stderr to
    // avoid accidental capture in logs or CI pipelines. Set CRED_ALLOW_PRINT=1
    // to override when piping output intentionally.
    {
        use std::io::IsTerminal;
        let force_print = std::env::var("CRED_ALLOW_PRINT")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !force_print && !std::io::stderr().is_terminal() {
            eprintln!("ERROR: refusing to print secret -- stderr is not a terminal");
            eprintln!("Set CRED_ALLOW_PRINT=1 to override");
            std::process::exit(1);
        }
    }
    eprintln!();
    eprintln!("HMAC secret (save this in Bitwarden NOW):");
    eprintln!("  {}", secret_hex);
    eprintln!();

    // Check for YubiKey
    if yubikey::is_available() {
        print!("YubiKey detected. Program slot 2 with this secret? [Y/n] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y") {
            // Program YubiKey
            eprintln!("programming YubiKey slot 2...");
            program_yubikey_slot2(&secret_hex)?;
            eprintln!("YubiKey programmed.");
        }
    } else {
        eprintln!("No YubiKey detected. Program it manually:");
        eprintln!("  ykman otp chalresp 2 --force {}", secret_hex);
    }

    // Generate challenge file
    eprintln!();
    eprintln!("generating challenge file...");
    let _challenge = yubikey::get_or_create_challenge()?;
    eprintln!("challenge file created: {}", challenge_path.display());

    // Create recovery file
    eprintln!();
    eprintln!("creating recovery file...");
    let passphrase =
        rpassword::prompt_password("recovery passphrase: ").context("failed to read passphrase")?;
    let passphrase_confirm =
        rpassword::prompt_password("confirm passphrase: ").context("failed to read passphrase")?;

    if passphrase != passphrase_confirm {
        anyhow::bail!("passphrases do not match");
    }

    let recovery_data = encrypt_recovery(&passphrase, &secret)?;
    let recovery_path = config.join("recovery.enc");
    std::fs::write(&recovery_path, &recovery_data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&recovery_path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("recovery file written to: {}", recovery_path.display());

    // Initialize database
    eprintln!();
    eprintln!("initializing database...");
    let db = Database::connect(&db_path().to_string_lossy()).await?;
    init_schema(&db).await?;
    eprintln!("database initialized: {}", db_path().display());

    eprintln!();
    eprintln!("setup complete!");
    eprintln!();
    eprintln!("IMPORTANT:");
    eprintln!("  1. Save the HMAC secret to Bitwarden");
    eprintln!("  2. Copy recovery.enc to a safe backup location");
    eprintln!("  3. Remember your recovery passphrase");

    Ok(())
}

async fn cmd_recover(from: &str) -> Result<()> {
    let path = shellexpand(from);

    if !std::path::Path::new(&path).exists() {
        anyhow::bail!("recovery file not found: {}", path);
    }

    eprintln!("reading recovery file: {}", path);
    let data = std::fs::read(&path)?;

    let passphrase =
        rpassword::prompt_password("recovery passphrase: ").context("failed to read passphrase")?;

    let secret =
        decrypt_recovery(&passphrase, &data).context("decryption failed -- wrong passphrase?")?;

    eprintln!("secret recovered ({} bytes)", secret.len());
    eprintln!();

    // Check if YubiKey is present
    if yubikey::is_available() {
        print!("YubiKey detected. Program it with the recovered secret? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("y") {
            program_yubikey_slot2(&hex::encode(&secret))?;
            eprintln!("YubiKey programmed.");

            // Make sure challenge file exists
            let _challenge = yubikey::get_or_create_challenge()?;
            eprintln!("ready to use.");
            return Ok(());
        }
    }

    // If no YubiKey or user declined, show the hex
    eprintln!("HMAC secret (hex): {}", hex::encode(&secret));
    eprintln!("program a YubiKey manually:");
    eprintln!("  ykman otp chalresp 2 --force {}", hex::encode(&secret));

    Ok(())
}

async fn cmd_store(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    service: &str,
    key: &str,
    secret_type: &str,
) -> Result<()> {
    let data = prompt_secret_data(secret_type)?;

    storage::store_secret(db, CRED_USER_ID, service, key, &data, master_key)
        .await
        .context("failed to store secret")?;

    eprintln!("stored: {}/{}", service, key);
    Ok(())
}

fn hash_value_argon2(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let params = Params::new(65536, 3, 4, None)
        .map_err(|e| anyhow::anyhow!("argon2 params error: {}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {}", e))?;
    Ok(hash.to_string())
}

async fn cmd_get(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    service: &str,
    key: &str,
    field: Option<&str>,
    raw: bool,
    hash: Option<&str>,
) -> Result<()> {
    require_get_session_grant_if_needed()?;

    let (_row, data) = storage::get_secret(db, CRED_USER_ID, service, key, master_key)
        .await
        .context("secret not found")?;

    if let Some(algo) = hash {
        let plain = if let Some(field_name) = field {
            data.get_field(field_name)
                .ok_or_else(|| anyhow::anyhow!("field `{}` not found", field_name))?
        } else {
            data.bare_value()
                .ok_or_else(|| anyhow::anyhow!("secret has no bare value -- use --field"))?
        };
        let hashed = match algo {
            "argon2" => hash_value_argon2(&plain)?,
            _ => anyhow::bail!("unsupported hash algorithm: {}", algo),
        };
        print!("{}", hashed);
        return Ok(());
    }

    if raw {
        // Print raw value for piping
        if let Some(field_name) = field {
            if let Some(value) = data.get_field(field_name) {
                print!("{}", value);
            }
        } else if let Some(value) = data.bare_value() {
            print!("{}", value);
        } else {
            print!("{}", serde_json::to_string(&data)?);
        }
    } else {
        // Pretty print
        println!("{}/{}", service, key);
        println!("{}", serde_json::to_string_pretty(&data)?);
    }

    Ok(())
}

/// Run a child command with a stored secret injected as env var or stdin.
/// cred prints nothing of its own to stdout. Used to keep secrets out of
/// captured tool results in agent contexts.
#[allow(clippy::too_many_arguments)]
async fn cmd_exec(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    service: &str,
    key: &str,
    field: Option<&str>,
    env_name: Option<&str>,
    use_stdin: bool,
    hash: Option<&str>,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified after `--`");
    }

    let (_row, data) = match storage::get_secret(db, CRED_USER_ID, service, key, master_key).await {
        Ok(result) => result,
        Err(_) => resolve_via_credd(master_key, service, key)
            .await
            .context("secret not found in local DB or credd")?,
    };

    let mut value = if let Some(field_name) = field {
        data.get_field(field_name).ok_or_else(|| {
            anyhow::anyhow!(
                "field `{}` not found on secret type {}",
                field_name,
                data.type_name()
            )
        })?
    } else {
        data.bare_value().ok_or_else(|| {
            anyhow::anyhow!(
                "secret type {} has no bare value -- pass --field <name>",
                data.type_name()
            )
        })?
    };

    if let Some(algo) = hash {
        value = match algo {
            "argon2" => hash_value_argon2(&value)?,
            _ => anyhow::bail!("unsupported hash algorithm: {}", algo),
        };
    }

    let program = command[0].clone();
    let args: Vec<String> = command[1..].to_vec();

    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&args);

    if use_stdin {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        let var = env_name.unwrap_or("CRED_VALUE");
        cmd.env(var, &value);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", program))?;

    if use_stdin {
        if let Some(mut child_stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            child_stdin.write_all(value.as_bytes()).await?;
            // dropping closes stdin so the child sees EOF
        }
    }

    // Best effort: zeroize our copy now that the child has its own.
    value.zeroize();

    let status = child.wait().await?;
    std::process::exit(status.code().unwrap_or(1));
}

async fn cmd_list(
    db: &Database,
    _master_key: &[u8; KEY_SIZE],
    service_filter: Option<&str>,
) -> Result<()> {
    let secrets = storage::list_secrets(db, CRED_USER_ID, service_filter).await?;

    if secrets.is_empty() {
        println!("no secrets stored");
        return Ok(());
    }

    // Find column widths
    let max_svc = secrets
        .iter()
        .map(|s| s.category.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let max_key = secrets
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(3)
        .max(3);

    println!(
        "{:<width_s$}  {:<width_k$}  TYPE",
        "SERVICE",
        "KEY",
        width_s = max_svc,
        width_k = max_key,
    );
    println!(
        "{:-<width_s$}  {:-<width_k$}  {:-<10}",
        "",
        "",
        "",
        width_s = max_svc,
        width_k = max_key,
    );

    for row in &secrets {
        println!(
            "{:<width_s$}  {:<width_k$}  {}",
            row.category,
            row.name,
            row.secret_type.as_str(),
            width_s = max_svc,
            width_k = max_key,
        );
    }

    println!("\n{} secret(s)", secrets.len());
    Ok(())
}

async fn cmd_delete(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    service: &str,
    key: &str,
    skip_confirm: bool,
) -> Result<()> {
    // Verify it exists first
    let _ = storage::get_secret(db, CRED_USER_ID, service, key, master_key)
        .await
        .context("secret not found")?;

    if !skip_confirm {
        print!("delete {}/{}? [y/N] ", service, key);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("aborted.");
            return Ok(());
        }
    }

    storage::delete_secret(db, CRED_USER_ID, service, key).await?;
    eprintln!("deleted: {}/{}", service, key);
    Ok(())
}

async fn cmd_import(db: &Database, master_key: &[u8; KEY_SIZE], dry_run: bool) -> Result<()> {
    eprintln!("reading secrets from stdin");
    eprintln!("accepts JSON (from 'cred export') or TSV (service<TAB>key<TAB>value)");
    eprintln!("press Ctrl-D when done");
    if dry_run {
        eprintln!("(dry run -- nothing will be stored)");
    }
    eprintln!();

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input = input.trim();

    if input.is_empty() {
        eprintln!("no input");
        return Ok(());
    }

    // Detect JSON vs TSV
    if input.starts_with('[') {
        cmd_import_json(db, master_key, input, dry_run).await
    } else {
        cmd_import_tsv(db, master_key, input, dry_run).await
    }
}

async fn cmd_import_json(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    input: &str,
    dry_run: bool,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct ImportEntry {
        service: String,
        key: String,
        value: SecretData,
    }

    let entries: Vec<ImportEntry> =
        serde_json::from_str(input).context("failed to parse JSON import")?;

    let mut imported = 0u32;

    for entry in &entries {
        if dry_run {
            eprintln!(
                "  [dry run] would store: {}/{} ({})",
                entry.service,
                entry.key,
                entry.value.type_name()
            );
        } else {
            storage::store_secret(
                db,
                CRED_USER_ID,
                &entry.service,
                &entry.key,
                &entry.value,
                master_key,
            )
            .await?;
            eprintln!("  stored: {}/{}", entry.service, entry.key);
        }
        imported += 1;
    }

    eprintln!();
    if dry_run {
        eprintln!("dry run complete: {} would be imported", imported);
    } else {
        eprintln!("import complete: {} stored", imported);
    }
    Ok(())
}

async fn cmd_import_tsv(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    input: &str,
    dry_run: bool,
) -> Result<()> {
    let mut imported = 0u32;
    let mut skipped = 0u32;

    for (lineno, line) in input.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() != 3 {
            eprintln!(
                "  line {}: skipping (expected 3 tab-separated fields)",
                lineno + 1
            );
            skipped += 1;
            continue;
        }

        let (service, key, value) = (parts[0].trim(), parts[1].trim(), parts[2].trim());

        if service.is_empty() || key.is_empty() || value.is_empty() {
            eprintln!("  line {}: skipping (empty field)", lineno + 1);
            skipped += 1;
            continue;
        }

        if dry_run {
            eprintln!(
                "  [dry run] would store: {}/{} ({} chars)",
                service,
                key,
                value.len()
            );
        } else {
            let data = SecretData::ApiKey {
                key: value.to_string(),
                endpoint: None,
                notes: None,
            };
            storage::store_secret(db, CRED_USER_ID, service, key, &data, master_key).await?;
            eprintln!("  stored: {}/{}", service, key);
        }
        imported += 1;
    }

    eprintln!();
    if dry_run {
        eprintln!(
            "dry run complete: {} would be imported, {} skipped",
            imported, skipped
        );
    } else {
        eprintln!("import complete: {} stored, {} skipped", imported, skipped);
    }
    Ok(())
}

async fn cmd_export(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    output: Option<PathBuf>,
) -> Result<()> {
    let rows = storage::list_secrets(db, CRED_USER_ID, None).await?;

    if rows.is_empty() {
        eprintln!("no secrets to export");
        return Ok(());
    }

    #[derive(serde::Serialize)]
    struct ExportEntry {
        service: String,
        key: String,
        value: SecretData,
    }

    let mut entries = Vec::new();
    for row in rows {
        // Decrypt each secret
        match storage::get_secret(db, CRED_USER_ID, &row.category, &row.name, master_key).await {
            Ok((_row, data)) => {
                entries.push(ExportEntry {
                    service: row.category,
                    key: row.name,
                    value: data,
                });
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to decrypt {}/{}: {}",
                    row.category, row.name, e
                );
            }
        }
    }

    let json = serde_json::to_string_pretty(&entries)?;

    match output {
        Some(path) => {
            // Write atomically with owner-only perms so the plaintext export
            // never lands on disk world-readable.
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            std::fs::write(&tmp, &json)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, &path)?;
            eprintln!(
                "exported {} secret(s) to {} (mode 0600)",
                entries.len(),
                path.display()
            );
        }
        None => {
            // Refuse to dump plaintext secrets when stdout is redirected to a
            // file/pipe (which would be created with the default umask).
            // Printing is allowed only to an interactive terminal.
            use std::io::IsTerminal;
            if !io::stdout().is_terminal() {
                anyhow::bail!(
                    "refusing to write plaintext secrets to a non-terminal stdout; \
                     pass --output <file> (written mode 0600)"
                );
            }
            println!("{}", json);
            eprintln!("\nexported {} secret(s)", entries.len());
        }
    }
    Ok(())
}

// Helper functions

fn prompt_secret_data(secret_type: &str) -> Result<SecretData> {
    match secret_type {
        "api-key" => {
            let key = rpassword::prompt_password("api key: ")?;
            print!("endpoint (optional): ");
            io::stdout().flush()?;
            let mut endpoint = String::new();
            io::stdin().read_line(&mut endpoint)?;
            let endpoint = endpoint.trim();

            Ok(SecretData::ApiKey {
                key,
                endpoint: if endpoint.is_empty() {
                    None
                } else {
                    Some(endpoint.to_string())
                },
                notes: None,
            })
        }
        "note" => {
            eprintln!("enter note (Ctrl-D to finish):");
            let mut content = String::new();
            io::stdin().read_to_string(&mut content)?;
            Ok(SecretData::Note { content })
        }
        "login" => {
            print!("url: ");
            io::stdout().flush()?;
            let mut url = String::new();
            io::stdin().read_line(&mut url)?;

            print!("username: ");
            io::stdout().flush()?;
            let mut username = String::new();
            io::stdin().read_line(&mut username)?;

            let password = rpassword::prompt_password("password: ")?;

            Ok(SecretData::Login {
                username: username.trim().to_string(),
                password,
                url: Some(url.trim().to_string()),
                totp_seed: None,
                notes: None,
            })
        }
        "oauth-app" => {
            print!("client id: ");
            io::stdout().flush()?;
            let mut client_id = String::new();
            io::stdin().read_line(&mut client_id)?;

            let client_secret = rpassword::prompt_password("client secret: ")?;

            print!("redirect uri (optional): ");
            io::stdout().flush()?;
            let mut redirect_uri = String::new();
            io::stdin().read_line(&mut redirect_uri)?;
            let redirect_uri = redirect_uri.trim();

            print!("scopes (comma-separated, optional): ");
            io::stdout().flush()?;
            let mut scopes_str = String::new();
            io::stdin().read_line(&mut scopes_str)?;
            let scopes_str = scopes_str.trim();

            Ok(SecretData::OAuthApp {
                client_id: client_id.trim().to_string(),
                client_secret,
                redirect_uri: if redirect_uri.is_empty() {
                    None
                } else {
                    Some(redirect_uri.to_string())
                },
                scopes: if scopes_str.is_empty() {
                    None
                } else {
                    Some(
                        scopes_str
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect(),
                    )
                },
            })
        }
        "ssh-key" => {
            eprintln!("enter private key (paste, then Ctrl-D):");
            let mut private_key = String::new();
            io::stdin().read_to_string(&mut private_key)?;

            print!("passphrase (optional, press enter to skip): ");
            io::stdout().flush()?;
            let passphrase = rpassword::prompt_password("")?;

            Ok(SecretData::SshKey {
                private_key,
                public_key: None,
                passphrase: if passphrase.is_empty() {
                    None
                } else {
                    Some(passphrase)
                },
            })
        }
        "environment" | "env" => {
            eprintln!("enter variables (KEY=VALUE per line, Ctrl-D to finish):");
            let mut variables = std::collections::HashMap::new();
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    variables.insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    eprintln!("  skipping invalid line: {}", line);
                }
            }
            Ok(SecretData::Environment { variables })
        }
        _ => {
            // Default to api-key for unknown types
            let key = rpassword::prompt_password("value: ")?;
            Ok(SecretData::ApiKey {
                key,
                endpoint: None,
                notes: None,
            })
        }
    }
}

fn program_yubikey_slot2(secret_hex: &str) -> Result<()> {
    // The ykman invocation is identical on every platform; the previous
    // #[cfg(windows)] / #[cfg(not(windows))] split was dead duplication.
    // Treat a non-zero exit as a hard error: a silently-discarded failure
    // (wrong YubiKey state, auth error, busy) would let `cred init` / `cred
    // recover` report success while the vault key is left unrecoverable via
    // hardware.
    let status = std::process::Command::new("ykman")
        .args(["otp", "chalresp", "2", "--force", secret_hex])
        .status()
        .context("failed to run ykman")?;
    if !status.success() {
        anyhow::bail!(
            "ykman exited with {} while programming YubiKey slot 2; \
             the challenge-response secret was not written",
            status
        );
    }
    Ok(())
}

/// One-shot migration that lifts pre-existing `user_id = 0` rows in both
/// `cred_secrets` and `cred_agent_keys` up to `CRED_USER_ID = 1`, the post-fix
/// canonical id. Returns the combined count of rows promoted across both tables.
///
/// Pre-fix builds wrote `user_id=0` from `cmd_store`/`cmd_get`/etc (and from the
/// agent-key generate/list/revoke commands) while `cmd_bootstrap_wrap` and the
/// secret operations used `user_id=1`. After the fix every site uses
/// `CRED_USER_ID`; rows produced by old binaries would otherwise become
/// invisible. This function brings them into the visible namespace.
///
/// Idempotent: re-running on a migrated DB is a no-op (no rows match).
/// Conflict-safe: when a `(user_id=0, category, name)` row would collide
/// with an existing `(user_id=1, category, name)` row (UNIQUE constraint),
/// or when multiple legacy `user_id=0` rows share the same `(category,name)`,
/// only one canonical row is promoted and the others are left in place with
/// a warning so the human operator can reconcile. Returns the count of rows
/// that were promoted.
async fn migrate_legacy_user_id_zero_rows(db: &Database) -> Result<usize> {
    db.write(|conn| {
        // Collect collisions with existing uid=1 rows first so the UPDATE
        // doesn't fight UNIQUE.
        let mut stmt = conn.prepare(
            "SELECT a.id, a.category, a.name FROM cred_secrets a
             WHERE a.user_id = 0
               AND EXISTS (
                   SELECT 1 FROM cred_secrets b
                   WHERE b.user_id = 1 AND b.category = a.category AND b.name = a.name
               )",
        )?;
        let collisions: Vec<(i64, String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        drop(stmt);

        for (id, cat, name) in &collisions {
            eprintln!(
                "warning: legacy cred row id={} ({}/{}) cannot be promoted; \
                 a user_id=1 row with the same key already exists. \
                 Resolve manually with sqlite3 cred.db (DELETE the legacy row \
                 or rename one of the entries).",
                id, cat, name
            );
        }

        // Legacy binaries could also create duplicate uid=0 rows for the same
        // key. Promoting all of them in one UPDATE would violate the UNIQUE
        // constraint on (user_id, category, name), so we promote only the
        // lowest-id row in each duplicate set and leave the rest parked at
        // uid=0 for manual cleanup.
        let mut dup_stmt = conn.prepare(
            "SELECT a.id, a.category, a.name FROM cred_secrets a
             WHERE a.user_id = 0
               AND EXISTS (
                   SELECT 1 FROM cred_secrets d
                   WHERE d.user_id = 0
                     AND d.category = a.category
                     AND d.name = a.name
                     AND d.id < a.id
               )",
        )?;
        let duplicate_uid0_rows: Vec<(i64, String, String)> = dup_stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        drop(dup_stmt);

        for (id, cat, name) in &duplicate_uid0_rows {
            eprintln!(
                "warning: legacy cred row id={} ({}/{}) is a duplicate uid=0 entry; \
                 leaving it in place and promoting only the oldest row for this key. \
                 Resolve manually with sqlite3 cred.db once access is restored.",
                id, cat, name
            );
        }

        let rows_promoted = conn.execute(
            "UPDATE cred_secrets
             SET user_id = 1
             WHERE id IN (
                 SELECT a.id
                 FROM cred_secrets a
                 WHERE a.user_id = 0
                   AND a.id = (
                       SELECT MIN(d.id)
                       FROM cred_secrets d
                       WHERE d.user_id = 0
                         AND d.category = a.category
                         AND d.name = a.name
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM cred_secrets b
                       WHERE b.user_id = 1
                         AND b.category = a.category
                         AND b.name = a.name
                   )
             )
             AND user_id = 0
               AND NOT EXISTS (
                   SELECT 1 FROM cred_secrets b
                   WHERE b.user_id = 1 AND b.category = cred_secrets.category AND b.name = cred_secrets.name
               )",
            [],
        )?;

        // cred_agent_keys carries the same legacy divergence: pre-fix binaries
        // wrote keys at user_id=0 while every other cred operation uses
        // user_id=1, so old keys are invisible to list/revoke. Promote them with
        // the same collision-safe logic. Its UNIQUE constraint is (user_id, name),
        // so keys are keyed on `name` alone (no category column).
        let mut key_collision_stmt = conn.prepare(
            "SELECT a.id, a.name FROM cred_agent_keys a
             WHERE a.user_id = 0
               AND EXISTS (
                   SELECT 1 FROM cred_agent_keys b
                   WHERE b.user_id = 1 AND b.name = a.name
               )",
        )?;
        let key_collisions: Vec<(i64, String)> = key_collision_stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        drop(key_collision_stmt);

        for (id, name) in &key_collisions {
            eprintln!(
                "warning: legacy cred agent key id={} ({}) cannot be promoted; \
                 a user_id=1 key with the same name already exists. \
                 Resolve manually with sqlite3 cred.db (DELETE the legacy key \
                 or rename one of the entries).",
                id, name
            );
        }

        // Duplicate uid=0 keys sharing a name: promote only the oldest, park the rest.
        let mut key_dup_stmt = conn.prepare(
            "SELECT a.id, a.name FROM cred_agent_keys a
             WHERE a.user_id = 0
               AND EXISTS (
                   SELECT 1 FROM cred_agent_keys d
                   WHERE d.user_id = 0 AND d.name = a.name AND d.id < a.id
               )",
        )?;
        let key_dups: Vec<(i64, String)> = key_dup_stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        drop(key_dup_stmt);

        for (id, name) in &key_dups {
            eprintln!(
                "warning: legacy cred agent key id={} ({}) is a duplicate uid=0 entry; \
                 leaving it in place and promoting only the oldest key for this name. \
                 Resolve manually with sqlite3 cred.db once access is restored.",
                id, name
            );
        }

        let keys_promoted = conn.execute(
            "UPDATE cred_agent_keys
             SET user_id = 1
             WHERE id IN (
                 SELECT a.id
                 FROM cred_agent_keys a
                 WHERE a.user_id = 0
                   AND a.id = (
                       SELECT MIN(d.id)
                       FROM cred_agent_keys d
                       WHERE d.user_id = 0 AND d.name = a.name
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM cred_agent_keys b
                       WHERE b.user_id = 1 AND b.name = a.name
                   )
             )
             AND user_id = 0
               AND NOT EXISTS (
                   SELECT 1 FROM cred_agent_keys b
                   WHERE b.user_id = 1 AND b.name = cred_agent_keys.name
               )",
            [],
        )?;

        Ok(rows_promoted + keys_promoted)
    })
    .await
    .context("failed to run user_id=0 -> 1 migration")
}

async fn init_schema(db: &Database) -> Result<()> {
    db.write(|conn| {
        // CRED_USER_ID is the canonical user_id for the local cred store.
        // The DEFAULT keeps fresh installs aligned even if a future caller
        // forgets to pass it explicitly.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cred_secrets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, category, name)
            );
            CREATE INDEX IF NOT EXISTS idx_cred_secrets_user_category
                ON cred_secrets(user_id, category);",
        )?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("failed to init schema: {}", e))
}

async fn cmd_agent_key(db: &Database, action: AgentKeyAction) -> Result<()> {
    use kleos_cred::{agent_keys, agent_keys_file::FileAgentKeyStore};

    match action {
        AgentKeyAction::Generate {
            name,
            description,
            scope,
        } => {
            // Any `bootstrap/*` scope routes the token to the file-backed
            // store so a fresh shell can read it before the cred DB is
            // unlocked. Mixing bootstrap and non-bootstrap scopes on a
            // single token is rejected; the two stores serve different
            // auth surfaces (bootstrap-bearer endpoint vs three-tier
            // resolve handlers).
            let bootstrap_scopes: Vec<&String> = scope
                .iter()
                .filter(|s| s.starts_with("bootstrap/") || s.as_str() == "*")
                .collect();
            let other_scopes: Vec<&String> = scope
                .iter()
                .filter(|s| !s.starts_with("bootstrap/") && s.as_str() != "*")
                .collect();

            if !bootstrap_scopes.is_empty() && !other_scopes.is_empty() {
                anyhow::bail!(
                    "cannot mix bootstrap/* scopes with other scopes in a single token; \
                     mint two separate tokens"
                );
            }

            if !bootstrap_scopes.is_empty() {
                // File-backed bootstrap-agent token.
                let mut store = FileAgentKeyStore::load()
                    .map_err(|e| anyhow::anyhow!("load agent-keys.json: {}", e))?;
                let key_hex = store
                    .generate(&name, &description, scope.clone())
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                eprintln!("minted bootstrap-agent token for '{}'", name);
                if !description.is_empty() {
                    eprintln!("description: {}", description);
                }
                eprintln!("scopes: {}", scope.join(", "));
                eprintln!();
                eprintln!("token (save this now -- it cannot be retrieved later):");
                println!("{}", key_hex);
                eprintln!();
                eprintln!("To make this shell's hook bootstrap pick it up:");
                eprintln!(
                    "  echo '{}' > ~/.config/cred/credd-agent-key.token",
                    key_hex
                );
                eprintln!("  chmod 600 ~/.config/cred/credd-agent-key.token");
                Ok(())
            } else {
                // DB-backed three-tier resolve agent key.
                let perms = kleos_cred::AgentKeyPermissions::default();
                let (key_str, agent_key) =
                    agent_keys::create_agent_key(db, CRED_USER_ID, &name, &perms)
                        .await
                        .map_err(|e| anyhow::anyhow!("{}", e))?;
                eprintln!("generated agent key for '{}'", name);
                if !description.is_empty() {
                    eprintln!("description: {}", description);
                }
                eprintln!();
                eprintln!("key (save this now -- it cannot be retrieved later):");
                println!("{}", key_str);
                eprintln!();
                eprintln!("key id: {}", agent_key.id);
                Ok(())
            }
        }
        AgentKeyAction::List => {
            let keys = agent_keys::list_agent_keys(db, CRED_USER_ID)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            if keys.is_empty() {
                println!("no agent keys");
                return Ok(());
            }

            println!(
                "{:<20} {:<10} {:<20} HASH PREFIX",
                "NAME", "STATUS", "CREATED"
            );
            println!("{:-<20} {:-<10} {:-<20} {:-<16}", "", "", "", "");

            for k in &keys {
                let status = if k.is_valid() { "active" } else { "revoked" };
                let hash_prefix = &k.key_hash[..16.min(k.key_hash.len())];
                println!(
                    "{:<20} {:<10} {:<20} {}",
                    k.name, status, k.created_at, hash_prefix
                );
            }
            println!("\n{} key(s)", keys.len());
            Ok(())
        }
        AgentKeyAction::Revoke { name, yes } => {
            if !yes {
                print!("revoke agent key '{}'? [y/N] ", name);
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("aborted.");
                    return Ok(());
                }
            }
            agent_keys::revoke_agent_key(db, CRED_USER_ID, &name)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            eprintln!("revoked agent key: {}", name);
            Ok(())
        }
    }
}

// --- TUI ---

/// A secret loaded for TUI display (decrypted).
struct TuiSecret {
    id: i64,
    service: String,
    key: String,
    data: SecretData,
}

struct TuiApp<'a> {
    db: &'a Database,
    master_key: [u8; 32],
    secrets: Vec<TuiSecret>,
    table_state: TableState,
    mode: TuiMode,
    input_buf: String,
    input_field: InputField,
    status_msg: String,
    show_values: bool,
    filter: String,
}

#[derive(PartialEq)]
enum TuiMode {
    Normal,
    Adding,
    Filtering,
    Confirm,
    Detail,
}

#[derive(PartialEq)]
enum InputField {
    Service,
    Key,
    Value,
}

impl<'a> TuiApp<'a> {
    fn new(db: &'a Database, master_key: [u8; 32]) -> Self {
        Self {
            db,
            master_key,
            secrets: Vec::new(),
            table_state: TableState::default(),
            mode: TuiMode::Normal,
            input_buf: String::new(),
            input_field: InputField::Service,
            status_msg: String::new(),
            show_values: false,
            filter: String::new(),
        }
    }

    async fn refresh(&mut self) {
        match storage::list_secrets(self.db, CRED_USER_ID, None).await {
            Ok(rows) => {
                let mut secrets = Vec::new();
                for row in rows {
                    match storage::get_secret(
                        self.db,
                        CRED_USER_ID,
                        &row.category,
                        &row.name,
                        &self.master_key,
                    )
                    .await
                    {
                        Ok((_r, data)) => {
                            secrets.push(TuiSecret {
                                id: row.id,
                                service: row.category,
                                key: row.name,
                                data,
                            });
                        }
                        Err(e) => {
                            self.status_msg = format!("decrypt error: {}", e);
                        }
                    }
                }
                self.secrets = secrets;
                if self.secrets.is_empty() {
                    self.table_state.select(None);
                } else if self.table_state.selected().is_none() {
                    self.table_state.select(Some(0));
                }
            }
            Err(e) => {
                self.status_msg = format!("error: {}", e);
            }
        }
    }

    fn filtered_secrets(&self) -> Vec<&TuiSecret> {
        if self.filter.is_empty() {
            self.secrets.iter().collect()
        } else {
            let f = self.filter.to_lowercase();
            self.secrets
                .iter()
                .filter(|s| {
                    s.service.to_lowercase().contains(&f) || s.key.to_lowercase().contains(&f)
                })
                .collect()
        }
    }

    fn selected_secret(&self) -> Option<&TuiSecret> {
        let filtered = self.filtered_secrets();
        self.table_state
            .selected()
            .and_then(|i| filtered.get(i).copied())
    }
}

async fn cmd_tui(db: &Database, master_key: &[u8; 32]) -> Result<()> {
    let mut app = TuiApp::new(db, *master_key);
    app.refresh().await;

    // Terminal setup
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Temp buffers for add flow
    let mut add_service = String::new();
    let mut add_key = String::new();

    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match app.mode {
                    TuiMode::Normal => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            let filtered = app.filtered_secrets();
                            if !filtered.is_empty() {
                                let i = app
                                    .table_state
                                    .selected()
                                    .map(|i| (i + 1) % filtered.len())
                                    .unwrap_or(0);
                                app.table_state.select(Some(i));
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            let filtered = app.filtered_secrets();
                            if !filtered.is_empty() {
                                let i = app
                                    .table_state
                                    .selected()
                                    .map(|i| if i == 0 { filtered.len() - 1 } else { i - 1 })
                                    .unwrap_or(0);
                                app.table_state.select(Some(i));
                            }
                        }
                        KeyCode::Char('a') => {
                            app.mode = TuiMode::Adding;
                            app.input_field = InputField::Service;
                            app.input_buf.clear();
                            add_service.clear();
                            add_key.clear();
                            app.status_msg = "enter service name".to_string();
                        }
                        KeyCode::Char('d') if app.selected_secret().is_some() => {
                            app.mode = TuiMode::Confirm;
                            app.status_msg = "delete? (y/n)".to_string();
                        }
                        KeyCode::Char('v') => {
                            app.show_values = !app.show_values;
                            app.status_msg = if app.show_values {
                                "values visible".to_string()
                            } else {
                                "values hidden".to_string()
                            };
                        }
                        KeyCode::Char('/') => {
                            app.mode = TuiMode::Filtering;
                            app.input_buf = app.filter.clone();
                            app.status_msg = "filter:".to_string();
                        }
                        KeyCode::Enter if app.selected_secret().is_some() => {
                            app.mode = TuiMode::Detail;
                        }
                        KeyCode::Char('r') => {
                            app.refresh().await;
                            app.status_msg = "refreshed".to_string();
                        }
                        _ => {}
                    },

                    TuiMode::Adding => match key.code {
                        KeyCode::Esc => {
                            app.input_buf.zeroize();
                            add_service.zeroize();
                            add_key.zeroize();
                            app.mode = TuiMode::Normal;
                            app.status_msg.clear();
                        }
                        KeyCode::Enter => match app.input_field {
                            InputField::Service => {
                                if app.input_buf.is_empty() {
                                    app.status_msg = "service name cannot be empty".to_string();
                                } else {
                                    add_service = app.input_buf.clone();
                                    app.input_buf.clear();
                                    app.input_field = InputField::Key;
                                    app.status_msg = "enter key name".to_string();
                                }
                            }
                            InputField::Key => {
                                if app.input_buf.is_empty() {
                                    app.status_msg = "key name cannot be empty".to_string();
                                } else {
                                    add_key = app.input_buf.clone();
                                    app.input_buf.clear();
                                    app.input_field = InputField::Value;
                                    app.status_msg = "enter api-key value".to_string();
                                }
                            }
                            InputField::Value => {
                                if app.input_buf.is_empty() {
                                    app.status_msg = "value cannot be empty".to_string();
                                } else {
                                    let data = SecretData::ApiKey {
                                        key: app.input_buf.clone(),
                                        endpoint: None,
                                        notes: None,
                                    };
                                    app.input_buf.zeroize();
                                    match storage::store_secret(
                                        app.db,
                                        CRED_USER_ID,
                                        &add_service,
                                        &add_key,
                                        &data,
                                        &app.master_key,
                                    )
                                    .await
                                    {
                                        Ok(id) => {
                                            app.status_msg = format!(
                                                "stored {}/{} (id={})",
                                                add_service, add_key, id
                                            );
                                            app.refresh().await;
                                        }
                                        Err(e) => {
                                            app.status_msg = format!("error: {}", e);
                                        }
                                    }
                                    add_service.zeroize();
                                    add_key.zeroize();
                                    app.mode = TuiMode::Normal;
                                }
                            }
                        },
                        KeyCode::Backspace => {
                            app.input_buf.pop();
                        }
                        KeyCode::Char(c) => {
                            app.input_buf.push(c);
                        }
                        _ => {}
                    },

                    TuiMode::Filtering => match key.code {
                        KeyCode::Esc => {
                            app.filter.clear();
                            app.mode = TuiMode::Normal;
                            app.status_msg.clear();
                            app.table_state.select(if app.secrets.is_empty() {
                                None
                            } else {
                                Some(0)
                            });
                        }
                        KeyCode::Enter => {
                            app.filter = app.input_buf.clone();
                            app.mode = TuiMode::Normal;
                            app.status_msg = if app.filter.is_empty() {
                                String::new()
                            } else {
                                format!("filter: {}", app.filter)
                            };
                            app.table_state
                                .select(if app.filtered_secrets().is_empty() {
                                    None
                                } else {
                                    Some(0)
                                });
                        }
                        KeyCode::Backspace => {
                            app.input_buf.pop();
                        }
                        KeyCode::Char(c) => {
                            app.input_buf.push(c);
                        }
                        _ => {}
                    },

                    TuiMode::Confirm => match key.code {
                        KeyCode::Char('y') => {
                            if let Some(secret) = app.selected_secret() {
                                let svc = secret.service.clone();
                                let k = secret.key.clone();
                                match storage::delete_secret(app.db, CRED_USER_ID, &svc, &k).await {
                                    Ok(()) => {
                                        app.status_msg = format!("deleted {}/{}", svc, k);
                                        app.refresh().await;
                                    }
                                    Err(e) => {
                                        app.status_msg = format!("error: {}", e);
                                    }
                                }
                            }
                            app.mode = TuiMode::Normal;
                        }
                        _ => {
                            app.mode = TuiMode::Normal;
                            app.status_msg = "cancelled".to_string();
                        }
                    },

                    TuiMode::Detail => match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                            app.mode = TuiMode::Normal;
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn draw_ui(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // table
            Constraint::Length(3), // status / input
        ])
        .split(f.area());

    draw_header(f, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_status(f, app, chunks[2]);

    // Modal overlay for detail view
    if app.mode == TuiMode::Detail {
        if let Some(secret) = app.selected_secret() {
            draw_detail_modal(f, secret, app.show_values);
        }
    }
}

fn draw_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "cred",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled("a", Style::default().fg(Color::Yellow)),
        Span::raw("dd "),
        Span::styled("d", Style::default().fg(Color::Yellow)),
        Span::raw("elete "),
        Span::styled("v", Style::default().fg(Color::Yellow)),
        Span::raw("alues "),
        Span::styled("/", Style::default().fg(Color::Yellow)),
        Span::raw("filter "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw("efresh "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw("uit"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let filtered = app.filtered_secrets();

    let header = Row::new(vec![
        Cell::from("SERVICE").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("KEY").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TYPE").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("PREVIEW").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = filtered
        .iter()
        .map(|secret| {
            let preview = if app.show_values {
                secret.data.redacted_preview()
            } else {
                secret.data.type_name().to_string()
            };
            Row::new(vec![
                Cell::from(secret.service.clone()).style(Style::default().fg(Color::Green)),
                Cell::from(secret.key.clone()),
                Cell::from(secret.data.type_name()).style(Style::default().fg(Color::Yellow)),
                Cell::from(preview).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(35),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(if app.filter.is_empty() {
                    format!(" secrets ({}) ", app.secrets.len())
                } else {
                    format!(
                        " secrets ({}/{}) [{}] ",
                        filtered.len(),
                        app.secrets.len(),
                        app.filter
                    )
                }),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_status(f: &mut Frame, app: &TuiApp, area: Rect) {
    let content = match app.mode {
        TuiMode::Adding => {
            let field_name = match app.input_field {
                InputField::Service => "service",
                InputField::Key => "key",
                InputField::Value => "value",
            };
            let display = if app.input_field == InputField::Value {
                "*".repeat(app.input_buf.len())
            } else {
                app.input_buf.clone()
            };
            format!("[add] {}: {}|", field_name, display)
        }
        TuiMode::Filtering => {
            format!("/{}", app.input_buf)
        }
        _ => app.status_msg.clone(),
    };

    let status = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(status, area);
}

fn draw_detail_modal(f: &mut Frame, secret: &TuiSecret, show_value: bool) {
    let area = f.area();
    let modal_width = 60.min(area.width - 4);
    let modal_height = 10.min(area.height - 4);
    let modal_area = Rect::new(
        (area.width - modal_width) / 2,
        (area.height - modal_height) / 2,
        modal_width,
        modal_height,
    );

    f.render_widget(Clear, modal_area);

    let preview = if show_value {
        secret.data.redacted_preview()
    } else {
        "[hidden -- press v to show]".to_string()
    };

    let fields_str = secret.data.field_names().join(", ");

    let lines = vec![
        Line::from(vec![
            Span::styled("Service: ", Style::default().fg(Color::Cyan)),
            Span::raw(&secret.service),
        ]),
        Line::from(vec![
            Span::styled("Key:     ", Style::default().fg(Color::Cyan)),
            Span::raw(&secret.key),
        ]),
        Line::from(vec![
            Span::styled("Type:    ", Style::default().fg(Color::Cyan)),
            Span::raw(secret.data.type_name()),
        ]),
        Line::from(vec![
            Span::styled("Fields:  ", Style::default().fg(Color::Cyan)),
            Span::raw(&fields_str),
        ]),
        Line::from(vec![
            Span::styled("Preview: ", Style::default().fg(Color::Cyan)),
            Span::raw(preview),
        ]),
        Line::from(vec![
            Span::styled("ID:      ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("#{}", secret.id)),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "press ESC to close, v to toggle values",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" detail "),
    );
    f.render_widget(detail, modal_area);
}

// --- credd fallback for secret resolution ---

async fn resolve_via_credd(
    master_key: &[u8; KEY_SIZE],
    service: &str,
    key: &str,
) -> Result<(storage::SecretRow, kleos_cred::types::SecretData)> {
    let credd_url = std::env::var("CREDD_URL").unwrap_or_else(|_| "http://127.0.0.1:4400".into());
    // The master key authenticates to credd as a Bearer token (credd's auth
    // model). Refuse to send it over a plaintext non-loopback hop.
    kleos_cred::net::guard_credd_transport(&credd_url)?;
    let auth_token = hex::encode(master_key);

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/secret/{}/{}",
            credd_url.trim_end_matches('/'),
            service,
            key
        ))
        .header("Authorization", format!("Bearer {}", auth_token))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .context("credd unreachable")?;

    if !resp.status().is_success() {
        anyhow::bail!("credd returned {}", resp.status());
    }

    let body: serde_json::Value = resp.json().await.context("invalid credd response")?;

    let data: kleos_cred::types::SecretData =
        serde_json::from_value(body["value"].clone()).context("failed to parse secret data")?;

    let secret_type_str = body["type"].as_str().unwrap_or("api_key");
    let secret_type = kleos_cred::types::SecretType::parse(secret_type_str)
        .unwrap_or(kleos_cred::types::SecretType::ApiKey);

    let row = storage::SecretRow {
        id: 0,
        user_id: CRED_USER_ID,
        name: key.to_string(),
        category: service.to_string(),
        secret_type,
        created_at: String::new(),
        updated_at: String::new(),
    };

    Ok((row, data))
}

// --- Bootstrap blob (CBv1) wrap / unwrap ---

/// On-disk magic for the credd bootstrap blob.
const BOOTSTRAP_MAGIC: &[u8; 4] = b"CBv1";
/// ASCII record separator used to split the JSON header from the bare key.
const HEADER_KEY_SEPARATOR: u8 = 0x1E;

fn bootstrap_default_path() -> PathBuf {
    config_dir().join("bootstrap.enc")
}

fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()))
}

/// Read an ApiKey-typed cred entry, encrypt with the just-derived master
/// key, and write a CBv1 blob to disk (mode 0600). credd will decrypt this
/// blob at startup using the same YubiKey-derived key.
async fn cmd_bootstrap_wrap(
    db: &Database,
    master_key: &[u8; KEY_SIZE],
    service: &str,
    secret_key: &str,
    out_path: Option<PathBuf>,
) -> Result<()> {
    let out = out_path.unwrap_or_else(bootstrap_default_path);

    let (_row, data) = storage::get_secret(db, CRED_USER_ID, service, secret_key, master_key)
        .await
        .with_context(|| format!("entry {}/{} not found in cred store", service, secret_key))?;

    let bare_key = match &data {
        SecretData::ApiKey { key, .. } => key.clone(),
        other => anyhow::bail!(
            "bootstrap can only wrap ApiKey-typed entries (got: {}/{} of type {:?})",
            service,
            secret_key,
            std::mem::discriminant(other)
        ),
    };

    let hostname = read_hostname();
    let header = serde_json::json!({
        "v": 1,
        "slot": format!("{}/{}", service, secret_key),
        "host": hostname,
    });
    let header_bytes = serde_json::to_vec(&header)?;

    let mut payload: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(header_bytes.len() + 1 + bare_key.len()));
    payload.extend_from_slice(&header_bytes);
    payload.push(HEADER_KEY_SEPARATOR);
    payload.extend_from_slice(bare_key.as_bytes());

    let ciphertext = crypto_encrypt(master_key, &payload).context("encrypt bootstrap blob")?;

    let mut blob = Vec::with_capacity(BOOTSTRAP_MAGIC.len() + ciphertext.len());
    blob.extend_from_slice(BOOTSTRAP_MAGIC);
    blob.extend_from_slice(&ciphertext);

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&out)?
            .write_all(&blob)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&out, &blob)?;
    }

    eprintln!("wrote {} bytes to {}", blob.len(), out.display());
    Ok(())
}

/// Decrypt a CBv1 bootstrap blob and print the bare bearer to stdout.
/// Used as a manual escape hatch when credd itself cannot serve the bearer.
async fn cmd_bootstrap_unwrap(
    master_key: &[u8; KEY_SIZE],
    from_path: Option<PathBuf>,
    raw: bool,
) -> Result<()> {
    let from = from_path.unwrap_or_else(bootstrap_default_path);

    let data =
        std::fs::read(&from).with_context(|| format!("failed to read {}", from.display()))?;

    if data.len() < BOOTSTRAP_MAGIC.len() || &data[..BOOTSTRAP_MAGIC.len()] != BOOTSTRAP_MAGIC {
        anyhow::bail!(
            "not a CBv1 bootstrap blob: {} (got magic {:?})",
            from.display(),
            &data[..BOOTSTRAP_MAGIC.len().min(data.len())]
        );
    }

    let plaintext_bytes = crypto_decrypt(master_key, &data[BOOTSTRAP_MAGIC.len()..])
        .context("decryption failed (wrong YubiKey or corrupted blob)")?;
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(plaintext_bytes);

    let sep_pos = plaintext
        .iter()
        .position(|&b| b == HEADER_KEY_SEPARATOR)
        .ok_or_else(|| anyhow::anyhow!("malformed CBv1 payload: missing 0x1E separator"))?;
    let (header_bytes, key_bytes) = plaintext.split_at(sep_pos);
    let key_bytes = &key_bytes[1..]; // skip the 0x1E byte itself

    if let Ok(hdr) = serde_json::from_slice::<serde_json::Value>(header_bytes) {
        let slot = hdr.get("slot").and_then(|v| v.as_str()).unwrap_or("?");
        let host = hdr.get("host").and_then(|v| v.as_str()).unwrap_or("?");
        eprintln!("bootstrap blob: slot={} host={}", slot, host);
    }

    let bare_key_str =
        std::str::from_utf8(key_bytes).context("bootstrap blob key bytes are not valid UTF-8")?;

    if raw {
        print!("{}", bare_key_str);
    } else {
        println!("{}", bare_key_str);
    }
    io::stdout().flush()?;

    drop(plaintext);
    Ok(())
}

// --- cred piv subcommand ---

async fn cmd_piv(cmd: PivCmd) -> Result<()> {
    use kleos_cred::piv::{
        export_pubkey_pem, generate_p256_key, generate_self_signed_cert, pubkey_fingerprint,
        pubkey_path, slot_has_key, PinPolicy, PivSlot, TouchPolicy,
    };

    match cmd {
        PivCmd::Setup { touch_policy } => {
            let touch = match touch_policy.as_str() {
                "never" => TouchPolicy::Never,
                "cached" => TouchPolicy::Cached,
                "always" => TouchPolicy::Always,
                other => anyhow::bail!(
                    "invalid touch policy `{}` (use: never, cached, always)",
                    other
                ),
            };

            // Make sure the config dir exists.
            let cfg_parent = pubkey_path(PivSlot::KeyManagement);
            if let Some(parent) = cfg_parent.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create config dir at {}", parent.display()))?;
            }

            for (slot, subject) in [
                (PivSlot::KeyManagement, "CN=credd-ecdh-9d,O=Syntheos"),
                (PivSlot::Authentication, "CN=credd-auth-9a,O=Syntheos"),
            ] {
                let out = pubkey_path(slot);
                if slot_has_key(slot) {
                    eprintln!(
                        "slot {} already has a key -- re-exporting pubkey + (re)generating cert",
                        slot.as_hex()
                    );
                    let pem = export_pubkey_pem(slot)?;
                    std::fs::write(&out, &pem)
                        .with_context(|| format!("write pubkey to {}", out.display()))?;
                } else {
                    eprintln!(
                        "generating P-256 keypair on YubiKey slot {} (touch-policy={})...",
                        slot.as_hex(),
                        touch.as_str()
                    );
                    generate_p256_key(slot, PinPolicy::Never, touch, &out)?;
                }
                eprintln!(
                    "  generating self-signed cert for slot {}...",
                    slot.as_hex()
                );
                generate_self_signed_cert(slot, subject, &out)?;
                eprintln!("  pubkey -> {}", out.display());
            }
            eprintln!("PIV setup complete.");
            Ok(())
        }
        PivCmd::SetupSshCa { touch_policy } => {
            let touch = match touch_policy.as_str() {
                "never" => TouchPolicy::Never,
                "cached" => TouchPolicy::Cached,
                "always" => TouchPolicy::Always,
                other => anyhow::bail!(
                    "invalid touch policy `{}` (use: never, cached, always)",
                    other
                ),
            };

            let slot = PivSlot::Signature;
            let subject = "CN=ssh-ca,O=Syntheos";
            let out = pubkey_path(slot);

            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create config dir at {}", parent.display()))?;
            }

            if slot_has_key(slot) {
                eprintln!(
                    "slot {} already has a key -- re-exporting pubkey + (re)generating cert",
                    slot.as_hex()
                );
                let pem = export_pubkey_pem(slot)?;
                std::fs::write(&out, &pem)
                    .with_context(|| format!("write pubkey to {}", out.display()))?;
            } else {
                eprintln!(
                    "generating P-256 SSH CA keypair on YubiKey slot {} (touch-policy={})...",
                    slot.as_hex(),
                    touch.as_str()
                );
                generate_p256_key(slot, PinPolicy::Never, touch, &out)?;
            }
            eprintln!(
                "  generating self-signed cert for slot {}...",
                slot.as_hex()
            );
            generate_self_signed_cert(slot, subject, &out)?;
            eprintln!("  pubkey PEM -> {}", out.display());

            let ssh_ca_pub = out
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("ssh-ca.pub");
            let convert = std::process::Command::new("ssh-keygen")
                .args(["-i", "-m", "PKCS8", "-f"])
                .arg(&out)
                .output()
                .context("ssh-keygen not found")?;
            if !convert.status.success() {
                anyhow::bail!(
                    "ssh-keygen -i failed: {}",
                    String::from_utf8_lossy(&convert.stderr)
                );
            }
            std::fs::write(&ssh_ca_pub, &convert.stdout)
                .with_context(|| format!("write SSH CA pubkey to {}", ssh_ca_pub.display()))?;
            eprintln!("  ssh pubkey -> {}", ssh_ca_pub.display());
            eprintln!(
                "SSH CA setup complete. Deploy {} to servers as TrustedUserCAKeys.",
                ssh_ca_pub.display()
            );
            Ok(())
        }
        PivCmd::Status => {
            for slot in [
                PivSlot::KeyManagement,
                PivSlot::Authentication,
                PivSlot::Signature,
            ] {
                let path = pubkey_path(slot);
                if !slot_has_key(slot) {
                    println!("slot {}: empty", slot.as_hex());
                    continue;
                }
                let pem = match export_pubkey_pem(slot) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("slot {}: error -- {}", slot.as_hex(), e);
                        continue;
                    }
                };
                let fp = pubkey_fingerprint(&pem);
                let cached_match = std::fs::read_to_string(&path)
                    .map(|c| c.trim() == pem.trim())
                    .unwrap_or(false);
                println!("slot {}: provisioned", slot.as_hex());
                println!("  fingerprint: SHA-256:{}", fp);
                println!(
                    "  cached pem : {} ({})",
                    path.display(),
                    if cached_match {
                        "matches slot"
                    } else if path.exists() {
                        "DIFFERS from slot"
                    } else {
                        "missing"
                    }
                );
            }
            Ok(())
        }
    }
}

// --- cred ssh-ca subcommand ---

const PKCS11_LIB_PATHS: &[&str] = &[
    "/usr/lib/libykcs11.so",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/local/lib/libykcs11.so",
    "/opt/homebrew/lib/libykcs11.so",
];

fn find_pkcs11_lib() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("PKCS11_PROVIDER") {
        let path = PathBuf::from(&p);
        anyhow::ensure!(path.exists(), "PKCS11_PROVIDER={} does not exist", p);
        return Ok(path);
    }
    for p in PKCS11_LIB_PATHS {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }
    anyhow::bail!("libykcs11.so not found. Install yubico-piv-tool or set PKCS11_PROVIDER env var.")
}

fn ssh_ca_pubkey_path() -> PathBuf {
    kleos_cred::piv::pubkey_path(kleos_cred::piv::PivSlot::Signature)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("ssh-ca.pub")
}

fn ssh_ca_sign_impl(identity: &str, principal: &str, ttl: &str, pubkey: &Path) -> Result<PathBuf> {
    let pkcs11 = find_pkcs11_lib()?;
    let ca_pub = ssh_ca_pubkey_path();
    anyhow::ensure!(
        ca_pub.exists(),
        "SSH CA pubkey not found at {}. Run `cred piv setup-ssh-ca` first.",
        ca_pub.display()
    );
    anyhow::ensure!(
        pubkey.exists(),
        "agent pubkey not found at {}",
        pubkey.display()
    );

    let pin = std::env::var("YKMAN_PIN")
        .or_else(|_| std::env::var("PIV_PIN"))
        .ok()
        .filter(|p| !p.is_empty() && p != kleos_cred::piv::DEFAULT_PIN)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "PIV PIN not available: set YKMAN_PIN or PIV_PIN to a non-default value \
             (refusing factory-default to avoid burning PIN retries)"
            )
        })?;
    // F08: write the askpass helper to a random-named O_EXCL tempfile instead of
    // a predictable /tmp path, so a local attacker cannot pre-create or race it.
    // into_temp_path() drops the write handle (avoids ETXTBSY when ssh-keygen
    // execs the script); the returned TempPath auto-removes on drop.
    let askpass = tempfile::Builder::new()
        .prefix("cred-ssh-ca-askpass-")
        .suffix(".sh")
        .tempfile()
        .context("create askpass helper")?
        .into_temp_path();
    std::fs::write(&askpass, format!("#!/bin/sh\necho '{}'\n", pin))
        .context("write askpass helper")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))
            .context("chmod askpass")?;
    }

    let out = std::process::Command::new("ssh-keygen")
        .args(["-s"])
        .arg(&ca_pub)
        .args(["-D"])
        .arg(&pkcs11)
        .args(["-I", identity, "-n", principal, "-V", ttl])
        .arg(pubkey)
        .env("SSH_ASKPASS", askpass.as_os_str())
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .output()
        .context("ssh-keygen not found")?;

    // Eagerly remove the PIN-bearing helper as soon as ssh-keygen returns to
    // minimise its lifetime; the TempPath drop is the fallback if this fails.
    let _ = std::fs::remove_file(&askpass);

    if !out.status.success() {
        anyhow::bail!(
            "ssh-keygen -s failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let stem = pubkey
        .to_string_lossy()
        .trim_end_matches(".pub")
        .to_string();
    Ok(PathBuf::from(format!("{}-cert.pub", stem)))
}

/// Response from Phylax after signing caller-provided public key material.
#[derive(serde::Deserialize)]
struct PhylaxSignResponse {
    /// OpenSSH certificate public key text.
    cert_public_key: String,
}

/// Response from Phylax after minting an agent keypair and certificate.
#[derive(serde::Deserialize)]
struct PhylaxMintResponse {
    /// Path to the generated private key.
    key_path: PathBuf,
    /// Path to the generated public certificate.
    cert_path: PathBuf,
}

/// Resolve the local Phylax base URL.
fn phylax_url() -> String {
    std::env::var("PHYLAX_URL")
        .or_else(|_| std::env::var("CREDD_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:4400".into())
}

/// Read the local credd/phylax bearer token for agent-safe API calls.
fn phylax_auth_token() -> Result<String> {
    if let Ok(token) = std::env::var("CREDD_AGENT_KEY") {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }

    let token_path = config_dir().join("credd-agent-key.token");
    let token = std::fs::read_to_string(&token_path)
        .with_context(|| format!("read Phylax agent token from {}", token_path.display()))?;
    let token = token.trim();
    anyhow::ensure!(
        !token.is_empty(),
        "Phylax agent token at {} is empty",
        token_path.display()
    );
    Ok(token.to_string())
}

/// Sign an existing public key through Phylax and write the local cert file.
async fn ssh_ca_sign_via_phylax(
    identity: &str,
    principal: &str,
    ttl: &str,
    pubkey: &Path,
) -> Result<PathBuf> {
    let public_key = std::fs::read_to_string(pubkey)
        .with_context(|| format!("read public key from {}", pubkey.display()))?;
    // F07: the owner/master key is sent as the Bearer token below; refuse to
    // transmit it over plaintext http to a non-loopback Phylax host.
    let base = phylax_url();
    kleos_cred::net::guard_credd_transport(&base)?;
    let resp = reqwest::Client::new()
        .post(format!("{}/phylax/ssh-ca/sign", base.trim_end_matches('/')))
        .header("Authorization", format!("Bearer {}", phylax_auth_token()?))
        .json(&serde_json::json!({
            "identity": identity,
            "principal": principal,
            "ttl": ttl,
            "public_key": public_key,
        }))
        .send()
        .await
        .context("Phylax SSH CA sign request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Phylax SSH CA sign returned {}", resp.status());
    }

    let body: PhylaxSignResponse = resp.json().await.context("parse Phylax sign response")?;
    let stem = pubkey
        .to_string_lossy()
        .trim_end_matches(".pub")
        .to_string();
    let cert_path = PathBuf::from(format!("{}-cert.pub", stem));
    std::fs::write(&cert_path, body.cert_public_key)
        .with_context(|| format!("write certificate to {}", cert_path.display()))?;
    Ok(cert_path)
}

/// Ask Phylax to mint an agent keypair and SSH certificate.
async fn ssh_ca_mint_via_phylax(
    agent: &str,
    principal: &str,
    ttl: &str,
) -> Result<PhylaxMintResponse> {
    // F07: refuse to send the Bearer token over plaintext http to a non-loopback
    // Phylax host (same transport guard as the sign path).
    let base = phylax_url();
    kleos_cred::net::guard_credd_transport(&base)?;
    let resp = reqwest::Client::new()
        .post(format!("{}/phylax/ssh-ca/mint", base.trim_end_matches('/')))
        .header("Authorization", format!("Bearer {}", phylax_auth_token()?))
        .json(&serde_json::json!({
            "agent": agent,
            "principal": principal,
            "ttl": ttl,
        }))
        .send()
        .await
        .context("Phylax SSH CA mint request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Phylax SSH CA mint returned {}", resp.status());
    }

    resp.json().await.context("parse Phylax mint response")
}

async fn cmd_ssh_ca(cmd: SshCaCmd) -> Result<()> {
    match cmd {
        SshCaCmd::Sign {
            identity,
            principal,
            ttl,
            via_phylax,
            pubkey,
        } => {
            let cert = if via_phylax {
                ssh_ca_sign_via_phylax(&identity, &principal, &ttl, &pubkey).await?
            } else {
                ssh_ca_sign_impl(&identity, &principal, &ttl, &pubkey)?
            };
            println!("{}", cert.display());
            Ok(())
        }
        SshCaCmd::Mint {
            agent,
            principal,
            ttl,
            out_dir,
            via_phylax,
        } => {
            if via_phylax {
                let minted = ssh_ca_mint_via_phylax(&agent, &principal, &ttl).await?;
                println!("key:  {}", minted.key_path.display());
                println!("cert: {}", minted.cert_path.display());
                return Ok(());
            }

            let dir = out_dir.unwrap_or_else(|| {
                directories::BaseDirs::new()
                    .map(|d| d.home_dir().to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".ssh")
                    .join("agent")
            });
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("create agent key dir at {}", dir.display()))?;

            let key_path = dir.join(&agent);
            let pub_path = dir.join(format!("{}.pub", agent));

            if key_path.exists() {
                std::fs::remove_file(&key_path).ok();
            }
            if pub_path.exists() {
                std::fs::remove_file(&pub_path).ok();
            }

            let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M");
            let comment = format!("{}@{}", agent, timestamp);

            let gen = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-C", &comment, "-f"])
                .arg(&key_path)
                .output()
                .context("ssh-keygen not found")?;
            if !gen.status.success() {
                anyhow::bail!(
                    "ssh-keygen keygen failed: {}",
                    String::from_utf8_lossy(&gen.stderr)
                );
            }

            let cert = ssh_ca_sign_impl(&agent, &principal, &ttl, &pub_path)?;

            println!("key:  {}", key_path.display());
            println!("cert: {}", cert.display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    #[allow(deprecated)]
    #[test]
    fn cbv1_format_roundtrip() {
        let key = derive_key_legacy(b"01234567890123456789");
        let bare = "kl_test_bearer_xyz789";

        let header = serde_json::json!({"v":1,"slot":"engram-rust/credd-test","host":"test"});
        let header_bytes = serde_json::to_vec(&header).unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(&header_bytes);
        payload.push(HEADER_KEY_SEPARATOR);
        payload.extend_from_slice(bare.as_bytes());

        let ciphertext = crypto_encrypt(&key, &payload).unwrap();
        let mut blob = BOOTSTRAP_MAGIC.to_vec();
        blob.extend_from_slice(&ciphertext);

        assert_eq!(&blob[..4], BOOTSTRAP_MAGIC);

        let decrypted = crypto_decrypt(&key, &blob[4..]).unwrap();
        let sep = decrypted
            .iter()
            .position(|&b| b == HEADER_KEY_SEPARATOR)
            .unwrap();
        let (hdr_bytes, rest) = decrypted.split_at(sep);
        let key_bytes = &rest[1..];

        let hdr: serde_json::Value = serde_json::from_slice(hdr_bytes).unwrap();
        assert_eq!(hdr["v"], 1);
        assert_eq!(hdr["slot"], "engram-rust/credd-test");
        assert_eq!(key_bytes, bare.as_bytes());
    }

    #[test]
    fn wrong_magic_detected() {
        let bad = b"BAD1somegarbage";
        assert_ne!(&bad[..4], BOOTSTRAP_MAGIC);
    }
}

#[cfg(test)]
mod user_id_migration_tests {
    use super::*;

    /// Build an in-memory cred_secrets table with the production schema and
    /// return a Database handle. We construct it inline so the test does not
    /// depend on the YubiKey-gated `cmd_init` path.
    async fn fresh_cred_db() -> Database {
        let db = Database::connect_memory().await.expect("in-memory db");
        // Match init_schema's CREATE statements exactly so the migration
        // runs against a representative schema.
        db.write(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS cred_secrets (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL DEFAULT 1,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    encrypted_data BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, category, name)
                );",
            )?;
            Ok(())
        })
        .await
        .unwrap();
        db
    }

    async fn fresh_legacy_cred_db_without_unique() -> Database {
        let db = Database::connect_memory().await.expect("in-memory db");
        db.write(|conn| {
            conn.execute("DROP TABLE IF EXISTS cred_secrets", [])?;
            conn.execute_batch(
                "CREATE TABLE cred_secrets (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL DEFAULT 1,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    encrypted_data BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );",
            )?;
            Ok(())
        })
        .await
        .unwrap();
        db
    }

    async fn insert_row(db: &Database, user_id: i64, category: &str, name: &str) {
        let category = category.to_string();
        let name = name.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO cred_secrets (user_id, name, category, secret_type, encrypted_data, nonce, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'api-key', X'00', X'00', '2026-01-01', '2026-01-01')",
                rusqlite::params![user_id, name, category],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn count_rows(db: &Database, user_id: i64) -> i64 {
        db.read(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM cred_secrets WHERE user_id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )?)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn migration_promotes_uid0_rows_when_no_collision() {
        let db = fresh_cred_db().await;
        insert_row(&db, 0, "myservice", "admin").await;
        insert_row(&db, 0, "grafana", "admin").await;
        insert_row(&db, 1, "engram-rust", "claude-code-host").await; // unrelated row

        let promoted = migrate_legacy_user_id_zero_rows(&db).await.unwrap();
        assert_eq!(promoted, 2, "both legacy rows should be promoted");

        assert_eq!(count_rows(&db, 0).await, 0, "no uid=0 rows should remain");
        assert_eq!(count_rows(&db, 1).await, 3, "all rows now live at uid=1");
    }

    #[tokio::test]
    async fn migration_is_idempotent() {
        let db = fresh_cred_db().await;
        insert_row(&db, 0, "myservice", "admin").await;

        let first = migrate_legacy_user_id_zero_rows(&db).await.unwrap();
        let second = migrate_legacy_user_id_zero_rows(&db).await.unwrap();

        assert_eq!(first, 1);
        assert_eq!(second, 0, "second run is a no-op");
        assert_eq!(count_rows(&db, 1).await, 1);
    }

    #[tokio::test]
    async fn migration_skips_collisions() {
        let db = fresh_cred_db().await;
        // Pre-existing uid=1 row that conflicts with the legacy uid=0 row
        insert_row(&db, 1, "myservice", "admin").await;
        insert_row(&db, 0, "myservice", "admin").await;
        // Non-colliding legacy row
        insert_row(&db, 0, "grafana", "admin").await;

        let promoted = migrate_legacy_user_id_zero_rows(&db).await.unwrap();
        assert_eq!(promoted, 1, "only the non-colliding legacy row is promoted");

        // The colliding legacy row is left at uid=0 for the human to resolve.
        assert_eq!(count_rows(&db, 0).await, 1);
        assert_eq!(count_rows(&db, 1).await, 2);
    }

    #[tokio::test]
    async fn migration_promotes_only_one_duplicate_uid0_row_per_key() {
        let db = fresh_legacy_cred_db_without_unique().await;
        insert_row(&db, 0, "myservice", "admin").await;
        insert_row(&db, 0, "myservice", "admin").await;
        insert_row(&db, 0, "grafana", "admin").await;

        let promoted = migrate_legacy_user_id_zero_rows(&db).await.unwrap();
        assert_eq!(
            promoted, 2,
            "one canonical row per legacy key should be promoted"
        );

        assert_eq!(
            count_rows(&db, 1).await,
            2,
            "myservice/admin and grafana/admin should be visible"
        );
        assert_eq!(
            count_rows(&db, 0).await,
            1,
            "the extra duplicate stays parked at uid=0"
        );
    }

    #[tokio::test]
    async fn migration_on_missing_table_errors_but_does_not_panic() {
        // Database::connect_memory() runs the full Kleos migration chain,
        // which already creates `cred_secrets`. Drop it explicitly so we
        // exercise the missing-table branch that main()'s error swallow
        // guards against (e.g. a legacy install whose Kleos migrations
        // did not yet add this table).
        let db = Database::connect_memory().await.unwrap();
        db.write(|conn| {
            conn.execute("DROP TABLE IF EXISTS cred_secrets", [])?;
            Ok(())
        })
        .await
        .unwrap();
        let result = migrate_legacy_user_id_zero_rows(&db).await;
        assert!(
            result.is_err(),
            "missing table should yield Err so main() can swallow it"
        );
    }

    #[test]
    fn cred_user_id_constant_is_one() {
        // Pin the chosen canonical id so future refactors don't silently
        // drift back to 0.
        assert_eq!(CRED_USER_ID, 1);
    }

    /// Insert a raw cred_agent_keys row at an explicit user_id (test-only).
    async fn insert_agent_key(db: &Database, user_id: i64, name: &str, key_hash: &str) {
        let name = name.to_string();
        let key_hash = key_hash.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO cred_agent_keys (user_id, key_hash, name, permissions, created_at)
                 VALUES (?1, ?2, ?3, '{}', '2026-01-01 00:00:00')",
                rusqlite::params![user_id, key_hash, name],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn count_agent_keys(db: &Database, user_id: i64) -> i64 {
        db.read(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM cred_agent_keys WHERE user_id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )?)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn migration_promotes_legacy_agent_keys() {
        // connect_memory runs the full Kleos migration chain, which creates
        // cred_agent_keys, so we can insert directly.
        let db = fresh_cred_db().await;
        // Two legacy uid=0 keys (the CRED-1 orphaned namespace) ...
        insert_agent_key(&db, 0, "ci-runner", "hash-a").await;
        insert_agent_key(&db, 0, "deployer", "hash-b").await;
        // ... one already-correct uid=1 key that must be left untouched.
        insert_agent_key(&db, 1, "existing", "hash-c").await;

        let promoted = migrate_legacy_user_id_zero_rows(&db).await.unwrap();
        assert_eq!(promoted, 2, "both legacy agent keys should be promoted");
        assert_eq!(count_agent_keys(&db, 0).await, 0, "no uid=0 keys remain");
        assert_eq!(count_agent_keys(&db, 1).await, 3, "all keys now at uid=1");
    }

    #[tokio::test]
    async fn migration_skips_colliding_agent_keys() {
        let db = fresh_cred_db().await;
        // A uid=1 key whose name collides with a legacy uid=0 key (UNIQUE(user_id, name)).
        insert_agent_key(&db, 1, "ci-runner", "hash-live").await;
        insert_agent_key(&db, 0, "ci-runner", "hash-legacy").await;
        // A non-colliding legacy key promotes cleanly.
        insert_agent_key(&db, 0, "deployer", "hash-b").await;

        let promoted = migrate_legacy_user_id_zero_rows(&db).await.unwrap();
        assert_eq!(promoted, 1, "only the non-colliding legacy key is promoted");
        assert_eq!(
            count_agent_keys(&db, 0).await,
            1,
            "the colliding legacy key stays parked at uid=0"
        );
        assert_eq!(count_agent_keys(&db, 1).await, 2);
    }
}

#[cfg(test)]
mod get_session_guard_tests {
    use super::*;

    #[test]
    fn agent_context_is_always_denied() {
        let err = enforce_get_access_policy(GetAccessContext::Agent, true).unwrap_err();
        assert!(err.to_string().contains("disabled in agent contexts"));
    }

    #[test]
    fn managed_session_requires_grant() {
        let err = enforce_get_access_policy(GetAccessContext::ManagedSession, false).unwrap_err();
        assert!(err.to_string().contains("requires a valid session grant"));
        assert!(enforce_get_access_policy(GetAccessContext::ManagedSession, true).is_ok());
    }

    #[test]
    fn non_interactive_stdout_requires_managed_session() {
        // Agent env hard-blocks regardless of TTY.
        assert_eq!(
            classify_get_access_context(true, false, true),
            GetAccessContext::Agent
        );
        // No agent env: a real interactive terminal prints freely.
        assert_eq!(
            classify_get_access_context(false, false, true),
            GetAccessContext::Interactive
        );
        // Captured (non-TTY) stdout -- an agent or script reading the output --
        // requires a session grant. This is the fail-closed gate that stops
        // plaintext leaking to a process that did not set an agent env var.
        assert_eq!(
            classify_get_access_context(false, false, false),
            GetAccessContext::ManagedSession
        );
        // A managed-session env signal requires a grant even at a TTY.
        assert_eq!(
            classify_get_access_context(false, true, true),
            GetAccessContext::ManagedSession
        );
    }

    #[test]
    fn session_grant_roundtrip_and_revocation() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("get-session-grants.json");

        let token = mint_get_session_grant(&path, 60).unwrap();
        assert!(has_valid_get_session_grant(&path, &token).unwrap());

        let revoked = revoke_get_session_grant(&path, &token).unwrap();
        assert!(revoked);
        assert!(!has_valid_get_session_grant(&path, &token).unwrap());
    }

    #[test]
    fn expired_grants_are_pruned() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("get-session-grants.json");
        let token = "deadbeef";
        let store = GetSessionGrantStore {
            grants: vec![GetSessionGrant {
                token_hash: hash_get_session_token(token),
                issued_at: 1,
                expires_at: 2,
            }],
        };
        save_get_session_grants(&path, &store).unwrap();

        assert!(!has_valid_get_session_grant(&path, token).unwrap());

        let reloaded = load_get_session_grants(&path).unwrap();
        assert!(reloaded.grants.is_empty());
    }
}
