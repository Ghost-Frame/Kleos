//! Engram credential management daemon.
//!
//! HTTP server providing secure credential storage and retrieval
//! with two-tier authentication (master key vs agent keys).

use clap::Parser;
use kleos_credd::server;
use tracing::info;

#[derive(Parser)]
#[command(name = "kleos-credd")]
#[command(about = "Kleos credential management daemon")]
// CLI arguments for starting credd with credential and database inputs.
struct Args {
    /// Listen address
    #[arg(long, default_value = "127.0.0.1:4400", env = "CREDD_LISTEN")]
    listen: String,

    /// Database path
    #[arg(long, default_value = "kleos.db", env = "CREDD_DB_PATH")]
    db_path: String,

    /// Master password (only consulted when --auth-mode=password).
    #[arg(long, env = "CREDD_MASTER_PASSWORD")]
    master_password: Option<String>,

    /// How credd derives its master key. `yubikey` (default) does an HMAC-SHA1
    /// challenge against slot 2 and Argon2id-derives a 32-byte key, requiring
    /// no on-disk secrets. `password` reads --master-password / stdin and
    /// derives via the same Argon2id KDF. `keyfile` reads a pre-derived
    /// 32-byte hex key from a file -- for unattended servers.
    #[arg(long, default_value = "yubikey", env = "CREDD_AUTH_MODE")]
    auth_mode: String,

    /// Path to keyfile containing hex-encoded 32-byte master key
    /// (only used when --auth-mode=keyfile).
    #[arg(long, env = "CREDD_KEYFILE")]
    keyfile: Option<std::path::PathBuf>,
}

#[tokio::main]
// Start credd after resolving tracing, CLI arguments, and runtime secrets.
async fn main() -> anyhow::Result<()> {
    kleos_lib::config::migrate_env_prefix();

    let _otel_guard =
        kleos_lib::observability::init_tracing("engram-credd", "kleos_credd=info,tower_http=debug");

    let args = Args::parse();

    info!("starting credd on {}", args.listen);

    server::run_with_env(
        &args.listen,
        &args.db_path,
        args.auth_mode.as_str(),
        args.master_password,
        args.keyfile,
        kleos_credd::profile::RunProfile::Legacy,
        kleos_credd::build_router,
    )
    .await?;

    Ok(())
}
