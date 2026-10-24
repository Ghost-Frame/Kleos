//! Phylax credential authority daemon.
//!
//! Composes credd's base router with Phylax agent-native extensions.
//! If no policies are configured, it behaves identically to plain credd.

use clap::Parser;
use kleos_credd::profile::RunProfile;
use kleos_credd::server;
use kleos_phylax::router::compose_router;
use tracing::info;

/// Phylax daemon CLI arguments.
#[derive(Parser)]
#[command(name = "phylaxd", about = "Phylax agent-native credential authority")]
struct Args {
    /// Address to bind to.
    #[arg(
        long,
        visible_alias = "bind",
        default_value = "127.0.0.1:3100",
        env = "CREDD_BIND"
    )]
    listen: String,

    /// Path to the credential database.
    #[arg(long, default_value = "kleos.db", env = "CREDD_DB_PATH")]
    db_path: String,

    /// How phylaxd derives its master key. `yubikey` (default) does an
    /// HMAC-SHA1 challenge against slot 2 and Argon2id-derives a 32-byte
    /// key, requiring no on-disk secrets. `password` reads from
    /// --master-password or stdin and derives the same way. `keyfile` reads a
    /// pre-derived 32-byte hex key from a file.
    #[arg(long, default_value = "yubikey", env = "CREDD_AUTH_MODE")]
    auth_mode: String,

    /// Path to a hex-encoded 32-byte master key file.
    /// Used only when --auth-mode=keyfile.
    #[arg(long, env = "CREDD_KEYFILE")]
    keyfile: Option<std::path::PathBuf>,

    /// Master password used when --auth-mode=password.
    #[arg(long, env = "CREDD_MASTER_PASSWORD")]
    master_password: Option<String>,
}

/// Entry point for the phylaxd daemon.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    kleos_lib::config::migrate_env_prefix();

    let _otel_guard = kleos_lib::observability::init_tracing(
        "kleos-phylaxd",
        "kleos_phylax=info,kleos_credd=info",
    );

    let args = Args::parse();

    // PHYLAX_CUSTODY=1 (exactly) selects the custody profile; any other value
    // warns and runs the legacy profile.
    let profile = RunProfile::from_env();

    info!(
        listen = %args.listen,
        db_path = %args.db_path,
        profile = ?profile,
        "starting phylaxd"
    );

    server::run_with_env(
        &args.listen,
        &args.db_path,
        args.auth_mode.as_str(),
        args.master_password,
        args.keyfile,
        profile,
        compose_router,
    )
    .await
}
