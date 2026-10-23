//! Listener selection: Unix socket, TCP, or both.
//!
//! Driven by env vars at startup so the same binary serves Linux agents
//! over an owner-only or explicitly group-shared Unix socket while still
//! answering Windows clients over loopback TCP.
//!
//! - `CREDD_SOCKET`: Unix domain socket path (Linux/macOS).
//! - `CREDD_SOCKET_GROUP`: optional group allowed to connect.
//! - `CREDD_SOCKET_MODE`: optional octal mode; defaults to 0600 without a
//!   group and 0660 with one. World permissions are rejected.
//! - `CREDD_BIND`: TCP listen address (e.g. `127.0.0.1:4400`).
//! - Neither: defaults to TCP `127.0.0.1:4400` for backwards compatibility.
//! - Both: serves on each concurrently via `tokio::try_join!`.

use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;
#[cfg(unix)]
use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    serve::IncomingStream,
};
use tracing::{info, warn};

#[cfg(unix)]
use crate::auth::IsUnixSocket;

/// Validated ownership and mode for a Unix listener socket.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct UnixSocketAccess {
    /// Final socket mode, restricted to owner and optional group bits.
    mode: u32,
    /// Optional group receiving socket ownership.
    gid: Option<nix::unistd::Gid>,
}

/// Restores the process umask after the synchronous socket bind.
#[cfg(unix)]
struct UmaskGuard(nix::sys::stat::Mode);

#[cfg(unix)]
/// Restores the prior process umask when the guard leaves scope.
impl Drop for UmaskGuard {
    /// Restore the umask that was active before socket creation.
    fn drop(&mut self) {
        nix::sys::stat::umask(self.0);
    }
}

/// Per-connection info captured from the Unix socket via SO_PEERCRED.
///
/// Implements `axum::extract::connect_info::Connected` so that axum's
/// `into_make_service_with_connect_info` plumbing injects it as a request
/// extension before any middleware runs.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct UdsConnectInfo {
    /// Kernel-verified peer identity; `None` if `peer_cred()` fails.
    peer: Option<crate::peercred::PeerIdentity>,
}

#[cfg(unix)]
/// Captures kernel peer credentials for each accepted Unix connection.
impl axum::extract::connect_info::Connected<IncomingStream<'_, tokio::net::UnixListener>>
    for UdsConnectInfo
{
    /// Called once per accepted connection with a reference to the raw stream.
    /// Reads SO_PEERCRED from the kernel and maps it to `PeerIdentity`.
    fn connect_info(stream: IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        let peer = stream
            .io()
            .peer_cred()
            .ok()
            .map(|ucred| crate::peercred::PeerIdentity {
                uid: ucred.uid(),
                pid: ucred.pid().unwrap_or(0),
            });
        Self { peer }
    }
}

/// Bind both Unix and TCP listeners as configured. Blocks until one returns.
pub async fn serve(app: Router) -> anyhow::Result<()> {
    let sock = std::env::var("CREDD_SOCKET").ok();
    let bind = std::env::var("CREDD_BIND").ok();

    match (sock, bind) {
        (Some(sock), None) => listen_unix(&sock, app).await,
        (None, Some(bind)) => listen_tcp(&bind, app).await,
        (Some(sock), Some(bind)) => {
            let app_unix = app.clone();
            let app_tcp = app;
            tokio::try_join!(listen_unix(&sock, app_unix), listen_tcp(&bind, app_tcp))?;
            Ok(())
        }
        (None, None) => listen_tcp("127.0.0.1:4400", app).await,
    }
}

/// Bind a Unix domain socket at `path` with validated ownership and serve `app`.
///
/// A stale socket owned by this daemon is removed first. Any other file type
/// or owner fails closed. Every request still requires normal bearer auth;
/// socket group membership grants transport access only.
///
/// Per-connection SO_PEERCRED is captured via `UdsConnectInfo` and injected
/// as a `crate::peercred::PeerIdentity` extension for handlers that need it.
///
/// Exposed as `pub` so that integration tests can drive the full listener
/// stack (including SO_PEERCRED injection) end-to-end.
#[cfg(unix)]
pub async fn listen_unix_test_only(path: &str, app: Router) -> anyhow::Result<()> {
    listen_unix(path, app).await
}

/// Bind the Unix socket at `path` with the access mode and group in `access`.
///
/// The socket is restricted at creation time via a temporary umask, then
/// chowned and chmodded explicitly. The umask guard lives only inside this
/// function, so the prior process umask is restored on return, before the
/// caller starts serving. No await occurs while the umask is changed.
#[cfg(unix)]
fn bind_unix_socket(
    path: &str,
    access: UnixSocketAccess,
) -> anyhow::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    let creation_mask = nix::sys::stat::Mode::from_bits_truncate(0o777 & !access.mode);
    let prior_umask = nix::sys::stat::umask(creation_mask);
    let _umask_guard = UmaskGuard(prior_umask);

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("failed to bind Unix socket at {}", path))?;

    if let Some(gid) = access.gid {
        nix::unistd::chown(path, None, Some(gid))
            .with_context(|| format!("failed to set Unix socket group on {}", path))?;
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(access.mode))
        .with_context(|| format!("failed to chmod {:04o} {}", access.mode, path))?;

    Ok(listener)
}

#[cfg(unix)]
/// Bind, secure, and serve the configured Unix socket.
async fn listen_unix(path: &str, app: Router) -> anyhow::Result<()> {
    let access = unix_socket_access_from_env()?;
    remove_owned_stale_socket(std::path::Path::new(path))?;

    // The process-global umask is held only inside `bind_unix_socket` and is
    // restored before the server starts serving.
    let listener = bind_unix_socket(path, access)?;

    info!(
        mode = format_args!("{:04o}", access.mode),
        "credd listening on unix:{}", path
    );

    // Inject ConnectInfo<SocketAddr> (axum extractors require it),
    // IsUnixSocket(true) so the rate limiter knows to skip, and
    // PeerIdentity sourced from the per-connection UdsConnectInfo.
    let fake_addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("hardcoded loopback addr is valid");

    let unix_app = app.layer(axum::middleware::from_fn(
        move |mut req: Request, next: Next| async move {
            // Extract the peer identity injected by UdsConnectInfo at connection
            // time and forward it as a plain PeerIdentity extension so handlers
            // can extract it without knowing about the connect-info wrapper.
            if let Some(uds_info) = req.extensions().get::<ConnectInfo<UdsConnectInfo>>() {
                if let Some(peer) = uds_info.0.peer {
                    req.extensions_mut().insert(peer);
                }
            }
            // Preserve the existing fake ConnectInfo<SocketAddr> and IsUnixSocket
            // extensions that other middleware (rate limiter, auth) depend on.
            req.extensions_mut().insert(ConnectInfo(fake_addr));
            req.extensions_mut().insert(IsUnixSocket(true));
            next.run(req).await
        },
    ));

    axum::serve(
        listener,
        unix_app.into_make_service_with_connect_info::<UdsConnectInfo>(),
    )
    .await
    .context("Unix socket server error")
}

/// Resolve and validate Unix socket access settings from the environment.
#[cfg(unix)]
fn unix_socket_access_from_env() -> anyhow::Result<UnixSocketAccess> {
    let group_name = std::env::var("CREDD_SOCKET_GROUP")
        .ok()
        .filter(|name| !name.is_empty());
    let mode = match std::env::var("CREDD_SOCKET_MODE") {
        Ok(raw) => parse_socket_mode(&raw)?,
        Err(_) if group_name.is_some() => 0o660,
        Err(_) => 0o600,
    };

    if mode & 0o007 != 0 {
        anyhow::bail!("CREDD_SOCKET_MODE must not grant permissions to other users");
    }
    if mode & 0o600 != 0o600 {
        anyhow::bail!("CREDD_SOCKET_MODE must grant owner read and write access");
    }
    if mode & 0o060 != 0 && group_name.is_none() {
        anyhow::bail!("CREDD_SOCKET_MODE grants group access but CREDD_SOCKET_GROUP is unset");
    }

    let gid = match group_name {
        Some(name) => {
            let group = nix::unistd::Group::from_name(&name)
                .with_context(|| format!("failed to resolve CREDD_SOCKET_GROUP {name:?}"))?
                .ok_or_else(|| anyhow::anyhow!("CREDD_SOCKET_GROUP {name:?} does not exist"))?;
            Some(group.gid)
        }
        None => None,
    };

    Ok(UnixSocketAccess { mode, gid })
}

/// Parse a four- or three-digit octal Unix socket mode.
#[cfg(unix)]
fn parse_socket_mode(raw: &str) -> anyhow::Result<u32> {
    let trimmed = raw.trim();
    if trimmed.len() < 3 || trimmed.len() > 4 || !trimmed.bytes().all(|b| matches!(b, b'0'..=b'7'))
    {
        anyhow::bail!("CREDD_SOCKET_MODE must be a three- or four-digit octal mode");
    }
    u32::from_str_radix(trimmed, 8).context("invalid CREDD_SOCKET_MODE")
}

/// Remove only an owned stale Unix socket, rejecting every other target.
#[cfg(unix)]
fn remove_owned_stale_socket(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_socket() {
        anyhow::bail!("refusing to replace non-socket path {}", path.display());
    }
    let daemon_uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != daemon_uid {
        anyhow::bail!(
            "refusing to replace socket {} owned by uid {}",
            path.display(),
            metadata.uid()
        );
    }
    std::fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))
}

#[cfg(not(unix))]
/// Reject Unix socket configuration on platforms without Unix sockets.
async fn listen_unix(path: &str, _app: Router) -> anyhow::Result<()> {
    anyhow::bail!(
        "CREDD_SOCKET set to {} but Unix sockets are not supported on this platform",
        path
    )
}

/// Bind a TCP socket at `addr` and serve `app`.
async fn listen_tcp(bind_str: &str, app: Router) -> anyhow::Result<()> {
    let addr: SocketAddr = bind_str
        .parse()
        .with_context(|| format!("invalid CREDD_BIND address: {}", bind_str))?;

    if !addr.ip().is_loopback() {
        warn!(
            "credd is binding to non-loopback address {}. \
             Ensure network access is restricted (firewall, VPN, etc.).",
            addr
        );
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind TCP on {}", addr))?;

    info!("credd listening on tcp:{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("TCP server error")
}

#[cfg(all(test, unix))]
/// Unix socket mode and stale-path safety tests.
mod tests {
    use super::*;

    /// Three- and four-digit octal modes parse to the intended permission bits.
    #[test]
    fn socket_mode_parser_accepts_octal_permissions() {
        assert_eq!(parse_socket_mode("600").unwrap(), 0o600);
        assert_eq!(parse_socket_mode("0660").unwrap(), 0o660);
    }

    /// Decimal-looking or malformed modes must not be interpreted permissively.
    #[test]
    fn socket_mode_parser_rejects_invalid_values() {
        assert!(parse_socket_mode("660x").is_err());
        assert!(parse_socket_mode("88").is_err());
        assert!(parse_socket_mode("00660").is_err());
    }

    /// Startup must preserve a regular file found at the configured socket path.
    #[test]
    fn stale_socket_cleanup_rejects_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred.sock");
        std::fs::write(&path, b"protected").unwrap();

        assert!(remove_owned_stale_socket(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"protected");
    }

    /// Environment marker telling the umask test it runs as the isolated child.
    #[cfg(unix)]
    const UMASK_CHILD_ENV: &str = "CREDD_UMASK_TEST_CHILD";

    /// Binding the socket must restore the process umask and apply the mode.
    ///
    /// The umask is process-global and would race with sibling tests creating
    /// files, so the real check re-executes this test binary as a child that
    /// runs only this test.
    #[cfg(unix)]
    #[test]
    fn bind_unix_socket_restores_umask_and_sets_mode() {
        if std::env::var_os(UMASK_CHILD_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "listener::tests::bind_unix_socket_restores_umask_and_sets_mode",
                    "--test-threads=1",
                ])
                .env(UMASK_CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success(), "isolated umask test failed");
            return;
        }

        use std::os::unix::fs::PermissionsExt;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _enter = runtime.enter();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred.sock");
        let path_str = path.to_str().unwrap();
        let access = UnixSocketAccess {
            mode: 0o600,
            gid: None,
        };

        let before = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        nix::sys::stat::umask(before);

        let _listener = bind_unix_socket(path_str, access).unwrap();

        let after = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        nix::sys::stat::umask(after);

        assert_eq!(before, after);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, access.mode);
    }
}
