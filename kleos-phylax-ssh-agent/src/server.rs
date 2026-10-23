// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! SSH agent server -- binds a Unix socket or Windows named pipe and
//! accepts SSH agent protocol connections.

use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::handler::handle_connection;
use crate::provider::KeyProvider;

/// Upper bound on concurrent connection handlers. Each handler can buffer up to
/// a 10 MiB message, so without a cap a misbehaving (same-user) client could
/// drive memory exhaustion by opening many connections. The socket is
/// owner-only (0600), so this is defense in depth against a local foot-gun.
const MAX_CONCURRENT_CONNS: usize = 64;

/// The SSH agent server.
///
/// Binds to a Unix socket (Linux/macOS) or Windows named pipe and serves
/// the SSH agent protocol. Each connection is handled in a separate task.
pub struct AgentServer<P: KeyProvider + 'static> {
    /// Path to the socket or pipe.
    path: String,
    /// The key provider shared across all connections.
    provider: Arc<P>,
}

impl<P: KeyProvider + 'static> AgentServer<P> {
    /// Creates a new agent server.
    pub fn new(path: String, provider: Arc<P>) -> Self {
        Self { path, provider }
    }

    /// Returns the socket/pipe path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Runs the agent server until the cancellation token is triggered.
    ///
    /// On Unix, binds a Unix socket at `self.path` with 0600 permissions.
    /// Spawns a task per connection.
    #[cfg(unix)]
    pub async fn run(&self, cancel: CancellationToken) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::UnixListener;

        // Remove stale socket if present.
        if std::path::Path::new(&self.path).exists() {
            // Try connecting to see if it's active.
            match tokio::net::UnixStream::connect(&self.path).await {
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!("socket {} is already in use by another process", self.path),
                    ));
                }
                Err(_) => {
                    // Stale socket -- remove it.
                    std::fs::remove_file(&self.path)?;
                }
            }
        }

        // Bind under a restrictive umask so the socket is never observable
        // with wider permissions: the previous bind-then-chmod sequence left
        // a window where another local user could connect to a key-holding
        // agent socket created with the process default umask.
        //
        // SAFETY: umask(2) only swaps the process file-mode creation mask and
        // cannot fail; the original mask is restored immediately after bind.
        let listener = {
            let old_mask = unsafe { libc::umask(0o177) };
            let bound = UnixListener::bind(&self.path);
            unsafe { libc::umask(old_mask) };
            bound?
        };

        // Belt-and-suspenders: normalize to 0600 (owner-only) in case the
        // platform ignored the mask for socket inodes.
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;

        log::info!("SSH agent listening on {}", self.path);

        let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    log::info!("SSH agent shutting down");
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            // Bound concurrent handlers; drop the connection when
                            // at the limit rather than spawning unboundedly.
                            match Arc::clone(&conn_limit).try_acquire_owned() {
                                Ok(permit) => {
                                    let provider = Arc::clone(&self.provider);
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        handle_connection(stream, provider.as_ref()).await;
                                    });
                                }
                                Err(_) => {
                                    log::warn!(
                                        "SSH agent at connection limit ({MAX_CONCURRENT_CONNS}); dropping connection"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("SSH agent accept error: {e}");
                        }
                    }
                }
            }
        }

        // Clean up socket file.
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }

    /// Runs the agent server on Windows using a named pipe.
    #[cfg(windows)]
    pub async fn run(&self, cancel: CancellationToken) -> std::io::Result<()> {
        use tokio::net::windows::named_pipe::ServerOptions;

        log::info!("SSH agent listening on {}", self.path);

        let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));

        loop {
            // Create a new pipe instance for each connection.
            let pipe = ServerOptions::new()
                .first_pipe_instance(false)
                .create(&self.path)?;

            tokio::select! {
                _ = cancel.cancelled() => {
                    log::info!("SSH agent shutting down");
                    break;
                }
                connect_result = pipe.connect() => {
                    match connect_result {
                        Ok(()) => {
                            // Bound concurrent handlers; drop the connection when
                            // at the limit rather than spawning unboundedly.
                            match Arc::clone(&conn_limit).try_acquire_owned() {
                                Ok(permit) => {
                                    let provider = Arc::clone(&self.provider);
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        handle_connection(pipe, provider.as_ref()).await;
                                    });
                                }
                                Err(_) => {
                                    log::warn!(
                                        "SSH agent at connection limit ({MAX_CONCURRENT_CONNS}); dropping connection"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("SSH agent pipe connect error: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
