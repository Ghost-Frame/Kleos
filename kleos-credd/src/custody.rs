//! Custody profile startup preflight.
//!
//! Each check returns a distinct [`CustodyStartupError`] variant so a refusal
//! is machine-distinguishable and nothing here panics. The uid is injected
//! through [`CustodyContext`] so tests can simulate the forbidden uid without
//! running as it.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

/// The interactive-user uid the custody daemon must never run as.
pub const FORBIDDEN_UID: u32 = 1000;

/// First three octets of the only network the custody TCP listener may bind in
/// (`10.50.0.0/24`).
pub const MESH_PREFIX: [u8; 3] = [10, 50, 0];

/// Required permission bits of the vault database file.
pub const VAULT_MODE: u32 = 0o600;

/// Unix socket mode enforced under the custody profile, regardless of env.
pub const SOCKET_MODE: u32 = 0o600;

/// Why a custody startup check refused to proceed.
#[derive(Debug, Error)]
pub enum CustodyStartupError {
    /// The process runs as the forbidden interactive uid.
    #[error("custody profile refuses to run as uid {uid}")]
    ForbiddenUid {
        /// The offending real or effective uid.
        uid: u32,
    },
    /// The vault database file is owned by a different uid than the daemon.
    #[error("vault database {} is owned by uid {owner}, expected effective uid {euid}", .path.display())]
    VaultWrongOwner {
        /// Vault database path.
        path: PathBuf,
        /// Actual owner uid of the file.
        owner: u32,
        /// The daemon's effective uid.
        euid: u32,
    },
    /// The vault database file mode is not exactly 0600.
    #[error("vault database {} has mode {mode:04o}, expected 0600", .path.display())]
    VaultWrongMode {
        /// Vault database path.
        path: PathBuf,
        /// Actual permission bits (including setuid/setgid/sticky).
        mode: u32,
    },
    /// The vault database path exists but is not a regular file.
    #[error("vault database path {} is not a regular file", .path.display())]
    VaultNotRegularFile {
        /// Vault database path.
        path: PathBuf,
    },
    /// The vault database file could not be inspected or created.
    #[error("cannot prepare vault database {}: {source}", .path.display())]
    VaultIo {
        /// Vault database path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The TCP bind string is not a literal IPv4 `ip:port` (e.g. a hostname).
    #[error("TCP bind address {bind:?} is not a literal IPv4 socket address")]
    BindNotLiteralIpv4 {
        /// The rejected bind string.
        bind: String,
    },
    /// The TCP bind address is a literal IPv4 outside 10.50.0.0/24.
    #[error("TCP bind address {addr} is outside 10.50.0.0/24")]
    BindOutsideMesh {
        /// The rejected address.
        addr: Ipv4Addr,
    },
}

/// Process identity the preflight evaluates (injectable for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyContext {
    /// Real uid of the process.
    pub real_uid: u32,
    /// Effective uid of the process.
    pub effective_uid: u32,
}

/// Construction of the process identity.
impl CustodyContext {
    /// Read the real and effective uid of the running process.
    pub fn current() -> Self {
        Self {
            real_uid: nix::unistd::getuid().as_raw(),
            effective_uid: nix::unistd::geteuid().as_raw(),
        }
    }
}

/// Refuse to run when either the real or effective uid is [`FORBIDDEN_UID`].
pub fn check_uid(ctx: &CustodyContext) -> Result<(), CustodyStartupError> {
    for uid in [ctx.real_uid, ctx.effective_uid] {
        if uid == FORBIDDEN_UID {
            return Err(CustodyStartupError::ForbiddenUid { uid });
        }
    }
    Ok(())
}

/// Require a literal IPv4 `ip:port` inside 10.50.0.0/24; hostnames, IPv6, and
/// every other network are rejected. Returns the parsed address.
pub fn check_bind_address(bind: &str) -> Result<SocketAddr, CustodyStartupError> {
    let not_literal = || CustodyStartupError::BindNotLiteralIpv4 {
        bind: bind.to_string(),
    };
    let addr = bind.parse::<SocketAddr>().map_err(|_| not_literal())?;
    let SocketAddr::V4(v4) = addr else {
        return Err(not_literal());
    };
    let octets = v4.ip().octets();
    if octets[..3] != MESH_PREFIX {
        return Err(CustodyStartupError::BindOutsideMesh { addr: *v4.ip() });
    }
    Ok(addr)
}

/// Wrap an I/O error with the vault path.
fn vault_io(path: &Path, source: std::io::Error) -> CustodyStartupError {
    CustodyStartupError::VaultIo {
        path: path.to_path_buf(),
        source,
    }
}

/// Ensure the vault database file exists with the right owner and mode.
///
/// A missing file is created with `O_EXCL` and mode 0600 before it is
/// inspected. A symlink, directory, or other non-regular file is refused; the
/// owner must equal `euid` and the mode must be exactly 0600.
pub fn ensure_vault_file(path: &Path, euid: u32) -> Result<(), CustodyStartupError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(VAULT_MODE)
                .open(path)
                .map_err(|e| vault_io(path, e))?
                .set_permissions(std::fs::Permissions::from_mode(VAULT_MODE))
                .map_err(|e| vault_io(path, e))?;
            std::fs::symlink_metadata(path).map_err(|e| vault_io(path, e))?
        }
        Err(e) => return Err(vault_io(path, e)),
    };

    if !metadata.file_type().is_file() {
        return Err(CustodyStartupError::VaultNotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != euid {
        return Err(CustodyStartupError::VaultWrongOwner {
            path: path.to_path_buf(),
            owner: metadata.uid(),
            euid,
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode != VAULT_MODE {
        return Err(CustodyStartupError::VaultWrongMode {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Run every custody startup check in order: uid, TCP bind, vault file.
///
/// `tcp_bind` is the TCP listen string the daemon will actually use, or `None`
/// when only the Unix socket is served.
pub fn preflight(
    ctx: &CustodyContext,
    db_path: &Path,
    tcp_bind: Option<&str>,
) -> Result<(), CustodyStartupError> {
    check_uid(ctx)?;
    if let Some(bind) = tcp_bind {
        check_bind_address(bind)?;
    }
    ensure_vault_file(db_path, ctx.effective_uid)
}

/// Unit tests for the individual custody checks.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a context with the given uids.
    fn ctx(real_uid: u32, effective_uid: u32) -> CustodyContext {
        CustodyContext {
            real_uid,
            effective_uid,
        }
    }

    /// Either uid being 1000 is refused with the dedicated variant.
    #[test]
    fn uid_1000_is_refused() {
        assert!(matches!(
            check_uid(&ctx(1000, 5000)),
            Err(CustodyStartupError::ForbiddenUid { uid: 1000 })
        ));
        assert!(matches!(
            check_uid(&ctx(5000, 1000)),
            Err(CustodyStartupError::ForbiddenUid { uid: 1000 })
        ));
        assert!(check_uid(&ctx(5000, 5000)).is_ok());
    }

    /// Only literal IPv4 addresses inside 10.50.0.0/24 pass.
    #[test]
    fn bind_address_rules() {
        assert!(check_bind_address("10.50.0.1:3100").is_ok());
        assert!(check_bind_address("10.50.0.254:80").is_ok());
        for bad in [
            "localhost:3100",
            "phylax.internal:3100",
            "[::1]:3100",
            "10.50.0.1",
        ] {
            assert!(
                matches!(
                    check_bind_address(bad),
                    Err(CustodyStartupError::BindNotLiteralIpv4 { .. })
                ),
                "{bad}"
            );
        }
        for bad in [
            "127.0.0.1:3100",
            "0.0.0.0:3100",
            "10.50.1.1:3100",
            "10.51.0.1:3100",
        ] {
            assert!(
                matches!(
                    check_bind_address(bad),
                    Err(CustodyStartupError::BindOutsideMesh { .. })
                ),
                "{bad}"
            );
        }
    }

    /// A missing vault file is created 0600 and then passes.
    #[test]
    fn missing_vault_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let euid = nix::unistd::geteuid().as_raw();
        ensure_vault_file(&path, euid).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        ensure_vault_file(&path, euid).unwrap();
    }

    /// A vault with a wider mode is refused with the mode variant.
    #[test]
    fn wrong_mode_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let euid = nix::unistd::geteuid().as_raw();
        assert!(matches!(
            ensure_vault_file(&path, euid),
            Err(CustodyStartupError::VaultWrongMode { mode: 0o640, .. })
        ));
    }

    /// A vault owned by someone other than the expected euid is refused.
    #[test]
    fn wrong_owner_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let other = nix::unistd::geteuid().as_raw().wrapping_add(1);
        assert!(matches!(
            ensure_vault_file(&path, other),
            Err(CustodyStartupError::VaultWrongOwner { .. })
        ));
    }

    /// A symlink at the vault path is refused as not a regular file.
    #[test]
    fn symlink_vault_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.db");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("vault.db");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let euid = nix::unistd::geteuid().as_raw();
        assert!(matches!(
            ensure_vault_file(&link, euid),
            Err(CustodyStartupError::VaultNotRegularFile { .. })
        ));
    }

    /// A missing parent directory surfaces as the I/O variant, not a panic.
    #[test]
    fn missing_parent_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("vault.db");
        let euid = nix::unistd::geteuid().as_raw();
        assert!(matches!(
            ensure_vault_file(&path, euid),
            Err(CustodyStartupError::VaultIo { .. })
        ));
    }
}
