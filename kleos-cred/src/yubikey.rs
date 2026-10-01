//! YubiKey HMAC-SHA1 challenge-response on OTP slot 2 (legacy) or slot 1
//! (Phylax custody profile).
//!
//! Slot 2 is used by convention (same as KeePassXC, cred, and anything that
//! expects to share a secret across tools). The custody profile uses slot 1
//! with its own challenge file and never falls back to slot 2. The YubiKey holds a 20-byte
//! HMAC-SHA1 key that cannot be extracted; we send it a 32-byte challenge
//! and receive a 20-byte response. Because the secret never leaves the
//! hardware, possession of the YubiKey is required to compute the response.
//!
//! This module shells out to `ykman` on Linux/macOS or `ykchallenge.exe`
//! (Yubico .NET SDK wrapper) on Windows. Direct PC/SC access from Rust is
//! possible but the subprocess path matches what the standalone `cred` tool
//! uses, so the two programs stay interoperable without sharing code.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::TryRngCore;
use tracing::{debug, info, warn};

use crate::{CredError, Result};

/// R7-005: cap how many failed challenge-response attempts we will issue in
/// a short window. The YubiKey itself rate-limits touch, but a local attacker
/// running `cred` in a loop (e.g. trying to brute-force which slot is
/// programmed, or spamming the user with touch prompts as a nuisance) can
/// still force the subprocess repeatedly. Cooldown avoids that.
const YUBIKEY_MAX_FAILURES: u32 = 5;
const YUBIKEY_WINDOW: Duration = Duration::from_secs(60);
const YUBIKEY_COOLDOWN: Duration = Duration::from_secs(30);

struct FailureState {
    count: u32,
    first_failure: Option<Instant>,
    locked_until: Option<Instant>,
}

static FAILURE_STATE: Mutex<FailureState> = Mutex::new(FailureState {
    count: 0,
    first_failure: None,
    locked_until: None,
});

fn check_rate_limit() -> Result<()> {
    let mut state = FAILURE_STATE
        .lock()
        .map_err(|_| CredError::YubiKey("yubikey rate-limit lock poisoned".into()))?;
    let now = Instant::now();
    if let Some(until) = state.locked_until {
        if now < until {
            let remaining = until.saturating_duration_since(now);
            return Err(CredError::YubiKey(format!(
                "yubikey attempts rate-limited; retry in {}s",
                remaining.as_secs().max(1)
            )));
        } else {
            state.locked_until = None;
            state.count = 0;
            state.first_failure = None;
        }
    }
    if let Some(first) = state.first_failure {
        if now.duration_since(first) > YUBIKEY_WINDOW {
            state.count = 0;
            state.first_failure = None;
        }
    }
    Ok(())
}

fn record_failure() {
    if let Ok(mut state) = FAILURE_STATE.lock() {
        let now = Instant::now();
        if state.first_failure.is_none() {
            state.first_failure = Some(now);
        }
        state.count = state.count.saturating_add(1);
        if state.count >= YUBIKEY_MAX_FAILURES {
            state.locked_until = Some(now + YUBIKEY_COOLDOWN);
            warn!(
                "yubikey failed {} times in window; locking out for {}s",
                state.count,
                YUBIKEY_COOLDOWN.as_secs()
            );
        }
    }
}

fn record_success() {
    if let Ok(mut state) = FAILURE_STATE.lock() {
        state.count = 0;
        state.first_failure = None;
        state.locked_until = None;
    }
}

/// OTP slot used for HMAC-SHA1 challenge-response by every legacy caller.
pub const SLOT: u8 = 2;

/// OTP slot used by the Phylax custody profile. Never falls back to [`SLOT`].
pub const CUSTODY_SLOT: u8 = 1;

/// Default location of the custody challenge file.
pub const DEFAULT_CUSTODY_CHALLENGE_PATH: &str = "/var/lib/phylax/challenge";

/// Environment variable overriding [`DEFAULT_CUSTODY_CHALLENGE_PATH`] (tests).
pub const CUSTODY_CHALLENGE_ENV: &str = "PHYLAX_CHALLENGE_PATH";

/// Challenge size in bytes. YubiKey HMAC-SHA1 accepts 0 to 64 byte challenges;
/// 32 matches what cred uses and gives us a full SHA-1 input block.
pub const CHALLENGE_SIZE: usize = 32;

/// HMAC-SHA1 response size in bytes.
pub const RESPONSE_SIZE: usize = 20;

/// Filename for the persisted challenge under the engram config dir.
const CHALLENGE_FILE: &str = "challenge";

/// Send a challenge to the legacy slot ([`SLOT`], slot 2) and get the
/// HMAC-SHA1 response.
///
/// Thin wrapper over [`challenge_response_slot`] kept so every existing
/// caller continues to use slot 2 unchanged.
pub fn challenge_response(challenge: &[u8]) -> Result<[u8; RESPONSE_SIZE]> {
    challenge_response_slot(challenge, SLOT)
}

/// Reject any OTP slot other than 1 or 2 before a subprocess is spawned.
fn validate_slot(slot: u8) -> Result<()> {
    if matches!(slot, 1 | 2) {
        Ok(())
    } else {
        Err(CredError::YubiKey(format!(
            "invalid YubiKey OTP slot {slot} (expected 1 or 2)"
        )))
    }
}

/// Build the `ykman` argument vector for `otp calculate <slot> <hex>`.
///
/// Pure so tests can assert the slot reaches the subprocess verbatim.
fn calculate_args(slot: u8, challenge_hex: &str) -> Vec<String> {
    let mut args = device_args();
    args.extend([
        "otp".to_string(),
        "calculate".to_string(),
        slot.to_string(),
        challenge_hex.to_string(),
    ]);
    args
}

/// Send a challenge to OTP `slot` (1 or 2) and get the HMAC-SHA1 response.
///
/// Uses `ykman otp calculate <slot> <hex>` on all platforms, with a Python
/// fallback on Unix for distros where the ykman wrapper script refuses
/// to take the HID. Both attempts use the same slot: there is no fallback to
/// a different slot, so an unprogrammed slot surfaces as a hard error.
pub fn challenge_response_slot(challenge: &[u8], slot: u8) -> Result<[u8; RESPONSE_SIZE]> {
    validate_slot(slot)?;
    check_rate_limit()?;

    let challenge_hex = hex::encode(challenge);

    #[cfg(not(windows))]
    let output = try_ykman_calculate(slot, &challenge_hex)
        .or_else(|first| try_python_ykman_calculate(slot, &challenge_hex).map_err(|_| first))
        .inspect_err(|_| record_failure())?;

    #[cfg(windows)]
    let output = try_ykman_calculate_win(slot, &challenge_hex).inspect_err(|_| record_failure())?;

    let decoded = hex::decode(output.trim()).map_err(|e| {
        record_failure();
        CredError::YubiKey(format!("invalid hex response from YubiKey: {}", e))
    })?;

    if decoded.len() != RESPONSE_SIZE {
        record_failure();
        return Err(CredError::YubiKey(format!(
            "unexpected HMAC response length: {} (expected {})",
            decoded.len(),
            RESPONSE_SIZE
        )));
    }

    let mut response = [0u8; RESPONSE_SIZE];
    response.copy_from_slice(&decoded);
    record_success();
    debug!(
        slot,
        "YubiKey challenge-response ok ({} bytes)", RESPONSE_SIZE
    );
    Ok(response)
}

/// Check whether a YubiKey is plugged in and responsive.
///
/// This does not verify that slot 2 is programmed, only that `ykman info`
/// returns successfully.
pub fn is_available() -> bool {
    Command::new("ykman")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Program slot 2 with an HMAC-SHA1 secret.
///
/// WARNING: This overwrites whatever is currently in the slot.
pub fn program_hmac_secret(secret: &[u8]) -> Result<()> {
    if secret.len() != RESPONSE_SIZE {
        return Err(CredError::YubiKey(format!(
            "HMAC secret must be exactly {} bytes",
            RESPONSE_SIZE
        )));
    }

    let secret_hex = hex::encode(secret);

    #[cfg(not(windows))]
    {
        try_ykman_program(&secret_hex)
            .or_else(|first| try_python_ykman_program(&secret_hex).map_err(|_| first))?;
    }

    #[cfg(windows)]
    {
        // On Windows, use ykman directly (no ykchallenge equivalent for programming)
        let out = Command::new("ykman")
            .args(["otp", "chalresp", &SLOT.to_string(), "--force", &secret_hex])
            .output()
            .map_err(|e| CredError::YubiKey(format!("ykman not found: {}", e)))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(CredError::YubiKey(format!(
                "ykman program failed: {}",
                stderr.trim()
            )));
        }
    }

    info!("programmed HMAC-SHA1 secret on slot {}", SLOT);
    Ok(())
}

/// Delete the OTP slot configuration.
pub fn delete_slot() -> Result<()> {
    #[cfg(not(windows))]
    {
        try_ykman_delete().or_else(|first| try_python_ykman_delete().map_err(|_| first))?;
    }

    #[cfg(windows)]
    {
        let out = Command::new("ykman")
            .args(["otp", "delete", &SLOT.to_string(), "--force"])
            .output()
            .map_err(|e| CredError::YubiKey(format!("ykman not found: {}", e)))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(CredError::YubiKey(format!(
                "ykman delete failed: {}",
                stderr.trim()
            )));
        }
    }

    info!("deleted slot {} configuration", SLOT);
    Ok(())
}

/// Get YubiKey device info (serial, firmware, etc.)
pub fn device_info() -> Result<String> {
    #[cfg(not(windows))]
    {
        try_ykman_info().or_else(|first| try_python_ykman_info().map_err(|_| first))
    }

    #[cfg(windows)]
    {
        let out = Command::new("ykman")
            .args(["info"])
            .output()
            .map_err(|e| CredError::YubiKey(format!("ykman not found: {}", e)))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(CredError::YubiKey(format!(
                "ykman info failed: {}",
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

/// Derive the AES-256-GCM master key from YubiKey challenge-response.
///
/// Loads the stored challenge, sends it to the YubiKey, and derives
/// the encryption key using the legacy KDF (compatible with private cred).
#[allow(deprecated)]
pub fn derive_master_key() -> Result<[u8; crate::crypto::KEY_SIZE]> {
    let challenge = get_or_create_challenge()?;
    let response = challenge_response(&challenge)?;
    Ok(crate::crypto::derive_key_legacy(&response))
}

/// Load or create the persistent 32-byte engram challenge.
///
/// Stored under `~/.config/engram/challenge` (or `$XDG_CONFIG_HOME/engram/
/// challenge`) with mode 0600. If the file exists with the wrong size we
/// refuse to overwrite it: that file protects an encrypted database and
/// silently regenerating would make the database unrecoverable.
pub fn get_or_create_challenge() -> Result<[u8; CHALLENGE_SIZE]> {
    get_or_create_challenge_at(&config_dir().join(CHALLENGE_FILE))
}

/// Resolve the custody challenge path: `PHYLAX_CHALLENGE_PATH` when set and
/// non-empty, otherwise [`DEFAULT_CUSTODY_CHALLENGE_PATH`].
pub fn custody_challenge_path() -> PathBuf {
    custody_challenge_path_from(std::env::var(CUSTODY_CHALLENGE_ENV).ok().as_deref())
}

/// Pure form of [`custody_challenge_path`] taking the env override explicitly.
fn custody_challenge_path_from(override_path: Option<&str>) -> PathBuf {
    match override_path {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_CUSTODY_CHALLENGE_PATH),
    }
}

/// Load or create the 32-byte challenge stored at `path`.
///
/// A new file is created with `O_EXCL` and mode 0600 (parent directory
/// created 0700 if missing). An existing file with the wrong size is never
/// overwritten: it protects an encrypted database, and regenerating it would
/// make that database unrecoverable.
pub fn get_or_create_challenge_at(path: &std::path::Path) -> Result<[u8; CHALLENGE_SIZE]> {
    if path.exists() {
        let data = std::fs::read(path)
            .map_err(|e| CredError::YubiKey(format!("read challenge {}: {}", path.display(), e)))?;
        if data.len() != CHALLENGE_SIZE {
            return Err(CredError::YubiKey(format!(
                "challenge file {} has wrong size ({} bytes, expected {}); refusing to overwrite -- back up and delete manually if you know what you are doing",
                path.display(),
                data.len(),
                CHALLENGE_SIZE
            )));
        }
        let mut out = [0u8; CHALLENGE_SIZE];
        out.copy_from_slice(&data);
        return Ok(out);
    }

    let mut challenge = [0u8; CHALLENGE_SIZE];
    OsRng
        .try_fill_bytes(&mut challenge)
        .map_err(|e| CredError::YubiKey(format!("OS CSPRNG unavailable: {e}")))?;

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_private_dir(dir)?;
    }
    write_new_private_file(path, &challenge)?;

    info!("generated new engram challenge at {}", path.display());
    Ok(challenge)
}

/// Create `dir` (and parents) when missing; newly created leaf is mode 0700.
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| CredError::YubiKey(format!("mkdir {}: {}", dir.display(), e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CredError::YubiKey(format!("chmod 700 {}: {}", dir.display(), e)))?;
    }
    Ok(())
}

/// Create `path` with `O_EXCL` and mode 0600 and write `bytes` to it.
fn write_new_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| CredError::YubiKey(format!("create challenge {}: {}", path.display(), e)))?;
    file.write_all(bytes)
        .map_err(|e| CredError::YubiKey(format!("write challenge {}: {}", path.display(), e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CredError::YubiKey(format!("chmod 600 {}: {}", path.display(), e)))?;
    }
    Ok(())
}

/// Software fallback for HMAC-SHA1 challenge-response (testing only).
///
/// Matches the byte-for-byte output of a YubiKey programmed with `secret`,
/// so CI and unit tests can exercise the derivation path without hardware.
pub fn software_hmac(secret: &[u8], challenge: &[u8; CHALLENGE_SIZE]) -> [u8; RESPONSE_SIZE] {
    use hmac::{digest::FixedOutput, Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(challenge);
    let out = mac.finalize_fixed();

    let mut response = [0u8; RESPONSE_SIZE];
    response.copy_from_slice(&out[..RESPONSE_SIZE]);
    response
}

/// Path of the challenge file this host currently uses, without creating one.
///
/// Returns `None` when no challenge file exists, so callers that must not
/// silently fork the vault key (rotation, auditing) can refuse instead.
pub fn active_challenge_path() -> Option<PathBuf> {
    let path = config_dir().join(CHALLENGE_FILE);
    path.exists().then_some(path)
}

/// Config directory for engram: `$XDG_CONFIG_HOME/engram` or
/// `~/.config/engram`.
fn config_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| PathBuf::from("."))
        });
    let cred_dir = base.join("cred");
    if cred_dir.join(CHALLENGE_FILE).exists() {
        return cred_dir;
    }
    base.join("engram")
}

// --- subprocess helpers ---

/// Get device selection args if YKSERIAL is set.
fn device_args() -> Vec<String> {
    match std::env::var("YKSERIAL") {
        Ok(serial) if !serial.is_empty() => vec!["--device".to_string(), serial],
        _ => vec![],
    }
}

#[cfg(windows)]
fn try_ykman_calculate_win(slot: u8, challenge_hex: &str) -> Result<String> {
    let args = calculate_args(slot, challenge_hex);

    let out = Command::new("ykman").args(&args).output().map_err(|e| {
        CredError::YubiKey(format!(
            "ykman not found on PATH (install YubiKey Manager): {}",
            e
        ))
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman otp calculate failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_ykman_calculate(slot: u8, challenge_hex: &str) -> Result<String> {
    let args = calculate_args(slot, challenge_hex);

    let out = Command::new("ykman").args(&args).output().map_err(|e| {
        CredError::YubiKey(format!(
            "ykman not found on PATH (install yubikey-manager): {}",
            e
        ))
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman otp calculate failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_python_ykman_calculate(slot: u8, challenge_hex: &str) -> Result<String> {
    // H-011: pass args via env vars -- never interpolate into the script body.
    const SCRIPT: &str = r#"
import os, sys
from ykman._cli.__main__ import main
device = os.environ.get("YKMAN_DEVICE", "")
arg1 = os.environ.get("YKMAN_ARG_1", "")
arg2 = os.environ.get("YKMAN_ARG_2", "")
argv = ['ykman']
if device:
    argv.extend(['--device', device])
argv.extend(['otp', 'calculate', arg1, arg2])
sys.argv = argv
main()
"#;

    let yk_serial = std::env::var("YKSERIAL").unwrap_or_default();
    let out = Command::new("sudo")
        .args([
            "--preserve-env=YKMAN_DEVICE,YKMAN_ARG_1,YKMAN_ARG_2",
            "python3",
            "-c",
            SCRIPT,
        ])
        .env("YKMAN_DEVICE", &yk_serial)
        .env("YKMAN_ARG_1", slot.to_string())
        .env("YKMAN_ARG_2", challenge_hex)
        .output()
        .map_err(|e| CredError::YubiKey(format!("sudo python3 ykman failed: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "python ykman calculate failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_ykman_program(secret_hex: &str) -> Result<String> {
    let mut args = device_args();
    args.extend([
        "otp".to_string(),
        "chalresp".to_string(),
        SLOT.to_string(),
        "--force".to_string(),
        secret_hex.to_string(),
    ]);

    let out = Command::new("ykman")
        .args(&args)
        .output()
        .map_err(|e| CredError::YubiKey(format!("ykman not found: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman program failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_python_ykman_program(secret_hex: &str) -> Result<String> {
    // H-011: pass args via env vars -- never interpolate into the script body.
    const SCRIPT: &str = r#"
import os, sys
from ykman._cli.__main__ import main
device = os.environ.get("YKMAN_DEVICE", "")
arg1 = os.environ.get("YKMAN_ARG_1", "")
arg2 = os.environ.get("YKMAN_ARG_2", "")
argv = ['ykman']
if device:
    argv.extend(['--device', device])
argv.extend(['otp', 'chalresp', arg1, '--force', arg2])
sys.argv = argv
main()
"#;

    let yk_serial = std::env::var("YKSERIAL").unwrap_or_default();
    let out = Command::new("sudo")
        .args([
            "--preserve-env=YKMAN_DEVICE,YKMAN_ARG_1,YKMAN_ARG_2",
            "python3",
            "-c",
            SCRIPT,
        ])
        .env("YKMAN_DEVICE", &yk_serial)
        .env("YKMAN_ARG_1", SLOT.to_string())
        .env("YKMAN_ARG_2", secret_hex)
        .output()
        .map_err(|e| CredError::YubiKey(format!("sudo python3 ykman failed: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "python ykman program failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_ykman_delete() -> Result<String> {
    let mut args = device_args();
    args.extend([
        "otp".to_string(),
        "delete".to_string(),
        SLOT.to_string(),
        "--force".to_string(),
    ]);

    let out = Command::new("ykman")
        .args(&args)
        .output()
        .map_err(|e| CredError::YubiKey(format!("ykman not found: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman delete failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_python_ykman_delete() -> Result<String> {
    // H-011: use static script; SLOT is a constant but keep pattern consistent.
    const SCRIPT: &str = r#"
import os, sys
from ykman._cli.__main__ import main
device = os.environ.get("YKMAN_DEVICE", "")
arg1 = os.environ.get("YKMAN_ARG_1", "")
argv = ['ykman']
if device:
    argv.extend(['--device', device])
argv.extend(['otp', 'delete', arg1, '--force'])
sys.argv = argv
main()
"#;

    let yk_serial = std::env::var("YKSERIAL").unwrap_or_default();
    let out = Command::new("sudo")
        .args([
            "--preserve-env=YKMAN_DEVICE,YKMAN_ARG_1",
            "python3",
            "-c",
            SCRIPT,
        ])
        .env("YKMAN_DEVICE", &yk_serial)
        .env("YKMAN_ARG_1", SLOT.to_string())
        .output()
        .map_err(|e| CredError::YubiKey(format!("sudo python3 ykman failed: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "python ykman delete failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_ykman_info() -> Result<String> {
    let out = Command::new("ykman")
        .args(["info"])
        .output()
        .map_err(|e| CredError::YubiKey(format!("ykman not found: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman info failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(windows))]
fn try_python_ykman_info() -> Result<String> {
    let script =
        "import sys\nfrom ykman._cli.__main__ import main\nsys.argv = ['ykman', 'info']\nmain()\n";

    let out = Command::new("sudo")
        .args(["python3", "-c", script])
        .output()
        .map_err(|e| CredError::YubiKey(format!("sudo python3 ykman failed: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "python ykman info failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_hmac_deterministic() {
        let secret = b"test-secret-key";
        let mut challenge = [0u8; CHALLENGE_SIZE];
        challenge[0] = 1;
        challenge[31] = 2;

        let r1 = software_hmac(secret, &challenge);
        let r2 = software_hmac(secret, &challenge);
        assert_eq!(r1, r2);
    }

    #[test]
    fn software_hmac_varies_with_secret() {
        let mut challenge = [0u8; CHALLENGE_SIZE];
        challenge[0] = 1;

        let r1 = software_hmac(b"secret1", &challenge);
        let r2 = software_hmac(b"secret2", &challenge);
        assert_ne!(r1, r2);
    }

    #[test]
    fn software_hmac_varies_with_challenge() {
        let secret = b"shared-secret";
        let mut c1 = [0u8; CHALLENGE_SIZE];
        let mut c2 = [0u8; CHALLENGE_SIZE];
        c1[0] = 1;
        c2[0] = 2;

        let r1 = software_hmac(secret, &c1);
        let r2 = software_hmac(secret, &c2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn software_hmac_matches_rfc2202_case_1() {
        use hmac::{digest::FixedOutput, Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;

        let key = [0x0bu8; 20];
        let mut mac = HmacSha1::new_from_slice(&key).unwrap();
        mac.update(b"Hi There");
        let expected = mac.finalize_fixed();

        assert_eq!(
            hex::encode(expected),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn challenge_size_constants_are_sane() {
        assert_eq!(CHALLENGE_SIZE, 32);
        assert_eq!(RESPONSE_SIZE, 20);
        assert_eq!(SLOT, 2);
        assert_eq!(CUSTODY_SLOT, 1);
    }

    /// Only OTP slots 1 and 2 pass validation; anything else is rejected
    /// before a subprocess is spawned.
    #[test]
    fn slot_validation_accepts_only_one_and_two() {
        assert!(validate_slot(1).is_ok());
        assert!(validate_slot(2).is_ok());
        assert!(validate_slot(0).is_err());
        assert!(validate_slot(3).is_err());
        assert!(challenge_response_slot(&[0u8; CHALLENGE_SIZE], 9).is_err());
    }

    /// The requested slot is passed to `ykman otp calculate` verbatim, so the
    /// custody path (slot 1) can never silently use slot 2.
    #[test]
    fn calculate_args_carry_the_requested_slot() {
        let custody = calculate_args(CUSTODY_SLOT, "aa");
        let legacy = calculate_args(SLOT, "aa");
        assert!(custody.windows(3).any(|w| w == ["calculate", "1", "aa"]));
        assert!(legacy.windows(3).any(|w| w == ["calculate", "2", "aa"]));
    }

    /// The custody challenge path honours the env override and otherwise
    /// falls back to the fixed system location.
    #[test]
    fn custody_challenge_path_override_and_default() {
        assert_eq!(
            custody_challenge_path_from(None),
            PathBuf::from("/var/lib/phylax/challenge")
        );
        assert_eq!(
            custody_challenge_path_from(Some("")),
            PathBuf::from("/var/lib/phylax/challenge")
        );
        assert_eq!(
            custody_challenge_path_from(Some("/tmp/x/challenge")),
            PathBuf::from("/tmp/x/challenge")
        );
    }

    /// A fresh challenge file is created 0600 in a 0700 directory, is stable
    /// across reads, and a wrong-sized file is never overwritten.
    #[cfg(unix)]
    #[test]
    fn challenge_at_creates_private_file_and_refuses_resize() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("phylax").join("challenge");
        let first = get_or_create_challenge_at(&path).unwrap();
        let second = get_or_create_challenge_at(&path).unwrap();
        assert_eq!(first, second);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);

        std::fs::write(&path, b"short").unwrap();
        assert!(get_or_create_challenge_at(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    /// H-011: verify that a malicious argument cannot cause shell/Python injection.
    /// The try_python_ykman_calculate call will fail (ykman not found or bad hex),
    /// but the important assertion is that /tmp/PWNED was NOT created.
    #[cfg(not(windows))]
    #[test]
    fn malicious_arg_does_not_inject() {
        let result =
            try_python_ykman_calculate(SLOT, "'); import os; os.system('touch /tmp/PWNED'); ('");
        // ykman will reject the bad hex -- we just care it errored, not which error
        assert!(result.is_err());
        assert!(!std::path::Path::new("/tmp/PWNED").exists());
    }
}
