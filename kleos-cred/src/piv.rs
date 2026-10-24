//! YubiKey PIV applet operations for ECDH bootstrap auth.
//!
//! This module wraps `ykman` (CLI) for key generation /
//! certificate creation / pubkey export, and Python `yubikit` (subprocess)
//! for the ECDH key agreement and ECDSA signing operations that the
//! `ykman` CLI does not expose.
//!
//! Slot allocation:
//! - 9D KEY_MANAGEMENT: P-256 ECDH key agreement (server-side in credd).
//! - 9A AUTHENTICATION: P-256 ECDSA signing (client identity proof).

use std::path::PathBuf;
use std::process::Command;

use crate::{CredError, Result};

/// PIV slot identifiers we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivSlot {
    /// 9A AUTHENTICATION -- client identity proof (ECDSA sign).
    Authentication,
    /// 9C DIGITAL SIGNATURE -- SSH CA signing.
    Signature,
    /// 9D KEY_MANAGEMENT -- ECDH key agreement (server side).
    KeyManagement,
}

impl PivSlot {
    /// Hex string passed to `ykman piv` commands.
    pub fn as_hex(&self) -> &'static str {
        match self {
            PivSlot::Authentication => "9a",
            PivSlot::Signature => "9c",
            PivSlot::KeyManagement => "9d",
        }
    }

    /// Python `yubikit.piv.SLOT.<name>` symbol used by ECDH/sign helpers.
    pub fn yubikit_name(&self) -> &'static str {
        match self {
            PivSlot::Authentication => "AUTHENTICATION",
            PivSlot::Signature => "SIGNATURE",
            PivSlot::KeyManagement => "KEY_MANAGEMENT",
        }
    }
}

/// PIN policy for generated PIV keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    Never,
    Once,
    Always,
}

impl PinPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            PinPolicy::Never => "never",
            PinPolicy::Once => "once",
            PinPolicy::Always => "always",
        }
    }
}

/// Touch policy for generated PIV keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

impl TouchPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            TouchPolicy::Never => "never",
            TouchPolicy::Always => "always",
            TouchPolicy::Cached => "cached",
        }
    }
}

/// Standard config dir for cred (matches yubikey.rs::config_dir).
fn config_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| PathBuf::from("."))
        });
    base.join("cred")
}

/// Path where the PEM-encoded public key for `slot` is stored after
/// `cred piv setup`. credd reads from these files at startup.
pub fn pubkey_path(slot: PivSlot) -> PathBuf {
    config_dir().join(format!("piv-{}-pubkey.pem", slot.as_hex()))
}

fn ykman_missing(e: std::io::Error) -> CredError {
    CredError::YubiKey(format!(
        "ykman not found on PATH (install yubikey-manager): {}",
        e
    ))
}

/// YubiKey factory-default PIV PIN. Used when `YKMAN_PIN` env is not set.
pub const DEFAULT_PIN: &str = "123456";

/// Returns the user-supplied management key if `YKMAN_MGMT_KEY` is set,
/// otherwise None which signals "use default by piping a blank line to
/// ykman" (the YubiKey-side check accepts the prompt-default sentinel
/// rather than the literal hex bytes that the docs advertise).
fn mgmt_key_override() -> Option<String> {
    std::env::var("YKMAN_MGMT_KEY").ok()
}

fn piv_pin() -> String {
    std::env::var("YKMAN_PIN").unwrap_or_else(|_| DEFAULT_PIN.to_string())
}

/// Line written to ykman's stdin to answer its management-key prompt.
///
/// `Some(key)` supplies the operator's management key; `None` sends a blank
/// line, which ykman reads as "use the factory-default management key". The
/// key goes through stdin, never `--management-key`, so it cannot appear in
/// `ps`, `/proc/<pid>/cmdline` or shell audit logs.
fn mgmt_key_stdin_line(management_key: Option<&str>) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(format!("{}\n", management_key.unwrap_or("")))
}

/// Run a ykman command, answering its management-key prompt on stdin.
///
/// If `YKMAN_MGMT_KEY` is set its value is piped to ykman; otherwise a blank
/// line is piped so ykman uses its factory-default management key. The key is
/// deliberately not passed as `--management-key` (argv is world-readable on
/// most hosts). `extra_path` is appended after the arguments (used for output
/// PEM paths).
fn ykman_with_mgmt(args: &[&str], extra_path: Option<&PathBuf>) -> Result<std::process::Output> {
    use std::io::Write;
    let mut cmd = Command::new("ykman");
    cmd.args(args);
    if let Some(p) = extra_path {
        cmd.arg(p);
    }
    let mk = mgmt_key_override().map(zeroize::Zeroizing::new);
    let line = mgmt_key_stdin_line(mk.as_ref().map(|k| k.as_str()));
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(ykman_missing)?;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(line.as_bytes());
    }
    child
        .wait_with_output()
        .map_err(|e| CredError::YubiKey(format!("ykman wait failed: {}", e)))
}

/// Generate a P-256 keypair on-device in `slot` with the given policies.
/// Writes the public key to `out_pem` (PEM-encoded). The private key
/// never leaves the YubiKey.
pub fn generate_p256_key(
    slot: PivSlot,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    out_pem: &PathBuf,
) -> Result<()> {
    let out = ykman_with_mgmt(
        &[
            "piv",
            "keys",
            "generate",
            "--algorithm",
            "eccp256",
            "--pin-policy",
            pin_policy.as_str(),
            "--touch-policy",
            touch_policy.as_str(),
            slot.as_hex(),
        ],
        Some(out_pem),
    )?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman piv keys generate {} failed: {}",
            slot.as_hex(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Generate a self-signed certificate in `slot`. PIV requires a cert in
/// the slot even when we do not use X.509 validation.
pub fn generate_self_signed_cert(slot: PivSlot, subject: &str, pubkey_pem: &PathBuf) -> Result<()> {
    let pin = piv_pin();
    let out = ykman_with_mgmt(
        &[
            "piv",
            "certificates",
            "generate",
            "--subject",
            subject,
            "--pin",
            &pin,
            slot.as_hex(),
        ],
        Some(pubkey_pem),
    )?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman piv certificates generate {} failed: {}",
            slot.as_hex(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Read the public key currently stored in `slot` and return its PEM
/// representation. Useful for `cred piv status` and for re-exporting
/// when the cached pubkey file was deleted.
pub fn export_pubkey_pem(slot: PivSlot) -> Result<String> {
    // Write to a freshly-created private temp DIR (unpredictable, 0700) instead
    // of a predictable /tmp path, so a local attacker cannot pre-create or
    // symlink-race the export path. ykman creates the file inside; the TempDir
    // auto-removes the dir and file on drop.
    let dir = tempfile::Builder::new()
        .prefix("cred-piv-export-")
        .tempdir()
        .map_err(|e| CredError::YubiKey(format!("create temp dir: {}", e)))?;
    let tmp = dir.path().join("pubkey.pem");
    let out = Command::new("ykman")
        .args(["piv", "keys", "export", slot.as_hex()])
        .arg(&tmp)
        .output()
        .map_err(ykman_missing)?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "ykman piv keys export {} failed: {}",
            slot.as_hex(),
            stderr.trim()
        )));
    }

    let pem = std::fs::read_to_string(&tmp)
        .map_err(|e| CredError::YubiKey(format!("read pubkey tempfile: {}", e)))?;
    Ok(pem)
}

/// Cheap probe of whether `slot` has a key provisioned. Discards stdout.
pub fn slot_has_key(slot: PivSlot) -> bool {
    // Private temp dir (see export_pubkey_pem) instead of a predictable path.
    let Ok(dir) = tempfile::Builder::new().prefix("cred-piv-probe-").tempdir() else {
        return false;
    };
    let tmp = dir.path().join("probe.pem");
    Command::new("ykman")
        .args(["piv", "keys", "export", slot.as_hex()])
        .arg(&tmp)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Builds the PIV ECDH (`calculate_secret`) Python script for `slot`.
///
/// Reads the PIN and serial from the process environment (`PIV_PIN`,
/// `YKSERIAL`) so neither secret is interpolated into the program text on
/// `python3 -c` argv (world-visible in `/proc/<pid>/cmdline`). The peer
/// public key is supplied on stdin. Only the (validated enum) slot name is
/// interpolated.
fn build_ecdh_script(slot: PivSlot) -> String {
    format!(
        r#"
import sys, os, base64
from ykman.device import list_all_devices
from yubikit.piv import PivSession, SLOT
from yubikit.core.smartcard import SmartCardConnection
from cryptography.hazmat.primitives.serialization import load_pem_public_key

peer_pem = sys.stdin.buffer.read()
peer = load_pem_public_key(peer_pem)

target_serial = os.environ.get("YKSERIAL") or None
piv_pin = os.environ["PIV_PIN"]

devices = list_all_devices()
if not devices:
    print("no yubikey detected", file=sys.stderr); sys.exit(2)

dev, info = None, None
if target_serial:
    for d, i in devices:
        if str(i.serial) == target_serial:
            dev, info = d, i
            break
    if dev is None:
        print(f"YubiKey with serial {{target_serial}} not found", file=sys.stderr); sys.exit(2)
else:
    if len(devices) > 1:
        serials = ", ".join(str(i.serial) for _, i in devices)
        print(f"multiple YubiKeys detected ({{serials}}), set YKSERIAL to pick one", file=sys.stderr); sys.exit(2)
    dev, info = devices[0]

with dev.open_connection(SmartCardConnection) as conn:
    session = PivSession(conn)
    session.verify_pin(piv_pin)
    shared = session.calculate_secret(SLOT.{slot}, peer)
    sys.stdout.write(base64.b16encode(shared).decode().lower())
"#,
        slot = slot.yubikit_name(),
    )
}

/// Perform ECDH key agreement using the YubiKey PIV applet.
/// `peer_pubkey_pem` is the peer's P-256 public key in PEM form.
/// Returns the raw 32-byte shared secret. Only `KeyManagement` (9D)
/// is supported.
///
/// Implemented via Python `yubikit` because `ykman` CLI does not expose
/// `calculate_secret`. Pattern mirrors `try_python_ykman_calculate` in
/// `yubikey.rs`.
pub fn ecdh_agree(slot: PivSlot, peer_pubkey_pem: &str) -> Result<[u8; 32]> {
    if slot != PivSlot::KeyManagement {
        return Err(CredError::InvalidInput(format!(
            "ECDH only supported on KEY_MANAGEMENT (9D), not {}",
            slot.as_hex()
        )));
    }

    let yk_serial = std::env::var("YKSERIAL").unwrap_or_default();
    // Runtime path: refuse to fall back to the YubiKey factory-default PIN.
    // A misconfigured PIV_PIN would otherwise burn PIN retries on the YubiKey
    // every time ECDH ran. Fail fast and loud instead.
    let piv_pin = kleos_lib::auth_piv::runtime_piv_pin().map_err(|e| {
        CredError::InvalidInput(format!(
            "PIV PIN not configured: {e} (export PIV_PIN to a non-default value)"
        ))
    })?;

    let script = build_ecdh_script(slot);

    // Secrets travel through the child environment, never on argv. The peer
    // public key is piped on stdin below.
    let mut child = Command::new("python3")
        .args(["-c", &script])
        .env("PIV_PIN", piv_pin.as_str())
        .env("YKSERIAL", &yk_serial)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| CredError::YubiKey(format!("python3 spawn failed: {}", e)))?;

    {
        use std::io::Write;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| CredError::YubiKey("failed to open python3 stdin".into()))?;
        stdin
            .write_all(peer_pubkey_pem.as_bytes())
            .map_err(|e| CredError::YubiKey(format!("write peer pubkey: {}", e)))?;
    }

    let out = child
        .wait_with_output()
        .map_err(|e| CredError::YubiKey(format!("python3 wait failed: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "PIV ECDH (slot {}) failed: {}",
            slot.as_hex(),
            stderr.trim()
        )));
    }

    let hex_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bytes = hex::decode(&hex_str)
        .map_err(|e| CredError::YubiKey(format!("invalid hex from ECDH subprocess: {}", e)))?;
    if bytes.len() != 32 {
        return Err(CredError::YubiKey(format!(
            "expected 32-byte ECDH shared secret, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// ECDSA-sign `payload` using the private key in `slot`. Returns the raw
/// DER-encoded signature. Implemented via Python `yubikit`. Only
/// `Authentication` (9A) is supported.
pub fn piv_sign(slot: PivSlot, payload: &[u8]) -> Result<Vec<u8>> {
    if slot != PivSlot::Authentication && slot != PivSlot::Signature {
        return Err(CredError::InvalidInput(format!(
            "PIV sign only supported on AUTHENTICATION (9A) or SIGNATURE (9C), not {}",
            slot.as_hex()
        )));
    }

    let payload_hex = hex::encode(payload);
    // NOTE: yubikit's PivSession.sign(message, hash_algorithm=SHA256()) hashes
    // the message INTERNALLY when hash_algorithm is set. Pre-hashing and
    // passing the digest causes a double-hash and verification failure on
    // the server side. Pass the raw payload bytes.
    let script = format!(
        r#"
import sys, base64
from ykman.device import list_all_devices
from yubikit.piv import PivSession, SLOT, KEY_TYPE
from yubikit.core.smartcard import SmartCardConnection
from cryptography.hazmat.primitives import hashes

payload = bytes.fromhex("{payload}")

devices = list_all_devices()
if not devices:
    print("no yubikey detected", file=sys.stderr); sys.exit(2)

dev, _info = devices[0]
with dev.open_connection(SmartCardConnection) as conn:
    session = PivSession(conn)
    sig = session.sign(SLOT.{slot}, KEY_TYPE.ECCP256, payload, hash_algorithm=hashes.SHA256())
    sys.stdout.write(base64.b16encode(sig).decode().lower())
"#,
        payload = payload_hex,
        slot = slot.yubikit_name(),
    );

    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .map_err(|e| CredError::YubiKey(format!("python3 sign spawn failed: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(CredError::YubiKey(format!(
            "PIV sign (slot {}) failed: {}",
            slot.as_hex(),
            stderr.trim()
        )));
    }

    let hex_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
    hex::decode(&hex_str)
        .map_err(|e| CredError::YubiKey(format!("invalid hex from sign subprocess: {}", e)))
}

/// SHA-256 fingerprint of a PEM public key, formatted as colon-separated
/// uppercase hex (e.g. `AB:CD:EF:...`). Used by `cred piv status`.
pub fn pubkey_fingerprint(pem: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pem.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// NOTE: Tests for generate_p256_key, generate_self_signed_cert, export_pubkey_pem,
// slot_has_key, ecdh_agree, and piv_sign are intentionally omitted -- they all
// invoke ykman/python3 subprocesses and require a physical YubiKey to be present.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piv_slot_hex_strings() {
        assert_eq!(PivSlot::Authentication.as_hex(), "9a");
        assert_eq!(PivSlot::Signature.as_hex(), "9c");
        assert_eq!(PivSlot::KeyManagement.as_hex(), "9d");
    }

    /// The ECDH script must read secrets from env, never interpolate them.
    #[test]
    fn ecdh_script_never_embeds_pin_or_serial() {
        let script = build_ecdh_script(PivSlot::KeyManagement);
        assert!(script.contains(r#"piv_pin = os.environ["PIV_PIN"]"#));
        assert!(script.contains(r#"target_serial = os.environ.get("YKSERIAL")"#));
        // No leftover interpolation tokens for the secrets.
        assert!(!script.contains("{piv_pin}"));
        assert!(!script.contains("{yk_serial}"));
        // The validated slot name is still interpolated.
        assert!(script.contains("SLOT.KEY_MANAGEMENT"));
    }

    #[test]
    fn piv_slot_yubikit_names() {
        assert_eq!(PivSlot::Authentication.yubikit_name(), "AUTHENTICATION");
        assert_eq!(PivSlot::Signature.yubikit_name(), "SIGNATURE");
        assert_eq!(PivSlot::KeyManagement.yubikit_name(), "KEY_MANAGEMENT");
    }

    #[test]
    fn pin_policy_strings() {
        assert_eq!(PinPolicy::Never.as_str(), "never");
        assert_eq!(PinPolicy::Once.as_str(), "once");
        assert_eq!(PinPolicy::Always.as_str(), "always");
    }

    #[test]
    fn touch_policy_strings() {
        assert_eq!(TouchPolicy::Never.as_str(), "never");
        assert_eq!(TouchPolicy::Always.as_str(), "always");
        assert_eq!(TouchPolicy::Cached.as_str(), "cached");
    }

    #[test]
    fn pubkey_fingerprint_deterministic() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY=\n-----END PUBLIC KEY-----\n";
        let fp1 = pubkey_fingerprint(pem);
        let fp2 = pubkey_fingerprint(pem);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn pubkey_fingerprint_format() {
        let pem = "test-pem-data";
        let fp = pubkey_fingerprint(pem);
        // SHA-256 is 32 bytes = 31 colons separating 32 two-char hex groups
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(
            parts.len(),
            32,
            "fingerprint must have 32 colon-separated bytes"
        );
        for part in &parts {
            assert_eq!(part.len(), 2, "each byte must be 2 uppercase hex chars");
            assert!(
                part.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()),
                "hex chars must be uppercase"
            );
        }
    }

    /// The management key is answered on stdin; a blank line selects the default.
    #[test]
    fn mgmt_key_goes_to_stdin_not_argv() {
        assert_eq!(mgmt_key_stdin_line(None).as_str(), "\n");
        assert_eq!(mgmt_key_stdin_line(Some("0102")).as_str(), "0102\n");
        // Guard against reintroducing the argv form in the ykman wrapper.
        let source = include_str!("piv.rs");
        let wrapper_start = source.find("fn ykman_with_mgmt").expect("wrapper present");
        let wrapper_end =
            source[wrapper_start..].find("\n}\n").expect("wrapper end") + wrapper_start;
        assert!(!source[wrapper_start..wrapper_end].contains("--management-key"));
    }

    #[test]
    fn pubkey_fingerprint_differs_with_different_input() {
        let fp1 = pubkey_fingerprint("pem-a");
        let fp2 = pubkey_fingerprint("pem-b");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn ecdh_agree_rejects_non_key_management_slot() {
        // This test exercises the slot validation without needing a YubiKey.
        // ecdh_agree returns Err immediately when the slot is wrong.
        let result = crate::piv::ecdh_agree(PivSlot::Authentication, "dummy-pem");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("KEY_MANAGEMENT") || msg.contains("9D") || msg.contains("9d"),
            "error should mention KEY_MANAGEMENT slot, got: {}",
            msg
        );
    }

    #[test]
    fn piv_sign_rejects_key_management_slot() {
        // piv_sign only allows 9A and 9C; 9D must be rejected without subprocess.
        let result = crate::piv::piv_sign(PivSlot::KeyManagement, b"payload");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("AUTHENTICATION")
                || msg.contains("SIGNATURE")
                || msg.contains("9A")
                || msg.contains("9a"),
            "error should mention valid slots, got: {}",
            msg
        );
    }
}
