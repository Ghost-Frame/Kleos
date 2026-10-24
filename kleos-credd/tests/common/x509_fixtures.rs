//! Throwaway PKI fixtures for the x509 tests.
//!
//! Every certificate is built by `kleos_credd::x509::issue_certificate`, the
//! same code path `rotate-leaf` uses, so the tests exercise the real issuance
//! rather than a second implementation. Nothing here touches a real secret:
//! all keys are generated fresh per call.
//!
//! Each test binary uses a different subset of these helpers, hence the
//! blanket `dead_code` allowance.
#![allow(dead_code)]

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use x509_cert::name::Name;
use x509_cert::Certificate;

use kleos_credd::x509::{
    certificate_pem, generate_key, issue_certificate, private_key_pem, random_serial, serial_hex,
    CertProfile, CertSpec,
};

/// Seconds in one day.
const DAY_SECS: u64 = 24 * 60 * 60;

/// One certificate with its private key, parsed and as PEM.
pub struct Identity {
    /// The certificate.
    pub cert: Certificate,
    /// Its private key.
    pub key: SigningKey,
    /// The certificate as PEM.
    pub cert_pem: String,
    /// The private key as PKCS#8 PEM.
    pub key_pem: String,
}

/// Identity helpers.
impl Identity {
    /// Lowercase hex serial of the certificate, as `rotate-leaf` names it.
    pub fn serial_hex(&self) -> String {
        serial_hex(&self.cert)
    }

    /// The subject as an RFC 4514 string such as `CN=svc-client`.
    pub fn subject(&self) -> String {
        self.cert.tbs_certificate.subject.to_string()
    }
}

/// Issue one certificate of `profile` for `subject`, signed by `issuer` (or
/// self-signed when `None`), valid from five minutes ago for `lifetime`.
fn issue(
    profile: CertProfile,
    subject: &str,
    issuer: Option<&Identity>,
    lifetime: Duration,
) -> Identity {
    let key = generate_key().expect("generate key");
    let subject = Name::from_str(subject).expect("subject name");
    let now = SystemTime::now();
    let (issuer_name, issuer_key) = match issuer {
        Some(ca) => (ca.cert.tbs_certificate.subject.clone(), &ca.key),
        None => (subject.clone(), &key),
    };
    let cert = issue_certificate(&CertSpec {
        profile,
        subject: subject.clone(),
        subject_key: key.verifying_key(),
        issuer_name,
        issuer_key,
        serial: random_serial().expect("serial"),
        not_before: now - Duration::from_secs(300),
        not_after: now + lifetime,
        carried_extensions: Vec::new(),
    })
    .expect("issue certificate");
    let cert_pem = certificate_pem(&cert).expect("certificate pem");
    let key_pem = private_key_pem(&key).expect("key pem").to_string();
    Identity {
        cert,
        key,
        cert_pem,
        key_pem,
    }
}

/// A self-signed CA named `cn`, valid for ten years.
pub fn new_ca(cn: &str) -> Identity {
    issue(
        CertProfile::Ca,
        &format!("CN={cn}"),
        None,
        Duration::from_secs(3650 * DAY_SECS),
    )
}

/// A client-auth leaf named `cn` issued by `ca`, valid for `days`.
pub fn new_client(ca: &Identity, cn: &str, days: u64) -> Identity {
    issue(
        CertProfile::ClientAuth,
        &format!("CN={cn}"),
        Some(ca),
        Duration::from_secs(days * DAY_SECS),
    )
}

/// A server-auth leaf for `ip` issued by `ca`, valid for one day.
pub fn new_server(ca: &Identity, ip: IpAddr) -> Identity {
    issue(
        CertProfile::ServerAuth { ip },
        "CN=test-upstream",
        Some(ca),
        Duration::from_secs(DAY_SECS),
    )
}

/// Content of a legacy note bundle: base64 (standard, padded) of the
/// schema-versioned JSON object.
pub fn legacy_note_content(cert_pem: &str, key_pem: &str, schema_version: u64) -> String {
    let json = serde_json::json!({
        "schema_version": schema_version,
        "certificate_pem": cert_pem,
        "private_key_pem": key_pem,
    });
    STANDARD.encode(json.to_string())
}
