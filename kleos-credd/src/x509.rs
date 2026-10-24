//! X.509 issuance and verification helpers for custody-side leaf rotation.
//!
//! Everything here is pure: PEM in, PEM out, no database and no HTTP. The
//! single code path [`issue_certificate`] builds every certificate this crate
//! signs (ECDSA P-256 with SHA-256): the replacement client leaf produced by
//! `POST /custody/x509/rotate-leaf`, and the throwaway CA and server
//! certificates the test suite needs. Private keys cross this module's API only
//! as [`SigningKey`] values or [`Zeroizing`] PEM strings, and no error variant
//! carries key material.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha1::{Digest, Sha1};
use thiserror::Error;
use x509_cert::der::asn1::{BitString, OctetString, UtcTime};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};
use zeroize::Zeroizing;

/// Lifetime, in days, of a rotated leaf when the caller does not choose one.
pub const DEFAULT_LEAF_LIFETIME_DAYS: u32 = 90;

/// Longest lifetime, in days, a rotated leaf may be given (the CA/Browser
/// Forum ceiling for publicly trusted TLS certificates).
pub const MAX_LEAF_LIFETIME_DAYS: u32 = 398;

/// How far before "now" a new certificate's `notBefore` is set, to absorb
/// clock skew between the issuer and the verifier.
const BACKDATE: Duration = Duration::from_secs(5 * 60);

/// Seconds in one day.
const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// `ecdsa-with-SHA256` (RFC 5758), the only signature algorithm this module
/// issues or accepts.
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// `id-ce-subjectKeyIdentifier`.
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// `id-ce-keyUsage`.
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// `id-ce-subjectAltName`.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// `id-ce-basicConstraints`.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// `id-ce-authorityKeyIdentifier`.
const OID_AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// `id-ce-extKeyUsage`.
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// `id-kp-serverAuth`.
const OID_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// `id-kp-clientAuth`.
const OID_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// Why an X.509 operation failed. No variant carries key or PEM text.
#[derive(Debug, Error)]
pub enum X509Error {
    /// The input is not a parseable PEM certificate.
    #[error("not a valid PEM certificate")]
    Certificate,
    /// The input is not a PKCS#8 PEM P-256 private key.
    #[error("not a valid PKCS#8 P-256 private key")]
    PrivateKey,
    /// The operating system could not supply random bytes.
    #[error("operating system entropy is unavailable")]
    Entropy,
    /// A timestamp fell outside the range X.509 can represent.
    #[error("timestamp is outside the representable range")]
    Time,
    /// The signing operation failed.
    #[error("certificate signing failed")]
    Signing,
    /// DER or PEM encoding of a structure failed.
    #[error("certificate encoding failed: {0}")]
    Encoding(String),
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, X509Error>;

/// Map any DER/SPKI error to [`X509Error::Encoding`] (structure errors only).
fn encoding<E: std::fmt::Display>(error: E) -> X509Error {
    X509Error::Encoding(error.to_string())
}

/// What a certificate issued by [`issue_certificate`] is for. It selects the
/// `basicConstraints`, `keyUsage`, `extKeyUsage` and `subjectAltName` content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertProfile {
    /// A certification authority: `CA:TRUE`, `keyCertSign` and `cRLSign`.
    Ca,
    /// A TLS client identity: `CA:FALSE`, `digitalSignature`, `clientAuth`.
    ClientAuth,
    /// A TLS server identity for one IP address: `CA:FALSE`,
    /// `digitalSignature`, `serverAuth` and an IP `subjectAltName`.
    ServerAuth {
        /// The address the certificate is valid for.
        ip: IpAddr,
    },
}

/// Everything [`issue_certificate`] needs to build and sign one certificate.
pub struct CertSpec<'a> {
    /// Which kind of certificate to build.
    pub profile: CertProfile,
    /// Subject distinguished name.
    pub subject: Name,
    /// Public key the certificate binds to the subject.
    pub subject_key: &'a VerifyingKey,
    /// Issuer distinguished name (equal to `subject` for a self-signed CA).
    pub issuer_name: Name,
    /// Key that signs the certificate (the subject's own key when self-signed).
    pub issuer_key: &'a SigningKey,
    /// Serial number bytes, big-endian, positive and at most 20 bytes.
    pub serial: Vec<u8>,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
    /// Extensions copied in verbatim (for example a predecessor's
    /// `subjectAltName`), skipped when the profile already emits that OID.
    pub carried_extensions: Vec<Extension>,
}

/// A freshly issued replacement leaf together with its new private key.
pub struct IssuedLeaf {
    /// The signed certificate.
    pub certificate: Certificate,
    /// The certificate as PEM (`CERTIFICATE`).
    pub certificate_pem: String,
    /// The new private key as PKCS#8 PEM (`PRIVATE KEY`), zeroized on drop.
    pub private_key_pem: Zeroizing<String>,
    /// Lowercase hex of the serial number.
    pub serial_hex: String,
    /// `notAfter` as seconds since the Unix epoch.
    pub not_after_unix: u64,
}

/// Parse the first PEM certificate in `pem`.
pub fn parse_certificate(pem: &str) -> Result<Certificate> {
    Certificate::from_pem(pem.as_bytes()).map_err(|_| X509Error::Certificate)
}

/// Parse a PKCS#8 PEM P-256 private key. The error never echoes the input.
pub fn parse_signing_key(pem: &str) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(pem).map_err(|_| X509Error::PrivateKey)
}

/// Encode a certificate as PEM (`CERTIFICATE`, LF line endings).
pub fn certificate_pem(certificate: &Certificate) -> Result<String> {
    certificate.to_pem(LineEnding::LF).map_err(encoding)
}

/// Encode a private key as PKCS#8 PEM (`PRIVATE KEY`, LF line endings).
pub fn private_key_pem(key: &SigningKey) -> Result<Zeroizing<String>> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| X509Error::PrivateKey)
}

/// Generate a fresh P-256 signing key from operating system entropy.
pub fn generate_key() -> Result<SigningKey> {
    // A random 32-byte string is a valid scalar with overwhelming
    // probability; retry the (astronomically unlikely) rejection a few times.
    for _ in 0..8 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut bytes[..])
            .map_err(|_| X509Error::Entropy)?;
        if let Ok(key) = SigningKey::from_slice(&bytes[..]) {
            return Ok(key);
        }
    }
    Err(X509Error::Entropy)
}

/// A random 20-byte serial number with the top bit cleared (positive in DER)
/// and never zero.
pub fn random_serial() -> Result<Vec<u8>> {
    let mut bytes = [0u8; 20];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| X509Error::Entropy)?;
    bytes[0] &= 0x7f;
    if bytes.iter().all(|b| *b == 0) {
        bytes[19] = 1;
    }
    Ok(bytes.to_vec())
}

/// Lowercase hex of a certificate's serial number (leading zeros stripped).
pub fn serial_hex(certificate: &Certificate) -> String {
    hex::encode(certificate.tbs_certificate.serial_number.as_bytes())
}

/// `notAfter` of a certificate as seconds since the Unix epoch.
pub fn not_after_unix(certificate: &Certificate) -> u64 {
    certificate
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs()
}

/// SubjectPublicKeyInfo for a P-256 verifying key.
fn spki_of(key: &VerifyingKey) -> Result<SubjectPublicKeyInfoOwned> {
    let document = key.to_public_key_der().map_err(encoding)?;
    SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).map_err(encoding)
}

/// RFC 5280 section 4.2.1.2 method (1): SHA-1 of the `subjectPublicKey` bits.
fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    Sha1::digest(spki.subject_public_key.raw_bytes()).to_vec()
}

/// The P-256 public key a certificate binds to its subject.
pub fn certificate_public_key(certificate: &Certificate) -> Result<VerifyingKey> {
    let der = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(encoding)?;
    VerifyingKey::from_public_key_der(&der).map_err(|_| X509Error::Certificate)
}

/// True when `key` is the private half of the key `certificate` certifies.
pub fn key_matches_certificate(certificate: &Certificate, key: &SigningKey) -> bool {
    let Ok(wanted) = spki_of(key.verifying_key()) else {
        return false;
    };
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        == wanted.subject_public_key.raw_bytes()
}

/// True when `leaf` names `ca` as its issuer and carries an ECDSA-SHA256
/// signature over its TBS bytes that verifies under `ca`'s public key.
pub fn verify_issued_by(leaf: &Certificate, ca: &Certificate) -> bool {
    if leaf.tbs_certificate.issuer != ca.tbs_certificate.subject {
        return false;
    }
    if leaf.signature_algorithm.oid != ECDSA_WITH_SHA256
        || leaf.tbs_certificate.signature.oid != ECDSA_WITH_SHA256
    {
        return false;
    }
    let Ok(ca_key) = certificate_public_key(ca) else {
        return false;
    };
    let Ok(tbs) = leaf.tbs_certificate.to_der() else {
        return false;
    };
    let Some(signature_bytes) = leaf.signature.as_bytes() else {
        return false;
    };
    let Ok(signature) = Signature::from_der(signature_bytes) else {
        return false;
    };
    ca_key.verify(&tbs, &signature).is_ok()
}

/// Convert a point in time to an RFC 5280 `Time`: `UTCTime` through 2049 and
/// `GeneralizedTime` after.
fn to_time(instant: SystemTime) -> Result<Time> {
    match UtcTime::from_system_time(instant) {
        Ok(utc) => Ok(Time::UtcTime(utc)),
        Err(_) => Time::try_from(instant).map_err(|_| X509Error::Time),
    }
}

/// Wrap a DER-encodable extension value in an [`Extension`].
fn extension<E: Encode>(oid: ObjectIdentifier, critical: bool, value: &E) -> Result<Extension> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der().map_err(encoding)?).map_err(encoding)?,
    })
}

/// Build and sign one certificate (ECDSA P-256 with SHA-256).
///
/// Extensions, in order: `basicConstraints` (critical), `keyUsage` (critical),
/// `extKeyUsage` (non-critical, absent for a CA), `subjectAltName` (server
/// profile only), `subjectKeyIdentifier` (SHA-1 of the subject key bits),
/// `authorityKeyIdentifier` (same method, over the issuer key), then any
/// carried extensions whose OID is not already present.
pub fn issue_certificate(spec: &CertSpec<'_>) -> Result<Certificate> {
    let subject_spki = spki_of(spec.subject_key)?;
    let issuer_spki = spki_of(spec.issuer_key.verifying_key())?;
    let algorithm = AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA256,
        parameters: None,
    };

    let mut extensions = vec![extension(
        OID_BASIC_CONSTRAINTS,
        true,
        &BasicConstraints {
            ca: spec.profile == CertProfile::Ca,
            path_len_constraint: None,
        },
    )?];
    let key_usage = match spec.profile {
        CertProfile::Ca => KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        CertProfile::ClientAuth | CertProfile::ServerAuth { .. } => {
            KeyUsage(KeyUsages::DigitalSignature.into())
        }
    };
    extensions.push(extension(OID_KEY_USAGE, true, &key_usage)?);
    match spec.profile {
        CertProfile::Ca => {}
        CertProfile::ClientAuth => extensions.push(extension(
            OID_EXT_KEY_USAGE,
            false,
            &ExtendedKeyUsage(vec![OID_CLIENT_AUTH]),
        )?),
        CertProfile::ServerAuth { ip } => {
            extensions.push(extension(
                OID_EXT_KEY_USAGE,
                false,
                &ExtendedKeyUsage(vec![OID_SERVER_AUTH]),
            )?);
            extensions.push(extension(
                OID_SUBJECT_ALT_NAME,
                false,
                &SubjectAltName(vec![GeneralName::from(ip)]),
            )?);
        }
    }
    extensions.push(extension(
        OID_SUBJECT_KEY_ID,
        false,
        &SubjectKeyIdentifier(OctetString::new(key_identifier(&subject_spki)).map_err(encoding)?),
    )?);
    extensions.push(extension(
        OID_AUTHORITY_KEY_ID,
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(key_identifier(&issuer_spki)).map_err(encoding)?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )?);
    for carried in &spec.carried_extensions {
        if !extensions.iter().any(|e| e.extn_id == carried.extn_id) {
            extensions.push(carried.clone());
        }
    }

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&spec.serial).map_err(encoding)?,
        signature: algorithm.clone(),
        issuer: spec.issuer_name.clone(),
        validity: Validity {
            not_before: to_time(spec.not_before)?,
            not_after: to_time(spec.not_after)?,
        },
        subject: spec.subject.clone(),
        subject_public_key_info: subject_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let tbs_der = tbs.to_der().map_err(encoding)?;
    let signature: Signature = spec
        .issuer_key
        .try_sign(&tbs_der)
        .map_err(|_| X509Error::Signing)?;
    let signature_der = signature.to_der();
    Ok(Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(signature_der.as_bytes()).map_err(encoding)?,
    })
}

/// Issue the replacement for `old_leaf`: a new P-256 key, the old subject, the
/// CA as issuer, and a client-auth profile valid for `lifetime_days` from `now`
/// (starting [`BACKDATE`] earlier).
///
/// The old leaf's `subjectAltName`, if any, is carried over so the replacement
/// keeps the identity the relying party matches on. `ca_certificate` supplies
/// the issuer name only; the caller has already checked that `ca_key` belongs
/// to it.
pub fn issue_replacement_leaf(
    ca_certificate: &Certificate,
    ca_key: &SigningKey,
    old_leaf: &Certificate,
    lifetime_days: u32,
    now: SystemTime,
) -> Result<IssuedLeaf> {
    let key = generate_key()?;
    let not_before = now.checked_sub(BACKDATE).ok_or(X509Error::Time)?;
    let not_after = now
        .checked_add(Duration::from_secs(u64::from(lifetime_days) * SECS_PER_DAY))
        .ok_or(X509Error::Time)?;
    let carried_extensions = old_leaf
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
        .cloned()
        .collect();
    let certificate = issue_certificate(&CertSpec {
        profile: CertProfile::ClientAuth,
        subject: old_leaf.tbs_certificate.subject.clone(),
        subject_key: key.verifying_key(),
        issuer_name: ca_certificate.tbs_certificate.subject.clone(),
        issuer_key: ca_key,
        serial: random_serial()?,
        not_before,
        not_after,
        carried_extensions,
    })?;
    Ok(IssuedLeaf {
        certificate_pem: certificate_pem(&certificate)?,
        private_key_pem: private_key_pem(&key)?,
        serial_hex: serial_hex(&certificate),
        not_after_unix: not_after_unix(&certificate),
        certificate,
    })
}

/// The Unix time of `instant` in whole seconds (0 before the epoch).
pub fn unix_secs(instant: SystemTime) -> u64 {
    instant
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unit tests: issuance, verification and the extension profile of each kind.
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use x509_cert::ext::pkix::name::GeneralName as Gn;

    /// Issue a self-signed CA named `cn`, valid for ten years.
    fn ca(cn: &str) -> (Certificate, SigningKey) {
        let key = generate_key().unwrap();
        let name = Name::from_str(&format!("CN={cn}")).unwrap();
        let now = SystemTime::now();
        let cert = issue_certificate(&CertSpec {
            profile: CertProfile::Ca,
            subject: name.clone(),
            subject_key: key.verifying_key(),
            issuer_name: name,
            issuer_key: &key,
            serial: random_serial().unwrap(),
            not_before: now - BACKDATE,
            not_after: now + Duration::from_secs(3650 * SECS_PER_DAY),
            carried_extensions: Vec::new(),
        })
        .unwrap();
        (cert, key)
    }

    /// A CA-signed client leaf for `cn` verifies under its CA and no other.
    #[test]
    fn issued_leaf_verifies_under_its_ca_only() {
        let (ca_cert, ca_key) = ca("test-ca");
        let (other_cert, _) = ca("other-ca");
        let old = ca("stand-in-for-old-leaf").0;
        let leaf = issue_replacement_leaf(&ca_cert, &ca_key, &old, 30, SystemTime::now()).unwrap();
        assert!(verify_issued_by(&leaf.certificate, &ca_cert));
        assert!(!verify_issued_by(&leaf.certificate, &other_cert));
        assert!(!verify_issued_by(&ca_cert, &leaf.certificate));
        // Subject copied from the predecessor, issuer is the CA.
        assert_eq!(
            leaf.certificate.tbs_certificate.subject.to_string(),
            "CN=stand-in-for-old-leaf"
        );
        assert_eq!(
            leaf.certificate.tbs_certificate.issuer,
            ca_cert.tbs_certificate.subject
        );
        // PEM round trip keeps the serial and the signature intact.
        let reparsed = parse_certificate(&leaf.certificate_pem).unwrap();
        assert_eq!(serial_hex(&reparsed), leaf.serial_hex);
        assert!(verify_issued_by(&reparsed, &ca_cert));
        assert!(parse_signing_key(&leaf.private_key_pem).is_ok());
    }

    /// A tampered certificate no longer verifies.
    #[test]
    fn tampering_breaks_verification() {
        let (ca_cert, ca_key) = ca("test-ca");
        let old = ca("old").0;
        let leaf = issue_replacement_leaf(&ca_cert, &ca_key, &old, 30, SystemTime::now()).unwrap();
        let mut forged = leaf.certificate.clone();
        forged.tbs_certificate.subject = Name::from_str("CN=someone-else").unwrap();
        assert!(!verify_issued_by(&forged, &ca_cert));
    }

    /// The client profile carries exactly the specified extensions with the
    /// specified criticality, and the key identifiers chain leaf to CA.
    #[test]
    fn client_profile_extensions() {
        let (ca_cert, ca_key) = ca("test-ca");
        let old = ca("old").0;
        let leaf = issue_replacement_leaf(&ca_cert, &ca_key, &old, 30, SystemTime::now())
            .unwrap()
            .certificate;
        let tbs = &leaf.tbs_certificate;

        let (bc_critical, bc) = tbs.get::<BasicConstraints>().unwrap().unwrap();
        assert!(bc_critical && !bc.ca);
        let (ku_critical, ku) = tbs.get::<KeyUsage>().unwrap().unwrap();
        assert!(ku_critical && ku.digital_signature() && !ku.key_cert_sign());
        let (eku_critical, eku) = tbs.get::<ExtendedKeyUsage>().unwrap().unwrap();
        assert!(!eku_critical);
        assert_eq!(eku.0, vec![OID_CLIENT_AUTH]);
        let (ski_critical, ski) = tbs.get::<SubjectKeyIdentifier>().unwrap().unwrap();
        assert!(!ski_critical);
        assert_eq!(
            ski.0.as_bytes(),
            key_identifier(&tbs.subject_public_key_info).as_slice()
        );
        let (aki_critical, aki) = tbs.get::<AuthorityKeyIdentifier>().unwrap().unwrap();
        assert!(!aki_critical);
        let (_, ca_ski) = ca_cert
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .unwrap()
            .unwrap();
        assert_eq!(aki.key_identifier.as_ref(), Some(&ca_ski.0));
        assert!(tbs.get::<SubjectAltName>().unwrap().is_none());
    }

    /// Serials are 20 bytes at most, positive, nonzero and distinct.
    #[test]
    fn serials_are_positive_nonzero_and_distinct() {
        let a = random_serial().unwrap();
        let b = random_serial().unwrap();
        assert_eq!(a.len(), 20);
        assert_eq!(a[0] & 0x80, 0);
        assert!(a.iter().any(|x| *x != 0));
        assert_ne!(a, b);
    }

    /// The CA profile is `CA:TRUE` with certificate-signing usage, and the
    /// server profile carries its IP SAN and `serverAuth`.
    #[test]
    fn ca_and_server_profiles() {
        let (ca_cert, ca_key) = ca("test-ca");
        let tbs = &ca_cert.tbs_certificate;
        let (critical, bc) = tbs.get::<BasicConstraints>().unwrap().unwrap();
        assert!(critical && bc.ca);
        let (_, ku) = tbs.get::<KeyUsage>().unwrap().unwrap();
        assert!(ku.key_cert_sign() && ku.crl_sign());
        assert!(tbs.get::<ExtendedKeyUsage>().unwrap().is_none());

        let server_key = generate_key().unwrap();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let now = SystemTime::now();
        let server = issue_certificate(&CertSpec {
            profile: CertProfile::ServerAuth { ip },
            subject: Name::from_str("CN=server").unwrap(),
            subject_key: server_key.verifying_key(),
            issuer_name: ca_cert.tbs_certificate.subject.clone(),
            issuer_key: &ca_key,
            serial: random_serial().unwrap(),
            not_before: now - BACKDATE,
            not_after: now + Duration::from_secs(SECS_PER_DAY),
            carried_extensions: Vec::new(),
        })
        .unwrap();
        assert!(verify_issued_by(&server, &ca_cert));
        let (_, san) = server
            .tbs_certificate
            .get::<SubjectAltName>()
            .unwrap()
            .unwrap();
        assert_eq!(san.0, vec![Gn::from(ip)]);
    }

    /// A predecessor's SAN is carried to the replacement.
    #[test]
    fn replacement_keeps_the_predecessors_san() {
        let (ca_cert, ca_key) = ca("test-ca");
        let key = generate_key().unwrap();
        let ip = IpAddr::from([10, 1, 2, 3]);
        let now = SystemTime::now();
        let old = issue_certificate(&CertSpec {
            profile: CertProfile::ServerAuth { ip },
            subject: Name::from_str("CN=old").unwrap(),
            subject_key: key.verifying_key(),
            issuer_name: ca_cert.tbs_certificate.subject.clone(),
            issuer_key: &ca_key,
            serial: random_serial().unwrap(),
            not_before: now - BACKDATE,
            not_after: now + Duration::from_secs(SECS_PER_DAY),
            carried_extensions: Vec::new(),
        })
        .unwrap();
        let fresh = issue_replacement_leaf(&ca_cert, &ca_key, &old, 10, now)
            .unwrap()
            .certificate;
        let (_, san) = fresh
            .tbs_certificate
            .get::<SubjectAltName>()
            .unwrap()
            .unwrap();
        assert_eq!(san.0, vec![Gn::from(ip)]);
    }

    /// Key and certificate pairing is detected.
    #[test]
    fn key_certificate_pairing() {
        let (ca_cert, ca_key) = ca("test-ca");
        assert!(key_matches_certificate(&ca_cert, &ca_key));
        assert!(!key_matches_certificate(&ca_cert, &generate_key().unwrap()));
    }

    /// Garbage inputs fail with the matching variant and echo nothing.
    #[test]
    fn parse_failures_do_not_echo_input() {
        let junk = "-----BEGIN PRIVATE KEY-----\nTk9UQUtFWQ==\n-----END PRIVATE KEY-----\n";
        let err = parse_signing_key(junk).unwrap_err();
        assert!(matches!(err, X509Error::PrivateKey));
        assert!(!err.to_string().contains("Tk9U"));
        assert!(matches!(
            parse_certificate("nope"),
            Err(X509Error::Certificate)
        ));
    }

    /// Times past 2049 switch to GeneralizedTime instead of failing.
    #[test]
    fn far_future_validity_uses_generalized_time() {
        let far = UNIX_EPOCH + Duration::from_secs(4_200_000_000);
        assert!(matches!(to_time(far).unwrap(), Time::GeneralTime(_)));
        let near = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(matches!(to_time(near).unwrap(), Time::UtcTime(_)));
    }
}
