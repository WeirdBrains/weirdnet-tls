//! Certificates and keys: PEM pairs, what a certificate says, self-signed and challenge certs.

use crate::{Error, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A certificate chain and its private key, both PEM.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertPair {
    /// The chain, leaf first.
    pub chain_pem: String,
    /// The leaf's private key (PKCS#8, SEC1 or PKCS#1).
    pub key_pem: String,
}

impl std::fmt::Debug for CertPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertPair").field("chain_pem", &self.chain_pem).field("key_pem", &"<redacted>").finish()
    }
}

/// What the leaf certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// DNS names from the subject alternative names, lowercase (wildcards as `*.example.com`).
    pub names: Vec<String>,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
    /// The serial number, hex.
    pub serial: String,
    /// The ACME Renewal Information id (`AKI.serial`, RFC 9773), when the cert has an AKI.
    pub ari_id: Option<String>,
    /// The leaf, DER.
    pub der: Vec<u8>,
}

impl CertInfo {
    /// The lifetime (`not_after - not_before`).
    pub fn lifetime(&self) -> Duration {
        self.not_after.duration_since(self.not_before).unwrap_or_default()
    }

    /// True if `now` is past `not_after`.
    pub fn expired(&self, now: SystemTime) -> bool {
        now >= self.not_after
    }

    /// True if the certificate covers `host` (exactly or by a one-label wildcard).
    pub fn covers(&self, host: &str) -> bool {
        self.names.iter().any(|n| name_matches(n, host))
    }

    /// The instant-acme identifier for ARI and `replaces`.
    pub fn ari(&self) -> Option<instant_acme::CertificateIdentifier<'static>> {
        let der = CertificateDer::from(self.der.clone());
        instant_acme::CertificateIdentifier::try_from(&der).ok().map(|c| c.into_owned())
    }
}

fn unix(secs: i64) -> SystemTime {
    if secs >= 0 { UNIX_EPOCH + Duration::from_secs(secs as u64) } else { UNIX_EPOCH }
}

/// Reads a DER certificate.
pub fn info(der: &[u8]) -> Result<CertInfo> {
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| Error::Cert(format!("parsing the certificate: {e}")))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for g in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(n) = g {
                names.push(n.to_ascii_lowercase());
            }
        }
    }
    let serial = c.raw_serial().iter().map(|b| format!("{b:02x}")).collect();
    let mut i = CertInfo {
        names,
        not_before: unix(c.validity().not_before.timestamp()),
        not_after: unix(c.validity().not_after.timestamp()),
        serial,
        ari_id: None,
        der: der.to_vec(),
    };
    i.ari_id = i.ari().map(|a| a.to_string());
    Ok(i)
}

/// The certificates in a PEM chain, leaf first.
pub fn parse_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Cert(format!("reading the PEM chain: {e}")))?;
    if chain.is_empty() {
        return Err(Error::Cert("the PEM chain has no certificates".into()));
    }
    Ok(chain)
}

/// The private key in a PEM file.
pub fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| Error::Cert(format!("reading the PEM key: {e}")))
}

/// Builds the rustls key for a chain and key, checking they belong together.
pub fn certified_key(pair: &CertPair) -> Result<(Arc<CertifiedKey>, CertInfo)> {
    let chain = parse_chain(&pair.chain_pem)?;
    let key = parse_key(&pair.key_pem)?;
    let ck = CertifiedKey::from_der(chain, key, &crate::crypto_provider()).map_err(|e| Error::Cert(e.to_string()))?;
    let i = info(ck.end_entity_cert().map_err(|e| Error::Cert(e.to_string()))?)?;
    Ok((Arc::new(ck), i))
}

/// A self-signed certificate for `names`, valid for `days` from now.
pub fn self_signed(names: &[String], days: u32) -> Result<CertPair> {
    let mut p = rcgen::CertificateParams::new(names.to_vec())?;
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::minutes(5);
    p.not_after = now + time::Duration::days(days.into());
    p.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(n) = names.first() {
        p.distinguished_name.push(rcgen::DnType::CommonName, n.clone());
    }
    let kp = rcgen::KeyPair::generate()?;
    let c = p.self_signed(&kp)?;
    Ok(CertPair { chain_pem: c.pem(), key_pem: kp.serialize_pem() })
}

/// The TLS-ALPN-01 answer for `name`: a self-signed cert with the acmeIdentifier extension
/// holding the SHA-256 digest of the key authorization (RFC 8737 section 3).
pub(crate) fn alpn_cert(name: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>> {
    let mut p = rcgen::CertificateParams::new(vec![name.to_string()])?;
    p.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let kp = rcgen::KeyPair::generate()?;
    let c = p.self_signed(&kp)?;
    let key = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    // Not `from_der`: its key check parses the leaf with webpki, which refuses the critical
    // acmeIdentifier extension.
    let signer = crate::crypto_provider().key_provider.load_private_key(key).map_err(|e| Error::Cert(e.to_string()))?;
    Ok(Arc::new(CertifiedKey::new(vec![c.der().clone()], signer)))
}

/// A fresh certificate key and CSR for `names`.
pub(crate) fn csr(names: &[String]) -> Result<(Vec<u8>, String)> {
    let key = rcgen::KeyPair::generate()?;
    let mut p = rcgen::CertificateParams::new(names.to_vec())?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    let csr = p.serialize_request(&key)?;
    Ok((csr.der().to_vec(), key.serialize_pem()))
}

/// Lowercases `name` and drops a trailing dot.
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// True if `pattern` (a name, or `*.` and a name) covers `host`. A wildcard covers exactly one
/// more label, as browsers do: `*.example.com` covers `a.example.com`, not `example.com` or
/// `a.b.example.com`.
pub fn name_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (normalize(pattern), normalize(host));
    match p.strip_prefix("*.") {
        Some(base) => h.split_once('.').is_some_and(|(label, rest)| !label.is_empty() && rest == base),
        None => p == h,
    }
}

/// True if `name` is a DNS name a public ACME CA (Let's Encrypt and the like) can certify
/// (`*.` allowed if `wildcard_ok`): a valid host name with at least two labels, not
/// `localhost` or under `.localhost`, not an IP address, and not ending in an all-digit label.
/// Use [`valid_private_name`] for a private CA that certifies such names.
pub fn valid_name(name: &str, wildcard_ok: bool) -> bool {
    valid_private_name(name, wildcard_ok) && public_name(name.strip_prefix("*.").unwrap_or(name))
}

/// True if `name` is a syntactically valid DNS name with at least two labels (`*.` allowed if
/// `wildcard_ok`), without [`valid_name`]'s public-CA rules: `a.localhost` and all-digit top
/// labels pass. For private CAs; see [`crate::AcmeConfig::private_names`].
pub fn valid_private_name(name: &str, wildcard_ok: bool) -> bool {
    let n = name.strip_prefix("*.").filter(|_| wildcard_ok).unwrap_or(name);
    n.len() <= 253
        && n.contains('.')
        && n.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Public CAs refuse `localhost`, IP addresses and names whose top label is all digits.
fn public_name(name: &str) -> bool {
    let n = normalize(name);
    let top = n.rsplit('.').next().unwrap_or("");
    n != "localhost" && !n.ends_with(".localhost") && n.parse::<std::net::IpAddr>().is_err() && !top.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_cover_one_label() {
        assert!(name_matches("*.example.com", "a.example.com"));
        assert!(name_matches("*.Example.com.", "A.example.COM"));
        assert!(!name_matches("*.example.com", "example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(name_matches("example.com", "EXAMPLE.com."));
    }

    #[test]
    fn names_are_checked() {
        assert!(valid_name("a.example.com", false));
        assert!(!valid_name("*.example.com", false));
        assert!(valid_name("*.example.com", true));
        assert!(!valid_name("localhost", false));
        assert!(!valid_name("-a.example.com", false));
        assert!(!valid_name("a_b.example.com", false));
    }

    #[test]
    fn public_cas_refuse_local_and_numeric_names() {
        for bad in ["localhost", "a.localhost", "A.LocalHost.", "*.localhost", "*.a.localhost", "127.0.0.1", "10.0.0.1", "::1", "a.b.123", "1.2"] {
            assert!(!valid_name(bad, true), "{bad:?}");
        }
        assert!(valid_name("a.example.123x", false));
        assert!(valid_name("localhost.example.com", false));
        assert!(valid_name("1.example.com", false));
        // A private CA may certify them.
        for ok in ["a.localhost", "*.a.localhost", "a.b.123", "127.0.0.1"] {
            assert!(valid_private_name(ok, true), "{ok:?}");
        }
        assert!(!valid_private_name("localhost", true), "one label");
        assert!(!valid_private_name("::1", true));
    }

    #[test]
    fn self_signed_reads_back() {
        let names = vec!["a.example.com".to_string(), "*.b.example.com".to_string()];
        let pair = self_signed(&names, 10).unwrap();
        let (_, i) = certified_key(&pair).unwrap();
        assert_eq!(i.names, names);
        assert!(i.covers("x.b.example.com"));
        let life = i.lifetime().as_secs();
        assert!((10 * 86400..=10 * 86400 + 600).contains(&life), "{life}");
        assert!(!format!("{pair:?}").contains("PRIVATE"));
    }

    #[test]
    fn mismatched_key_is_refused() {
        let a = self_signed(&["a.example.com".into()], 1).unwrap();
        let b = self_signed(&["a.example.com".into()], 1).unwrap();
        assert!(certified_key(&CertPair { chain_pem: a.chain_pem, key_pem: b.key_pem }).is_err());
    }
}
