//! A rustls server certificate resolver keyed by SNI.
//!
//! Each name (or `*.` wildcard) can hold one certificate per [`Source`]. A handshake gets, in
//! order: a pinned certificate for the name, then the user's own, then the ACME one, then the
//! self-signed one, skipping expired certificates while an unexpired one is left. Names without
//! a match, and handshakes without SNI, get the default certificate if one is set.
//!
//! Pinned certificates route internal names (enrolled devices, a private CA) to their own
//! certificate whatever else is configured. Changes take effect on the next handshake.
//!
//! A TLS-ALPN-01 validation (ALPN `acme-tls/1`) only ever gets the challenge certificate.

use crate::cert::{self, CertInfo, CertPair, normalize};
use crate::{ACME_TLS_ALPN, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Where a certificate came from, in the order the resolver prefers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// Pinned for internal names; always wins.
    Pinned,
    /// Supplied by the user.
    User,
    /// Issued over ACME.
    Acme,
    /// Generated here.
    SelfSigned,
}

impl Source {
    const ORDER: [Source; 4] = [Source::Pinned, Source::User, Source::Acme, Source::SelfSigned];
}

#[derive(Clone)]
struct Entry {
    key: Arc<CertifiedKey>,
    not_after: SystemTime,
}

#[derive(Default)]
struct Inner {
    names: HashMap<String, HashMap<Source, Entry>>,
    default: Option<Entry>,
    alpn: HashMap<String, Arc<CertifiedKey>>,
}

/// The SNI resolver. Share it as `Arc<Resolver>`.
#[derive(Default)]
pub struct Resolver {
    inner: RwLock<Inner>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = self.inner.read().unwrap();
        let mut names: Vec<_> = i.names.iter().map(|(n, m)| (n.clone(), m.keys().copied().collect::<Vec<_>>())).collect();
        names.sort();
        f.debug_struct("Resolver").field("names", &names).field("default", &i.default.is_some()).finish()
    }
}

impl Resolver {
    /// An empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// A resolver with a fresh self-signed certificate for `names`, also the default, so TLS
    /// keeps working before any other certificate arrives.
    pub fn with_self_signed(names: &[String]) -> Result<Self> {
        let r = Self::new();
        let pair = cert::self_signed(names, 365)?;
        let (k, i) = cert::certified_key(&pair)?;
        r.set_key(Source::SelfSigned, k.clone(), &i);
        r.set_default(k, i.not_after);
        Ok(r)
    }

    /// Installs `pair` from `source` for every DNS name in it; returns what it says.
    pub fn set(&self, source: Source, pair: &CertPair) -> Result<CertInfo> {
        let (k, i) = cert::certified_key(pair)?;
        self.set_key(source, k, &i);
        Ok(i)
    }

    /// Installs a built key from `source` for the names in `info`.
    pub fn set_key(&self, source: Source, key: Arc<CertifiedKey>, info: &CertInfo) {
        let mut g = self.inner.write().unwrap();
        for n in &info.names {
            g.names.entry(normalize(n)).or_default().insert(source, Entry { key: key.clone(), not_after: info.not_after });
        }
    }

    /// Pins `pair` for `pattern` (a name or `*.` wildcard), whatever the certificate's names.
    pub fn pin(&self, pattern: &str, pair: &CertPair) -> Result<CertInfo> {
        let (k, i) = cert::certified_key(pair)?;
        self.inner.write().unwrap().names.entry(normalize(pattern)).or_default().insert(Source::Pinned, Entry { key: k, not_after: i.not_after });
        Ok(i)
    }

    /// Removes the certificate from `source` for `name`.
    pub fn remove(&self, name: &str, source: Source) {
        let mut g = self.inner.write().unwrap();
        let n = normalize(name);
        if let Some(m) = g.names.get_mut(&n) {
            m.remove(&source);
            if m.is_empty() {
                g.names.remove(&n);
            }
        }
    }

    /// The certificate for handshakes without SNI or with an unknown name.
    pub fn set_default(&self, key: Arc<CertifiedKey>, not_after: SystemTime) {
        self.inner.write().unwrap().default = Some(Entry { key, not_after });
    }

    /// Clears the default certificate.
    pub fn clear_default(&self) {
        self.inner.write().unwrap().default = None;
    }

    /// The certificate and its source a handshake for `sni` gets now.
    pub fn lookup(&self, sni: Option<&str>) -> Option<(Source, Arc<CertifiedKey>)> {
        self.lookup_at(sni, SystemTime::now())
    }

    /// [`Resolver::lookup`] at time `now`.
    pub fn lookup_at(&self, sni: Option<&str>, now: SystemTime) -> Option<(Source, Arc<CertifiedKey>)> {
        let g = self.inner.read().unwrap();
        let found = sni.and_then(|host| {
            let host = normalize(host);
            // The exact name beats a wildcard.
            let exact = g.names.get(&host);
            let wild = host.split_once('.').and_then(|(_, rest)| g.names.get(&format!("*.{rest}")));
            let cands: Vec<(Source, &Entry)> = Source::ORDER
                .iter()
                .flat_map(|s| [exact.and_then(|m| m.get(s)), wild.and_then(|m| m.get(s))].into_iter().flatten().map(move |e| (*s, e)))
                .collect();
            cands.iter().find(|(_, e)| e.not_after > now).or(cands.first()).map(|(s, e)| (*s, e.key.clone()))
        });
        found.or_else(|| g.default.as_ref().map(|e| (Source::SelfSigned, e.key.clone())))
    }

    /// Publishes a TLS-ALPN-01 answer for `name`.
    pub(crate) fn set_alpn(&self, name: &str, key: Arc<CertifiedKey>) {
        self.inner.write().unwrap().alpn.insert(normalize(name), key);
    }

    /// Withdraws the TLS-ALPN-01 answer for `name`.
    pub(crate) fn remove_alpn(&self, name: &str) {
        self.inner.write().unwrap().alpn.remove(&normalize(name));
    }

    /// True while a TLS-ALPN-01 answer for `name` is published.
    pub fn has_alpn(&self, name: &str) -> bool {
        self.inner.read().unwrap().alpn.contains_key(&normalize(name))
    }

    /// A rustls server config using this resolver, offering `alpn` and `acme-tls/1`.
    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Result<Arc<rustls::ServerConfig>> {
        let mut c = rustls::ServerConfig::builder_with_provider(crate::crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| crate::Error::Config(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        c.alpn_protocols.push(ACME_TLS_ALPN.to_vec());
        Ok(Arc::new(c))
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name().map(str::to_string);
        let acme = hello.alpn().is_some_and(|mut a| a.any(|p| p == ACME_TLS_ALPN));
        if acme {
            // RFC 8737: answer validation only with the challenge certificate, never a real one.
            return sni.and_then(|n| self.inner.read().unwrap().alpn.get(&normalize(&n)).cloned());
        }
        self.lookup(sni.as_deref()).map(|(_, k)| k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pair(names: &[&str]) -> CertPair {
        cert::self_signed(&names.iter().map(|s| s.to_string()).collect::<Vec<_>>(), 30).unwrap()
    }

    fn leaf(k: &Arc<CertifiedKey>) -> Vec<u8> {
        k.end_entity_cert().unwrap().to_vec()
    }

    #[test]
    fn sources_win_in_order_and_hot_swap() {
        let r = Resolver::new();
        let ss = pair(&["a.example.com"]);
        r.set(Source::SelfSigned, &ss).unwrap();
        assert_eq!(r.lookup(Some("a.example.com")).unwrap().0, Source::SelfSigned);
        let acme = pair(&["a.example.com", "b.example.com"]);
        let ai = r.set(Source::Acme, &acme).unwrap();
        assert_eq!(r.lookup(Some("A.example.com.")).unwrap().0, Source::Acme);
        assert_eq!(leaf(&r.lookup(Some("b.example.com")).unwrap().1), ai.der);
        let user = pair(&["a.example.com"]);
        r.set(Source::User, &user).unwrap();
        assert_eq!(r.lookup(Some("a.example.com")).unwrap().0, Source::User);
        assert_eq!(r.lookup(Some("b.example.com")).unwrap().0, Source::Acme);
        // A new ACME cert replaces the old one for the next lookup.
        let acme2 = pair(&["b.example.com"]);
        let a2 = r.set(Source::Acme, &acme2).unwrap();
        assert_eq!(leaf(&r.lookup(Some("b.example.com")).unwrap().1), a2.der);
        r.remove("a.example.com", Source::User);
        assert_eq!(r.lookup(Some("a.example.com")).unwrap().0, Source::Acme);
        assert!(r.lookup(Some("c.example.com")).is_none());
    }

    #[test]
    fn expired_certs_give_way() {
        let r = Resolver::new();
        r.set(Source::User, &pair(&["a.example.com"])).unwrap();
        r.set(Source::SelfSigned, &pair(&["a.example.com"])).unwrap();
        let later = SystemTime::now() + Duration::from_secs(40 * 86400);
        // Both expired: still the preferred one rather than nothing.
        assert_eq!(r.lookup_at(Some("a.example.com"), later).unwrap().0, Source::User);
        let fresh = cert::self_signed(&["a.example.com".into()], 90).unwrap();
        r.set(Source::Acme, &fresh).unwrap();
        assert_eq!(r.lookup_at(Some("a.example.com"), later).unwrap().0, Source::Acme);
    }

    #[test]
    fn pinned_and_wildcards_and_default() {
        let r = Resolver::with_self_signed(&["host.example.com".into()]).unwrap();
        r.set(Source::Acme, &pair(&["*.example.com", "example.com"])).unwrap();
        assert_eq!(r.lookup(Some("x.example.com")).unwrap().0, Source::Acme);
        assert_eq!(r.lookup(Some("host.example.com")).unwrap().0, Source::Acme, "an ACME wildcard beats a self-signed exact name");
        let internal = pair(&["device-1.internal"]);
        let pi = r.pin("*.devices.example.com", &internal).unwrap();
        let (s, k) = r.lookup(Some("d1.devices.example.com")).unwrap();
        assert_eq!((s, leaf(&k)), (Source::Pinned, pi.der));
        assert_eq!(r.lookup(None).unwrap().0, Source::SelfSigned);
        assert_eq!(r.lookup(Some("other.test")).unwrap().0, Source::SelfSigned);
        r.clear_default();
        assert!(r.lookup(None).is_none());
    }
}
