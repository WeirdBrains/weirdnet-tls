//! Certificates from an ACME CA.
//!
//! ```no_run
//! # async fn demo() -> weirdnet_tls::Result<()> {
//! use std::sync::Arc;
//! use weirdnet_tls::*;
//! let names = vec!["example.com".to_string(), "www.example.com".to_string()];
//! let resolver = Arc::new(Resolver::with_self_signed(&names)?);
//! let store = Arc::new(FileStore::new("/var/lib/myapp/tls"));
//! let mut cfg = AcmeConfig::new("main", names);
//! cfg.contact = vec!["admin@example.com".into()];
//! let acme = Arc::new(Acme::new(cfg, store, resolver.clone())?);
//! acme.load()?;              // serve the stored certificate right away
//! let _renewer = acme.clone().spawn(); // issue now if needed, then renew in the background
//! let _tls = resolver.server_config(&[b"h2", b"http/1.1"])?; // TLS-ALPN-01 is answered here
//! # Ok(()) }
//! ```

use crate::cert::{self, CertInfo, CertPair};
use crate::challenge::{DnsChallenge, DnsRecord, Http01Board};
use crate::renew::{self, Outcome, Persisted, State, Status, Window};
use crate::resolver::{Resolver, Source};
use crate::store::{self, CertStore};
use crate::{Error, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Notify, watch};

/// Let's Encrypt production.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging (untrusted certificates, generous rate limits).
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// The ACME directory to use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Directory {
    /// Let's Encrypt production.
    LetsEncrypt,
    /// Let's Encrypt staging.
    LetsEncryptStaging,
    /// Any RFC 8555 directory URL.
    Custom(String),
}

impl Directory {
    /// The directory URL.
    pub fn url(&self) -> &str {
        match self {
            Directory::LetsEncrypt => LETS_ENCRYPT,
            Directory::LetsEncryptStaging => LETS_ENCRYPT_STAGING,
            Directory::Custom(u) => u,
        }
    }
}

/// How names are validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeKind {
    /// TLS-ALPN-01 on port 443, answered by the [`Resolver`].
    TlsAlpn01,
    /// HTTP-01 on port 80, answered from the [`Http01Board`].
    Http01,
    /// DNS-01 through a [`DnsChallenge`]; the only one for wildcards.
    Dns01,
}

impl ChallengeKind {
    fn acme(self) -> ChallengeType {
        match self {
            ChallengeKind::TlsAlpn01 => ChallengeType::TlsAlpn01,
            ChallengeKind::Http01 => ChallengeType::Http01,
            ChallengeKind::Dns01 => ChallengeType::Dns01,
        }
    }

    /// The RFC name, such as `tls-alpn-01`.
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeKind::TlsAlpn01 => "tls-alpn-01",
            ChallengeKind::Http01 => "http-01",
            ChallengeKind::Dns01 => "dns-01",
        }
    }
}

/// What to ask the CA for.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// The certificate set's id in the store (`a-z0-9._-`).
    pub set: String,
    /// The names on the certificate; the first is the main one.
    pub names: Vec<String>,
    /// The CA.
    pub directory: Directory,
    /// Contact emails for the account.
    pub contact: Vec<String>,
    /// The challenge.
    pub challenge: ChallengeKind,
    /// An ACME profile, for CAs that offer them (such as Let's Encrypt's `shortlived`).
    pub profile: Option<String>,
    /// When the CA refuses the profile's order, order with the CA's default instead.
    pub profile_optional: bool,
    /// How long to wait after publishing DNS-01 records before asking the CA to look.
    pub dns_wait: Duration,
    /// Use ACME Renewal Information (RFC 9773) when the CA offers it.
    pub ari: bool,
    /// Polling of orders and certificates.
    pub retry: RetryPolicy,
}

impl AcmeConfig {
    /// Let's Encrypt production, TLS-ALPN-01, ARI on, 30 seconds of DNS wait.
    pub fn new(set: impl Into<String>, names: Vec<String>) -> Self {
        Self {
            set: set.into(),
            names,
            directory: Directory::LetsEncrypt,
            contact: Vec::new(),
            challenge: ChallengeKind::TlsAlpn01,
            profile: None,
            profile_optional: false,
            dns_wait: Duration::from_secs(30),
            ari: true,
            retry: RetryPolicy::new().timeout(Duration::from_secs(120)),
        }
    }

    /// Checks the names, set id and challenge.
    pub fn validate(&self) -> Result<()> {
        store::check_key(&self.set).map_err(|_| Error::Config(format!("bad certificate set id {:?}", self.set)))?;
        if self.set.contains('/') {
            return Err(Error::Config(format!("bad certificate set id {:?}", self.set)));
        }
        if self.names.is_empty() {
            return Err(Error::Config("no names to certify".into()));
        }
        for n in &self.names {
            if !cert::valid_name(n, true) {
                return Err(Error::Config(format!("{n:?} is not a DNS name a CA can certify")));
            }
            if n.starts_with("*.") && self.challenge != ChallengeKind::Dns01 {
                return Err(Error::Config(format!("{n} is a wildcard: wildcards need dns-01")));
            }
        }
        for c in &self.contact {
            if !c.contains('@') || c.contains(char::is_whitespace) {
                return Err(Error::Config(format!("{c:?} is not an email address")));
            }
        }
        Ok(())
    }
}

type ClientFactory = Arc<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

/// One certificate set kept current from an ACME CA.
pub struct Acme {
    cfg: AcmeConfig,
    store: Arc<dyn CertStore>,
    resolver: Arc<Resolver>,
    http01: Arc<Http01Board>,
    dns: Option<Arc<dyn DnsChallenge>>,
    client: Option<ClientFactory>,
    status: watch::Sender<Status>,
    wake: Notify,
    busy: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Acme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acme").field("cfg", &self.cfg).field("status", &*self.status.borrow()).finish()
    }
}

impl Acme {
    /// Keeps `cfg` current in `store`, serving through `resolver`.
    pub fn new(cfg: AcmeConfig, store: Arc<dyn CertStore>, resolver: Arc<Resolver>) -> Result<Self> {
        cfg.validate()?;
        let status = watch::Sender::new(Status::missing(&cfg.set, &cfg.names));
        Ok(Self {
            cfg,
            store,
            resolver,
            http01: Arc::new(Http01Board::new()),
            dns: None,
            client: None,
            status,
            wake: Notify::new(),
            busy: tokio::sync::Mutex::new(()),
        })
    }

    /// Publishes HTTP-01 answers on `board` (by default a board of its own, see [`Acme::http01`]).
    pub fn with_http01(mut self, board: Arc<Http01Board>) -> Self {
        self.http01 = board;
        self
    }

    /// Publishes DNS-01 records through `dns`.
    pub fn with_dns(mut self, dns: Arc<dyn DnsChallenge>) -> Self {
        self.dns = Some(dns);
        self
    }

    /// Talks to the CA through clients from `f` (tests, proxies) instead of hyper-rustls.
    pub fn with_http_client(mut self, f: impl Fn() -> Box<dyn HttpClient> + Send + Sync + 'static) -> Self {
        self.client = Some(Arc::new(f));
        self
    }

    /// The configuration.
    pub fn config(&self) -> &AcmeConfig {
        &self.cfg
    }

    /// The resolver certificates are installed in.
    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }

    /// The HTTP-01 board; serve it with [`crate::challenge::serve_http01`] or your router.
    pub fn http01(&self) -> &Arc<Http01Board> {
        &self.http01
    }

    /// The current status.
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }

    /// Status updates.
    pub fn watch(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    /// Wakes the background renewer to check now.
    pub fn trigger(&self) {
        self.wake.notify_one();
    }

    fn persisted(&self) -> Persisted {
        store::get_json(&*self.store, &store::state_key(&self.cfg.set)).ok().flatten().unwrap_or_default()
    }

    fn save_persisted(&self, st: &Persisted) -> Result<()> {
        store::put_json(&*self.store, &store::state_key(&self.cfg.set), st)
    }

    /// The stored certificate, if any (not checked against the names).
    pub fn stored(&self) -> Result<Option<(CertPair, CertInfo)>> {
        match store::load_cert(&*self.store, &self.cfg.set)? {
            Some(p) => {
                let (_, i) = cert::certified_key(&p)?;
                Ok(Some((p, i)))
            }
            None => Ok(None),
        }
    }

    /// Installs the stored certificate in the resolver and updates the status.
    pub fn load(&self) -> Result<Option<CertInfo>> {
        let cur = match self.stored()? {
            Some((p, _)) => Some(self.resolver.set(Source::Acme, &p)?),
            None => None,
        };
        let st = self.persisted();
        self.publish(&st, cur.as_ref(), None, false, None);
        Ok(cur)
    }

    fn publish(&self, st: &Persisted, cur: Option<&CertInfo>, next: Option<SystemTime>, ari: bool, busy: Option<State>) {
        let now = SystemTime::now();
        let state = busy.unwrap_or(match cur {
            None if st.failures > 0 => State::Failing,
            None => State::Missing,
            Some(c) if c.expired(now) => State::Expired,
            Some(_) if st.failures > 0 => State::Failing,
            Some(_) => State::Valid,
        });
        self.status.send_replace(Status {
            set: self.cfg.set.clone(),
            names: self.cfg.names.clone(),
            state,
            source: cur.map(|_| Source::Acme),
            not_after: cur.map(|c| c.not_after),
            next_attempt: next,
            failures: st.failures,
            last_error: st.last_error.clone(),
            ari,
        });
    }

    fn builder(&self) -> Result<instant_acme::AccountBuilder> {
        Ok(match &self.client {
            Some(f) => Account::builder_with_http(f()),
            None => Account::builder()?,
        })
    }

    /// The ACME account for the directory, registered on first use and kept in the store.
    pub async fn account(&self) -> Result<Account> {
        let dir = self.cfg.directory.url();
        let key = store::account_key(dir);
        if let Some(creds) = store::get_json::<AccountCredentials>(&*self.store, &key)? {
            return Ok(self.builder()?.from_credentials(creds).await?);
        }
        let contact: Vec<String> = self.cfg.contact.iter().map(|e| format!("mailto:{e}")).collect();
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        let new = NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false };
        let (acct, creds) = self.builder()?.create(&new, dir.to_string(), None).await?;
        store::put_json(&*self.store, &key, &creds)?;
        Ok(acct)
    }

    /// When the current certificate should be renewed, and whether ARI said so.
    pub async fn due(&self, now: SystemTime) -> Result<(SystemTime, bool)> {
        let Some((_, cur)) = self.stored()? else { return Ok((now, false)) };
        if !self.cfg.names.iter().all(|n| cur.names.contains(&cert::normalize(n))) {
            return Ok((now, false));
        }
        let fallback = renew::fallback(cur.not_before, cur.not_after);
        let (Some(id), true) = (cur.ari_id.clone(), self.cfg.ari) else { return Ok((fallback, false)) };
        let mut st = self.persisted();
        let cached = st.ari.as_ref().filter(|(i, _)| *i == id).map(|(_, w)| *w);
        let window = match (cached, st.ari_recheck) {
            (Some(w), Some(t)) if t > now => Some(w),
            _ => match self.fetch_ari(&cur).await {
                Ok(Some((w, retry))) => {
                    st.ari = Some((id, w));
                    st.ari_recheck = Some(now + retry);
                    self.save_persisted(&st)?;
                    Some(w)
                }
                Ok(None) => None,
                Err(e) => {
                    tracing::debug!(set = %self.cfg.set, "ARI: {e}");
                    cached
                }
            },
        };
        Ok(match window {
            Some(w) => (renew::pick(w, &cur.serial), true),
            None => (fallback, false),
        })
    }

    async fn fetch_ari(&self, cur: &CertInfo) -> Result<Option<(Window, Duration)>> {
        let Some(id) = cur.ari() else { return Ok(None) };
        let acct = self.account().await?;
        match acct.renewal_info(&id).await {
            Ok((info, retry)) => {
                let w = Window { start: info.suggested_window.start.into(), end: info.suggested_window.end.into() };
                let retry =
                    if retry.is_zero() { renew::ARI_DEFAULT_RECHECK } else { retry.clamp(Duration::from_secs(60), Duration::from_secs(86400)) };
                Ok(Some((w, retry)))
            }
            Err(instant_acme::Error::Unsupported(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// One renewal pass: issues when due (or now if `force`), else says when it will be due.
    /// A forced renewal within [`renew::FORCE_MIN_AGE`] of the last issue fails with
    /// [`Error::TooSoon`]. A failure keeps the served certificate and backs off.
    pub async fn renew_once(&self, force: bool) -> Result<Outcome> {
        let _g = self.busy.lock().await;
        let now = SystemTime::now();
        let mut st = self.persisted();
        let cur = self.stored().ok().flatten().map(|(_, i)| i);
        if force {
            if let Some(t) = st.last_issued
                && now < t + renew::FORCE_MIN_AGE
            {
                return Err(Error::TooSoon(t + renew::FORCE_MIN_AGE));
            }
        } else {
            let (due, ari) = self.due(now).await.unwrap_or((now, false));
            st = self.persisted();
            let next = renew::next_attempt(due, &st);
            if next > now {
                self.publish(&st, cur.as_ref(), Some(next), ari, None);
                return Ok(Outcome::NotDue(next));
            }
        }
        self.publish(&st, cur.as_ref(), None, false, Some(State::Issuing));
        match self.issue().await {
            Ok(info) => {
                st = Persisted { last_issued: Some(SystemTime::now()), ..Default::default() };
                self.save_persisted(&st)?;
                let next = renew::fallback(info.not_before, info.not_after);
                self.publish(&st, Some(&info), Some(next), false, None);
                tracing::info!(set = %self.cfg.set, names = ?info.names, "certificate issued");
                Ok(Outcome::Renewed(info))
            }
            Err(e) => {
                st.failures += 1;
                st.last_failure = Some(SystemTime::now());
                st.last_error = Some(e.to_string());
                self.save_persisted(&st)?;
                let next = st.last_failure.map(|t| t + renew::backoff(st.failures));
                self.publish(&st, cur.as_ref(), next, false, None);
                tracing::warn!(set = %self.cfg.set, failures = st.failures, "certificate order failed: {e}");
                Err(e)
            }
        }
    }

    /// Runs renewal passes until the task is aborted: issues when due, sleeps until the next
    /// check (at most an hour), and wakes early on [`Acme::trigger`].
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.load() {
                tracing::warn!(set = %self.cfg.set, "loading the stored certificate: {e}");
            }
            loop {
                let wait = match self.renew_once(false).await {
                    Ok(Outcome::NotDue(t)) => t.duration_since(SystemTime::now()).unwrap_or_default(),
                    Ok(Outcome::Renewed(_)) => Duration::ZERO,
                    Err(_) => self.status().next_attempt.and_then(|t| t.duration_since(SystemTime::now()).ok()).unwrap_or(renew::BACKOFF_MIN),
                };
                let wait = wait.clamp(Duration::from_secs(1), Duration::from_secs(3600));
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = self.wake.notified() => {}
                }
            }
        })
    }

    /// Orders a certificate now, installs it in the resolver and saves it. Prefer
    /// [`Acme::renew_once`], which applies backoff and records the status.
    pub async fn issue(&self) -> Result<CertInfo> {
        let acct = self.account().await?;
        let names: Vec<String> = self.cfg.names.iter().map(|n| cert::normalize(n)).collect();
        let ids: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
        let replaces = if self.cfg.ari { self.stored().ok().flatten().and_then(|(_, i)| i.ari()) } else { None };
        let new = |r: Option<instant_acme::CertificateIdentifier<'static>>, with_profile: bool| {
            let mut o = NewOrder::new(&ids);
            if let Some(p) = self.cfg.profile.as_ref().filter(|_| with_profile) {
                o = o.profile(p);
            }
            if let Some(r) = r {
                o = o.replaces(r);
            }
            o
        };
        // CAs refuse `replaces` without ARI, or for a cert already replaced: then order
        // without it. With `profile_optional`, a refused profile falls back to the default.
        let mut attempts = vec![(replaces.clone(), true)];
        if replaces.is_some() {
            attempts.push((None, true));
        }
        if self.cfg.profile.is_some() && self.cfg.profile_optional {
            attempts.push((None, false));
        }
        let mut order = None;
        let mut last = None;
        for (r, with_profile) in attempts {
            match acct.new_order(&new(r, with_profile)).await {
                Ok(o) => {
                    order = Some(o);
                    break;
                }
                Err(e) => {
                    tracing::debug!(set = %self.cfg.set, "order failed ({e}); trying the next way");
                    last = Some(e);
                }
            }
        }
        let mut order = match (order, last) {
            (Some(o), _) => o,
            (None, Some(e)) => return Err(e.into()),
            (None, None) => return Err(Error::Acme("no order".into())),
        };

        let mut alpn: Vec<String> = Vec::new();
        let mut tokens: Vec<String> = Vec::new();
        let mut records: Vec<DnsRecord> = Vec::new();
        let res = async {
            // Publish every answer first, then (after the DNS wait) tell the CA to look.
            let mut pending = 0;
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a?;
                match a.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    s => return Err(Error::Acme(format!("authorization is {s:?}"))),
                }
                let kind = self.cfg.challenge;
                let ch = a.challenge(kind.acme()).ok_or_else(|| Error::Acme(format!("the CA does not offer {}", kind.as_str())))?;
                let id = ch.identifier().to_string();
                let ka = ch.key_authorization();
                match kind {
                    ChallengeKind::TlsAlpn01 => {
                        let name = cert::normalize(&id);
                        self.resolver.set_alpn(&name, cert::alpn_cert(&name, ka.digest().as_ref())?);
                        alpn.push(name);
                    }
                    ChallengeKind::Http01 => {
                        self.http01.insert(&ch.token, ka.as_str());
                        tokens.push(ch.token.clone());
                    }
                    ChallengeKind::Dns01 => {
                        let dns = self.dns.as_ref().ok_or_else(|| Error::Config("dns-01 needs a DnsChallenge (with_dns)".into()))?;
                        let r = DnsRecord::new(&id, &ka.dns_value());
                        dns.present(&r).await?;
                        records.push(r);
                    }
                }
                pending += 1;
            }
            if pending > 0 && !records.is_empty() && !self.cfg.dns_wait.is_zero() {
                tokio::time::sleep(self.cfg.dns_wait).await;
            }
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a?;
                if a.status != AuthorizationStatus::Pending {
                    continue;
                }
                let mut ch = a.challenge(self.cfg.challenge.acme()).ok_or_else(|| Error::Acme("challenge vanished".into()))?;
                ch.set_ready().await?;
            }
            let st = order.poll_ready(&self.cfg.retry).await.map_err(|e| Error::Acme(format!("validation failed: {e}")))?;
            if st != OrderStatus::Ready {
                let why = order.state().error.as_ref().map(|p| p.to_string()).unwrap_or_default();
                return Err(Error::Acme(format!("validation failed: the order is {st:?} {why}").trim().to_string()));
            }
            let (csr, key_pem) = cert::csr(&names)?;
            order.finalize_csr(&csr).await?;
            let chain_pem = order.poll_certificate(&self.cfg.retry).await?;
            Ok(CertPair { chain_pem, key_pem })
        }
        .await;
        for n in &alpn {
            self.resolver.remove_alpn(n);
        }
        for t in &tokens {
            self.http01.remove(t);
        }
        if let Some(dns) = &self.dns {
            for r in &records {
                if let Err(e) = dns.cleanup(r).await {
                    tracing::warn!(record = %r.name, "DNS cleanup: {e}");
                }
            }
        }
        let pair = res?;
        let (_, info) = cert::certified_key(&pair)?;
        for n in &self.cfg.names {
            if !info.covers(n.trim_start_matches("*.")) && !info.names.contains(&cert::normalize(n)) {
                return Err(Error::Acme(format!("the CA's certificate does not cover {n}")));
            }
        }
        store::save_cert(&*self.store, &self.cfg.set, &pair)?;
        self.resolver.set(Source::Acme, &pair)?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_checked() {
        let ok = AcmeConfig::new("main", vec!["a.example.com".into()]);
        ok.validate().unwrap();
        let mut c = ok.clone();
        c.names = vec!["*.example.com".into()];
        assert!(c.validate().unwrap_err().to_string().contains("dns-01"));
        c.challenge = ChallengeKind::Dns01;
        c.validate().unwrap();
        for bad in ["", "a/b", "Main"] {
            let mut c = ok.clone();
            c.set = bad.into();
            assert!(c.validate().is_err(), "{bad:?}");
        }
        let mut c = ok.clone();
        c.names.clear();
        assert!(c.validate().is_err());
        let mut c = ok.clone();
        c.contact = vec!["nope".into()];
        assert!(c.validate().is_err());
        assert_eq!(Directory::LetsEncryptStaging.url(), LETS_ENCRYPT_STAGING);
    }
}
