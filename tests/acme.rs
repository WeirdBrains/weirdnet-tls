//! End-to-end ACME against the mock CA, with real challenge answers.

use instant_acme::RetryPolicy;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use weirdnet_tls::renew::Window;
use weirdnet_tls::testing::{MockCa, MockDns};
use weirdnet_tls::*;

fn names(n: &[&str]) -> Vec<String> {
    n.iter().map(|s| s.to_string()).collect()
}

fn config(set: &str, n: &[&str], kind: ChallengeKind) -> AcmeConfig {
    let mut c = AcmeConfig::new(set, names(n));
    c.directory = Directory::Custom(MockCa::DIRECTORY.into());
    c.contact = vec!["ops@example.com".into()];
    c.challenge = kind;
    c.dns_wait = Duration::ZERO;
    c.retry = RetryPolicy::new().initial_delay(Duration::from_millis(5)).timeout(Duration::from_secs(5));
    c
}

fn acme(ca: &MockCa, cfg: AcmeConfig, store: Arc<dyn CertStore>, resolver: Arc<Resolver>) -> Acme {
    let ca = ca.clone();
    Acme::new(cfg, store, resolver).unwrap().with_http_client(move || ca.client())
}

/// A blocking TLS listener on the resolver (what an app's port 443 would be).
fn tls_listener(resolver: &Arc<Resolver>) -> SocketAddr {
    let cfg = resolver.server_config(&[b"http/1.1"]).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let Ok(mut c) = rustls::ServerConnection::new(cfg) else { return };
                while c.is_handshaking() {
                    if c.complete_io(&mut s).is_err() {
                        return;
                    }
                }
                let _ = c.complete_io(&mut s);
            });
        }
    });
    addr
}

/// A normal client handshake for `sni`, trusting only `root_pem`; the leaf it got.
fn verified_leaf(addr: SocketAddr, sni: &str, root_pem: &str) -> Result<Vec<u8>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for c in weirdnet_tls::cert::parse_chain(root_pem).unwrap() {
        roots.add(c).unwrap();
    }
    let mut cc = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cc), name).unwrap();
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut s).map_err(|e| e.to_string())?;
    }
    Ok(conn.peer_certificates().unwrap()[0].to_vec())
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_alpn_issue_serve_and_schedule() {
    let ca = MockCa::new();
    let n = ["a.example.com", "b.example.com"];
    let resolver = Arc::new(Resolver::with_self_signed(&names(&n)).unwrap());
    let addr = tls_listener(&resolver);
    ca.validate_tls_alpn_at(addr);
    let store: Arc<dyn CertStore> = Arc::new(MemoryStore::new());
    let a = acme(&ca, config("main", &n, ChallengeKind::TlsAlpn01), store.clone(), resolver.clone());
    assert_eq!(a.status().state, State::Missing);

    // Before: the self-signed cert, which the CA root does not sign.
    let root = ca.root_pem();
    let r2 = root.clone();
    assert!(blocking(move || verified_leaf(addr, "b.example.com", &r2)).await.is_err());

    let Outcome::Renewed(info) = a.renew_once(false).await.unwrap() else { panic!("not issued") };
    assert_eq!(info.names, names(&n));
    assert_eq!(ca.validations(), vec![("a.example.com".into(), "tls-alpn-01".into()), ("b.example.com".into(), "tls-alpn-01".into())]);
    assert!(!resolver.has_alpn("a.example.com") && !resolver.has_alpn("b.example.com"), "answers withdrawn");
    assert_eq!(resolver.lookup(Some("a.example.com")).unwrap().0, Source::Acme);
    let r2 = root.clone();
    let leaf = blocking(move || verified_leaf(addr, "b.example.com", &r2)).await.unwrap();
    assert_eq!(leaf, info.der, "the new cert is served on the next handshake");
    let st = a.status();
    assert_eq!((st.state, st.source, st.not_after, st.failures), (State::Valid, Some(Source::Acme), Some(info.not_after), 0));

    // Next: inside the CA's ARI window (2/3 to 3/4 of the lifetime), fetched once.
    let Outcome::NotDue(t) = a.renew_once(false).await.unwrap() else { panic!("renewed again") };
    let life = info.lifetime();
    assert!(t >= info.not_before + life * 2 / 3 && t < info.not_before + life * 3 / 4, "{t:?}");
    assert!(a.status().ari);
    a.renew_once(false).await.unwrap();
    assert_eq!(ca.ari_requests(), 1, "the window is cached until Retry-After");

    // Forcing right after an issue is refused.
    assert!(matches!(a.renew_once(true).await, Err(Error::TooSoon(_))));

    // A restart serves the stored cert and reuses the account.
    let r3 = Arc::new(Resolver::new());
    let b = acme(&ca, config("main", &n, ChallengeKind::TlsAlpn01), store.clone(), r3.clone());
    assert_eq!(b.load().unwrap().unwrap().der, info.der);
    assert_eq!(b.status().state, State::Valid);
    assert_eq!(r3.lookup(Some("a.example.com")).unwrap().0, Source::Acme);
    b.account().await.unwrap();
    assert_eq!(ca.accounts(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn http01_and_ari_replaces() {
    let ca = MockCa::new();
    let resolver = Arc::new(Resolver::new());
    let store: Arc<dyn CertStore> = Arc::new(MemoryStore::new());
    let mut cfg = config("web", &["www.example.com"], ChallengeKind::Http01);
    cfg.profile = Some("shortlived".into());
    let a = acme(&ca, cfg, store, resolver.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    ca.validate_http01_at(l.local_addr().unwrap());
    let _srv = challenge::serve_http01(l, a.http01().clone());

    let Outcome::Renewed(first) = a.renew_once(false).await.unwrap() else { panic!() };
    assert!(a.http01().is_empty(), "tokens withdrawn");
    assert_eq!(ca.validations(), vec![("www.example.com".into(), "http-01".into())]);

    // The CA moves the window into the past: due now, and the order says what it replaces.
    let past = SystemTime::now() - Duration::from_secs(3600);
    ca.set_window(Some(Window { start: past, end: past + Duration::from_secs(60) }));
    // The forced-renew guard does not apply to scheduled renewals.
    let Outcome::Renewed(second) = a.renew_once(false).await.unwrap() else { panic!("not renewed") };
    assert_ne!(first.serial, second.serial);
    let orders = ca.orders();
    assert_eq!(orders.len(), 2, "{orders:#?}");
    assert_eq!(orders[0].replaces, None);
    assert_eq!(orders[1].replaces, first.ari_id);
    assert_eq!(orders[1].profile.as_deref(), Some("shortlived"));
}

#[tokio::test(flavor = "multi_thread")]
async fn dns01_wildcard() {
    let ca = MockCa::new();
    let dns = Arc::new(MockDns::new());
    ca.validate_dns01_with(dns.clone());
    let resolver = Arc::new(Resolver::new());
    let a = acme(&ca, config("wild", &["*.example.com", "example.com"], ChallengeKind::Dns01), Arc::new(MemoryStore::new()), resolver.clone());
    // Without a publisher, dns-01 fails and says why.
    let e = a.renew_once(false).await.unwrap_err();
    assert!(e.to_string().contains("DnsChallenge"), "{e}");
    let a = acme(&ca, config("wild", &["*.example.com", "example.com"], ChallengeKind::Dns01), Arc::new(MemoryStore::new()), resolver.clone())
        .with_dns(dns.clone());
    let Outcome::Renewed(info) = a.renew_once(false).await.unwrap() else { panic!() };
    assert_eq!(info.names, names(&["*.example.com", "example.com"]));
    assert_eq!(resolver.lookup(Some("x.example.com")).unwrap().0, Source::Acme);
    assert_eq!(
        dns.log(),
        names(&[
            "present _acme-challenge.example.com",
            "present _acme-challenge.example.com",
            "cleanup _acme-challenge.example.com",
            "cleanup _acme-challenge.example.com"
        ])
    );
    assert!(dns.txt("_acme-challenge.example.com").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_keep_the_cert_and_back_off() {
    let ca = MockCa::new();
    ca.set_ari(false);
    let dns = Arc::new(MockDns::new());
    ca.validate_dns01_with(dns.clone());
    let resolver = Arc::new(Resolver::new());
    let store: Arc<dyn CertStore> = Arc::new(MemoryStore::new());
    let a = acme(&ca, config("f", &["f.example.com"], ChallengeKind::Dns01), store.clone(), resolver.clone()).with_dns(dns.clone());

    let Outcome::Renewed(info) = a.renew_once(false).await.unwrap() else { panic!() };
    // No ARI: two thirds of the lifetime.
    let Outcome::NotDue(t) = a.renew_once(false).await.unwrap() else { panic!() };
    assert_eq!(t, renew::fallback(info.not_before, info.not_after));
    assert!(!a.status().ari);

    // A short-lived cert that is due now, and a CA that refuses.
    ca.set_lifetime(Duration::from_secs(3));
    let mut s = store::get_json::<renew::Persisted>(&*store, &store::state_key("f")).unwrap().unwrap();
    s.last_issued = Some(SystemTime::now() - Duration::from_secs(2 * 86400));
    store::put_json(&*store, &store::state_key("f"), &s).unwrap();
    let Outcome::Renewed(short) = a.renew_once(true).await.unwrap() else { panic!() };
    tokio::time::sleep(Duration::from_secs(3)).await;
    ca.set_fail(true);
    let before = SystemTime::now();
    let e = a.renew_once(false).await.unwrap_err();
    assert!(e.to_string().contains("validation failed"), "{e}");
    let st = a.status();
    assert_eq!((st.state, st.failures), (State::Expired, 1));
    assert!(st.last_error.unwrap().contains("fails every validation"));
    let next = st.next_attempt.unwrap();
    assert!(next >= before + Duration::from_secs(3600) && next < before + Duration::from_secs(3700), "{next:?}");
    // The old cert is still served, never nothing.
    let (src, k) = resolver.lookup(Some("f.example.com")).unwrap();
    assert_eq!((src, k.end_entity_cert().unwrap().to_vec()), (Source::Acme, short.der.clone()));
    // Backed off: the next pass waits.
    assert_eq!(a.renew_once(false).await.unwrap(), Outcome::NotDue(next));
    assert_eq!(ca.orders().len(), 3);
    // The failure count survives a restart.
    let b = acme(&ca, config("f", &["f.example.com"], ChallengeKind::Dns01), store, Arc::new(Resolver::new()));
    b.load().unwrap();
    assert_eq!(b.status().failures, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn background_renewer_issues_and_reports() {
    let ca = MockCa::new();
    let dns = Arc::new(MockDns::new());
    ca.validate_dns01_with(dns.clone());
    let d = tempfile::tempdir().unwrap();
    let store: Arc<dyn CertStore> = Arc::new(FileStore::new(d.path()));
    let a = Arc::new(acme(&ca, config("bg", &["bg.example.com"], ChallengeKind::Dns01), store, Arc::new(Resolver::new())).with_dns(dns));
    let mut rx = a.watch();
    let h = a.clone().spawn();
    tokio::time::timeout(Duration::from_secs(10), rx.wait_for(|s| s.state == State::Valid && s.next_attempt.is_some())).await.unwrap().unwrap();
    h.abort();
    assert_eq!(ca.issued(), 1);
    assert!(d.path().join("cert/bg.json").exists() && d.path().join("state/bg.json").exists());
    assert_eq!(std::fs::read_dir(d.path().join("account")).unwrap().count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_profile_falls_back_only_when_optional() {
    let ca = MockCa::new();
    let resolver = Arc::new(Resolver::new());
    let mut cfg = config("web", &["www.example.com"], ChallengeKind::Http01);
    cfg.profile = Some("nonesuch".into());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    ca.validate_http01_at(l.local_addr().unwrap());
    let strict = acme(&ca, cfg.clone(), Arc::new(MemoryStore::new()), resolver.clone());
    assert!(strict.issue().await.is_err(), "refused profile, no fallback");
    cfg.profile_optional = true;
    let a = acme(&ca, cfg, Arc::new(MemoryStore::new()), resolver.clone());
    let _srv = challenge::serve_http01(l, a.http01().clone());
    a.issue().await.unwrap();
    let orders = ca.orders();
    assert_eq!(orders.last().unwrap().profile, None, "{orders:#?}");
}
