//! Running without the app: offline schedules, default certificates, forced triggers,
//! challenge-only listeners and imports, against the mock CA.

use instant_acme::RetryPolicy;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use weirdnet_tls::testing::MockCa;
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

/// An HTTP-01 issuer on its own listener.
async fn http01_acme(ca: &MockCa, cfg: AcmeConfig, store: Arc<dyn CertStore>, resolver: Arc<Resolver>) -> (Acme, tokio::task::JoinHandle<()>) {
    let a = acme(ca, cfg, store, resolver);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    ca.validate_http01_at(l.local_addr().unwrap());
    let h = challenge::serve_http01(l, a.http01().clone());
    (a, h)
}

#[tokio::test(flavor = "multi_thread")]
async fn schedule_reads_the_store_only() {
    let ca = MockCa::new();
    let store: Arc<dyn CertStore> = Arc::new(MemoryStore::new());
    let cfg = config("s", &["s.example.com"], ChallengeKind::Http01);
    let now = SystemTime::now();

    // Nothing stored: due now.
    let s = acme::schedule(&*store, &cfg, now).unwrap();
    assert_eq!((s.cert.is_none(), s.due, s.next_attempt, s.ari, s.failures), (true, now, now, false, 0));
    assert!(s.is_due(now));

    let (a, _srv) = http01_acme(&ca, cfg.clone(), store.clone(), Arc::new(Resolver::new())).await;
    let Outcome::Renewed(info) = a.renew_once(false).await.unwrap() else { panic!() };
    // Before any ARI answer: two thirds into the lifetime.
    let s = acme::schedule(&*store, &cfg, now).unwrap();
    assert_eq!((s.due, s.ari), (renew::fallback(info.not_before, info.not_after), false));
    assert_eq!(s.cert.as_ref().unwrap().serial, info.serial);
    assert!(s.last_issued.is_some());

    // The renewer caches the CA's window; the offline schedule then agrees with it.
    let Outcome::NotDue(t) = a.renew_once(false).await.unwrap() else { panic!() };
    let requests = ca.ari_requests();
    let s = acme::schedule(&*store, &cfg, SystemTime::now()).unwrap();
    assert_eq!((s.due, s.next_attempt, s.ari), (t, t, true));
    assert_eq!(a.schedule(SystemTime::now()).unwrap(), s);
    // ARI off in the config: the fallback again.
    let mut no_ari = cfg.clone();
    no_ari.ari = false;
    assert!(!acme::schedule(&*store, &no_ari, now).unwrap().ari);

    // A fresh Acme reports the next attempt on load, without asking the CA.
    let b = Acme::new(cfg.clone(), store.clone(), Arc::new(Resolver::new())).unwrap();
    b.load().unwrap();
    let st = b.status();
    assert_eq!((st.next_attempt, st.ari), (Some(t), true));
    assert_eq!(ca.ari_requests(), requests);

    // Failures push the attempt past the due time.
    let mut p = store::get_json::<renew::Persisted>(&*store, &store::state_key("s")).unwrap().unwrap();
    let fail = SystemTime::now();
    (p.failures, p.last_failure, p.last_error) = (3, Some(fail), Some("nope".into()));
    store::put_json(&*store, &store::state_key("s"), &p).unwrap();
    let s = acme::schedule(&*store, &cfg, now).unwrap();
    assert_eq!((s.failures, s.last_error.as_deref()), (3, Some("nope")));
    assert_eq!(s.next_attempt, (fail + renew::backoff(3)).max(t));

    // A name the stored certificate lacks: due now.
    let more = config("s", &["s.example.com", "t.example.com"], ChallengeKind::Http01);
    assert_eq!(acme::schedule(&*store, &more, now).unwrap().due, now);
}

#[tokio::test(flavor = "multi_thread")]
async fn acme_cert_can_be_the_default() {
    let ca = MockCa::new();
    let store: Arc<dyn CertStore> = Arc::new(MemoryStore::new());
    let resolver = Arc::new(Resolver::with_self_signed(&names(&["d.example.com"])).unwrap());
    let cfg = config("d", &["d.example.com"], ChallengeKind::Http01);
    let (a, _srv) = http01_acme(&ca, cfg.clone(), store.clone(), resolver.clone()).await;
    let a = a.with_default_cert(true);
    let info = a.issue().await.unwrap();
    for sni in [None, Some("192.0.2.1"), Some("other.example.org")] {
        let (s, k) = resolver.lookup(sni).unwrap();
        assert_eq!((s, k.end_entity_cert().unwrap().to_vec()), (Source::Acme, info.der.clone()), "{sni:?}");
    }
    // Off (the default): the self-signed default stays.
    let r2 = Arc::new(Resolver::with_self_signed(&names(&["d.example.com"])).unwrap());
    Acme::new(cfg.clone(), store.clone(), r2.clone()).unwrap().load().unwrap();
    assert_eq!(r2.lookup(None).unwrap().0, Source::SelfSigned);
    assert_eq!(r2.lookup(Some("d.example.com")).unwrap().0, Source::Acme);
    // A restart with it on serves the stored cert by default at once.
    let r3 = Arc::new(Resolver::new());
    Acme::new(cfg, store, r3.clone()).unwrap().with_default_cert(true).load().unwrap();
    assert_eq!(r3.default_source(), Some(Source::Acme));
    assert_eq!(r3.lookup(None).unwrap().1.end_entity_cert().unwrap().to_vec(), info.der);
}

#[tokio::test(flavor = "multi_thread")]
async fn trigger_renewal_forces_but_keeps_the_guard() {
    let ca = MockCa::new();
    let store: Arc<dyn CertStore> = Arc::new(MemoryStore::new());
    let (a, _srv) = http01_acme(&ca, config("f", &["f.example.com"], ChallengeKind::Http01), store.clone(), Arc::new(Resolver::new())).await;
    let a = Arc::new(a);
    let mut rx = a.watch();
    let h = a.clone().spawn();
    let wait_valid = |rx: &mut tokio::sync::watch::Receiver<Status>, n: usize| {
        let ca = ca.clone();
        let rx = rx.clone();
        async move {
            let mut rx = rx;
            tokio::time::timeout(Duration::from_secs(10), rx.wait_for(|s| s.state == State::Valid && ca.issued() == n)).await.unwrap().unwrap();
        }
    };
    wait_valid(&mut rx, 1).await;
    let first = a.status().not_after;

    // A plain trigger only checks: not due, nothing issued.
    a.trigger();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ca.issued(), 1);

    // Forced within a day of the last issue: the guard holds.
    a.trigger_renewal();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ca.issued(), 1, "repeat-certificate guard");
    assert_eq!(a.status().state, State::Valid);

    // Once the guard has passed, a forced renewal goes through ahead of the schedule.
    let mut p = store::get_json::<renew::Persisted>(&*store, &store::state_key("f")).unwrap().unwrap();
    p.last_issued = Some(SystemTime::now() - 2 * renew::FORCE_MIN_AGE);
    store::put_json(&*store, &store::state_key("f"), &p).unwrap();
    a.trigger_renewal();
    wait_valid(&mut rx, 2).await;
    assert_eq!(ca.issued(), 2);
    assert!(a.status().not_after >= first);
    h.abort();
}
