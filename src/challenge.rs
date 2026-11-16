//! Publishing challenge answers: the HTTP-01 board and listener, and DNS-01 publishers.
//!
//! TLS-ALPN-01 answers live in the [`crate::Resolver`].

use crate::{Error, Result};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The path prefix of HTTP-01 answers.
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

/// HTTP-01 answers by token. Answer from your own HTTP router with [`Http01Board::answer`], or
/// let [`serve_http01`] run a listener that serves only these.
#[derive(Debug, Default)]
pub struct Http01Board(Mutex<HashMap<String, String>>);

impl Http01Board {
    /// An empty board.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert(&self, token: &str, key_authorization: &str) {
        self.0.lock().unwrap().insert(token.to_string(), key_authorization.to_string());
    }

    pub(crate) fn remove(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }

    /// The body for a request to `path`, if it is a published `/.well-known/acme-challenge/`
    /// token. Serve it as `200 text/plain`.
    pub fn answer(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(HTTP01_PREFIX)?;
        self.0.lock().unwrap().get(token).cloned()
    }

    /// The number of published tokens.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// True when no token is published.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Serves HTTP-01 answers from `board` on `listener` (port 80): `200` with the key
/// authorization for published tokens, `404` for everything else. It never serves other
/// content, and never redirects.
pub fn serve_http01(listener: tokio::net::TcpListener, board: Arc<Http01Board>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { continue };
            let board = board.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                let head = tokio::time::timeout(Duration::from_secs(10), async {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                })
                .await;
                if head.is_err() {
                    return;
                }
                let line = String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string();
                let mut parts = line.split_whitespace();
                let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let body = if method == "GET" || method == "HEAD" { board.answer(path) } else { None };
                let resp = match body {
                    Some(b) => {
                        let b = if method == "HEAD" { String::new() } else { b };
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                    }
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                };
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    })
}

/// A DNS-01 TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// The name being validated, without `*.` (`example.com` for `*.example.com`).
    pub domain: String,
    /// The record name, `_acme-challenge.` and the domain.
    pub name: String,
    /// The TXT value.
    pub value: String,
}

impl DnsRecord {
    /// The record for `identifier` (wildcard or not) and TXT `value`.
    pub fn new(identifier: &str, value: &str) -> Self {
        let domain = crate::cert::normalize(identifier.trim_start_matches("*."));
        Self { name: format!("_acme-challenge.{domain}"), domain, value: value.to_string() }
    }
}

/// Publishes and withdraws DNS-01 TXT records.
pub trait DnsChallenge: Send + Sync {
    /// Publishes `record`; return once it is published (propagation is waited for separately).
    fn present<'a>(&'a self, record: &'a DnsRecord) -> BoxFuture<'a, Result<()>>;
    /// Withdraws `record` after validation. Errors are logged, not fatal.
    fn cleanup<'a>(&'a self, record: &'a DnsRecord) -> BoxFuture<'a, Result<()>>;
}

/// Runs a command for each record: `sh -c COMMAND` (`cmd /C` on Windows) with
/// `WEIRDNET_TLS_ACTION` (`present` or `cleanup`), `WEIRDNET_TLS_DOMAIN`, `WEIRDNET_TLS_NAME`
/// and `WEIRDNET_TLS_TXT` in the environment. A non-zero exit fails the step.
#[derive(Debug, Clone)]
pub struct HookDns {
    /// The command line.
    pub command: String,
}

impl HookDns {
    /// A hook running `command`.
    pub fn new(command: impl Into<String>) -> Self {
        Self { command: command.into() }
    }

    async fn run(&self, action: &str, r: &DnsRecord) -> Result<()> {
        #[cfg(windows)]
        let mut c = {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(&self.command);
            c
        };
        #[cfg(not(windows))]
        let mut c = {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(&self.command);
            c
        };
        let st = c
            .env("WEIRDNET_TLS_ACTION", action)
            .env("WEIRDNET_TLS_DOMAIN", &r.domain)
            .env("WEIRDNET_TLS_NAME", &r.name)
            .env("WEIRDNET_TLS_TXT", &r.value)
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|e| Error::Challenge(format!("running the DNS hook: {e}")))?;
        if st.success() { Ok(()) } else { Err(Error::Challenge(format!("the DNS hook's {action} for {} failed ({st})", r.name))) }
    }
}

impl DnsChallenge for HookDns {
    fn present<'a>(&'a self, record: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.run("present", record))
    }
    fn cleanup<'a>(&'a self, record: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.run("cleanup", record))
    }
}

type Prompt = dyn Fn(&DnsRecord) -> Result<()> + Send + Sync;

/// Asks a person to add the record: calls `prompt` on a blocking thread (a CLI can print the
/// record and wait for Enter) and returns once it does. Cleanup is left to the person.
#[derive(Clone)]
pub struct ManualDns(Arc<Prompt>);

impl ManualDns {
    /// A publisher calling `prompt`.
    pub fn new(prompt: impl Fn(&DnsRecord) -> Result<()> + Send + Sync + 'static) -> Self {
        Self(Arc::new(prompt))
    }
}

impl std::fmt::Debug for ManualDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManualDns")
    }
}

impl DnsChallenge for ManualDns {
    fn present<'a>(&'a self, record: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
        let (f, r) = (self.0.clone(), record.clone());
        Box::pin(async move { tokio::task::spawn_blocking(move || f(&r)).await.map_err(|e| Error::Challenge(e.to_string()))? })
    }
    fn cleanup<'a>(&'a self, _: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(feature = "grindvakt")]
pub use gv::GrindvaktDns;

#[cfg(feature = "grindvakt")]
mod gv {
    use super::{BoxFuture, DnsChallenge, DnsRecord};
    use crate::{Error, Result};
    use grindvakt_core::provider::DnsProvider;
    use grindvakt_core::record::{RecordKind, RecordValue};

    /// DNS-01 through a grindvakt-core [`DnsProvider`] (DNSimple, DigitalOcean, or your own).
    ///
    /// The record is keyed by name: an existing `_acme-challenge` TXT record is updated, else
    /// one is created. grindvakt-core providers cannot delete records, so cleanup leaves the
    /// last value in place; it is harmless (CAs check the value of the current order) and the
    /// next renewal overwrites it.
    pub struct GrindvaktDns<P> {
        provider: P,
        zone: String,
        ttl: u32,
    }

    impl<P: DnsProvider + Send + Sync> GrindvaktDns<P> {
        /// Publishes in `zone` (such as `example.com`) through `provider`, TTL 60 seconds.
        pub fn new(provider: P, zone: impl Into<String>) -> Self {
            Self { provider, zone: crate::cert::normalize(&zone.into()), ttl: 60 }
        }

        /// Sets the TTL (seconds).
        pub fn ttl(mut self, ttl: u32) -> Self {
            self.ttl = ttl;
            self
        }

        /// The record name relative to the zone.
        pub fn relative(&self, name: &str) -> Result<String> {
            let n = crate::cert::normalize(name);
            if n == self.zone {
                return Ok(String::new());
            }
            n.strip_suffix(&format!(".{}", self.zone))
                .map(str::to_string)
                .ok_or_else(|| Error::Challenge(format!("{n} is not in zone {}", self.zone)))
        }

        async fn publish(&self, r: &DnsRecord) -> Result<()> {
            let rel = self.relative(&r.name)?;
            let err = |e: grindvakt_core::Error| Error::Challenge(format!("{}: {e}", self.provider.name()));
            let value = RecordValue::Txt(r.value.clone());
            let existing = self.provider.list(&self.zone, &rel, RecordKind::Txt).await.map_err(err)?;
            match existing.first() {
                Some(e) => self.provider.update(&self.zone, e.id, &value, self.ttl).await.map_err(err),
                None => self.provider.create(&self.zone, &rel, &value, self.ttl).await.map_err(err),
            }
        }
    }

    impl<P: DnsProvider + Send + Sync> DnsChallenge for GrindvaktDns<P> {
        fn present<'a>(&'a self, record: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
            Box::pin(self.publish(record))
        }
        fn cleanup<'a>(&'a self, _: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use grindvakt_core::record::ExistingRecord;
        use std::future::Future;
        use std::sync::Mutex;

        #[derive(Default)]
        struct Fake(Mutex<Vec<ExistingRecord>>, Mutex<Vec<String>>);

        impl DnsProvider for Fake {
            fn name(&self) -> &str {
                "fake"
            }
            fn list(&self, zone: &str, name: &str, kind: RecordKind) -> impl Future<Output = grindvakt_core::Result<Vec<ExistingRecord>>> + Send {
                self.1.lock().unwrap().push(format!("list {zone} {name} {}", kind.as_str()));
                let v = self.0.lock().unwrap().iter().filter(|r| r.name == name && r.value.kind() == kind).cloned().collect();
                async { Ok(v) }
            }
            fn create(&self, zone: &str, name: &str, value: &RecordValue, ttl: u32) -> impl Future<Output = grindvakt_core::Result<()>> + Send {
                self.1.lock().unwrap().push(format!("create {zone} {name} {ttl}"));
                let mut g = self.0.lock().unwrap();
                let id = g.len() as u64 + 1;
                g.push(ExistingRecord { id, name: name.into(), value: value.clone(), ttl: Some(ttl) });
                async { Ok(()) }
            }
            fn update(&self, zone: &str, id: u64, value: &RecordValue, ttl: u32) -> impl Future<Output = grindvakt_core::Result<()>> + Send {
                self.1.lock().unwrap().push(format!("update {zone} {id} {ttl}"));
                for r in self.0.lock().unwrap().iter_mut().filter(|r| r.id == id) {
                    r.value = value.clone();
                }
                async { Ok(()) }
            }
        }

        #[tokio::test]
        async fn creates_then_overwrites() {
            let g = GrindvaktDns::new(Fake::default(), "Example.com").ttl(120);
            assert_eq!(g.relative("_acme-challenge.a.example.com").unwrap(), "_acme-challenge.a");
            assert!(g.relative("_acme-challenge.other.test").is_err());
            g.present(&DnsRecord::new("example.com", "one")).await.unwrap();
            g.cleanup(&DnsRecord::new("example.com", "one")).await.unwrap();
            g.present(&DnsRecord::new("*.example.com", "two")).await.unwrap();
            assert_eq!(
                *g.provider.1.lock().unwrap(),
                [
                    "list example.com _acme-challenge TXT",
                    "create example.com _acme-challenge 120",
                    "list example.com _acme-challenge TXT",
                    "update example.com 1 120"
                ]
            );
            let recs = g.provider.0.lock().unwrap();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].value, RecordValue::Txt("two".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_drop_the_wildcard() {
        let r = DnsRecord::new("*.Example.com", "v");
        assert_eq!((r.domain.as_str(), r.name.as_str()), ("example.com", "_acme-challenge.example.com"));
    }

    #[tokio::test]
    async fn http01_serves_only_tokens() {
        let board = Arc::new(Http01Board::new());
        board.insert("tok", "tok.thumb");
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = serve_http01(l, board.clone());
        let get = |path: &'static str| async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let ok = get("/.well-known/acme-challenge/tok").await;
        assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("\r\n\r\ntok.thumb"), "{ok}");
        assert!(get("/.well-known/acme-challenge/other").await.starts_with("HTTP/1.1 404"));
        assert!(get("/").await.starts_with("HTTP/1.1 404"));
        board.remove("tok");
        assert!(get("/.well-known/acme-challenge/tok").await.starts_with("HTTP/1.1 404"));
        h.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hook_gets_the_record() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("out");
        let hook =
            HookDns::new(format!("echo \"$WEIRDNET_TLS_ACTION $WEIRDNET_TLS_DOMAIN $WEIRDNET_TLS_NAME $WEIRDNET_TLS_TXT\" >> {}", out.display()));
        let r = DnsRecord::new("*.example.com", "abc");
        hook.present(&r).await.unwrap();
        hook.cleanup(&r).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "present example.com _acme-challenge.example.com abc\ncleanup example.com _acme-challenge.example.com abc\n"
        );
        assert!(HookDns::new("exit 3").present(&r).await.is_err());
    }

    #[tokio::test]
    async fn manual_waits_for_the_prompt() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let m = ManualDns::new(move |r| {
            s2.lock().unwrap().push(r.name.clone());
            Ok(())
        });
        m.present(&DnsRecord::new("a.example.com", "v")).await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec!["_acme-challenge.a.example.com"]);
    }
}
