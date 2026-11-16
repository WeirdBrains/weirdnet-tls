//! A mock ACME CA for tests (feature `testing`).
//!
//! [`MockCa`] speaks enough RFC 8555 and RFC 9773 for instant-acme: directory, nonces,
//! accounts, orders with one authorization per name, challenges, finalize, certificate download
//! and renewal information. It checks the real answers: it fetches HTTP-01 tokens from an
//! address, makes a TLS-ALPN-01 handshake and reads the acmeIdentifier extension, and reads
//! DNS-01 records from a [`MockDns`]. Certificates are signed by its own root, with an
//! authority key identifier, so ARI ids and `replaces` work.
//!
//! Hand [`MockCa::client`] to [`crate::Acme::with_http_client`]; the directory URL is
//! [`MockCa::DIRECTORY`].

use crate::challenge::{BoxFuture, DnsChallenge, DnsRecord};
use crate::renew::Window;
use crate::{ACME_TLS_ALPN, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const BASE: &str = "https://ca.test";

/// What the CA saw of an order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderView {
    /// The names asked for.
    pub names: Vec<String>,
    /// `replaces` (an ARI id), if sent.
    pub replaces: Option<String>,
    /// The profile, if sent.
    pub profile: Option<String>,
    /// The order status.
    pub status: String,
    /// The validation error, if it failed.
    pub error: Option<String>,
}

struct Order {
    names: Vec<String>,
    authz: Vec<usize>,
    status: String,
    error: Option<String>,
    cert: Option<usize>,
    replaces: Option<String>,
    profile: Option<String>,
}

struct Authz {
    name: String,
    wildcard: bool,
    token: String,
    thumb: String,
    status: String,
    kind: Option<String>,
}

struct Issued {
    pem: String,
    der: Vec<u8>,
}

#[derive(Clone, Default)]
struct Checks {
    fail: bool,
    http01: Option<SocketAddr>,
    tls_alpn: Option<SocketAddr>,
    dns: Option<Arc<MockDns>>,
}

struct Ca {
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
    root_pem: String,
    accounts: Vec<String>,
    orders: Vec<Order>,
    authz: Vec<Authz>,
    issued: Vec<Issued>,
    checks: Checks,
    lifetime: Duration,
    ari: bool,
    window: Option<Window>,
    fail: bool,
    serial: u64,
    ari_requests: u32,
}

/// The mock CA. Clones share state.
#[derive(Clone)]
pub struct MockCa(Arc<Mutex<Ca>>);

impl Default for MockCa {
    fn default() -> Self {
        Self::new()
    }
}

impl MockCa {
    /// The directory URL clients should use.
    pub const DIRECTORY: &'static str = "https://ca.test/dir";

    /// A CA with a fresh root, 90-day certificates and ARI on.
    pub fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("CA key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign, rcgen::KeyUsagePurpose::DigitalSignature];
        params.distinguished_name.push(rcgen::DnType::CommonName, "weirdnet-tls mock CA");
        let root = params.self_signed(&key).expect("CA cert");
        Self(Arc::new(Mutex::new(Ca {
            key,
            params,
            root_pem: root.pem(),
            accounts: Vec::new(),
            orders: Vec::new(),
            authz: Vec::new(),
            issued: Vec::new(),
            checks: Checks::default(),
            lifetime: Duration::from_secs(90 * 86400),
            ari: true,
            window: None,
            fail: false,
            serial: 0x1000,
            ari_requests: 0,
        })))
    }

    /// An instant-acme HTTP client talking to this CA.
    pub fn client(&self) -> Box<dyn HttpClient> {
        Box::new(self.clone())
    }

    /// The root certificate, PEM.
    pub fn root_pem(&self) -> String {
        self.0.lock().unwrap().root_pem.clone()
    }

    /// Validates HTTP-01 by fetching `http://ADDR/.well-known/acme-challenge/TOKEN`.
    pub fn validate_http01_at(&self, addr: SocketAddr) {
        self.0.lock().unwrap().checks.http01 = Some(addr);
    }

    /// Validates TLS-ALPN-01 by a handshake with `addr`.
    pub fn validate_tls_alpn_at(&self, addr: SocketAddr) {
        self.0.lock().unwrap().checks.tls_alpn = Some(addr);
    }

    /// Validates DNS-01 by reading `dns`.
    pub fn validate_dns01_with(&self, dns: Arc<MockDns>) {
        self.0.lock().unwrap().checks.dns = Some(dns);
    }

    /// Sets the lifetime of new certificates.
    pub fn set_lifetime(&self, d: Duration) {
        self.0.lock().unwrap().lifetime = d;
    }

    /// Turns ARI (the `renewalInfo` directory entry) on or off.
    pub fn set_ari(&self, on: bool) {
        self.0.lock().unwrap().ari = on;
    }

    /// Fixes the ARI window for every certificate (else 2/3 to 3/4 into its lifetime).
    pub fn set_window(&self, w: Option<Window>) {
        self.0.lock().unwrap().window = w;
    }

    /// Makes every validation fail (or succeed again).
    pub fn set_fail(&self, fail: bool) {
        self.0.lock().unwrap().fail = fail;
    }

    /// The orders seen, oldest first.
    pub fn orders(&self) -> Vec<OrderView> {
        let ca = self.0.lock().unwrap();
        ca.orders
            .iter()
            .map(|o| OrderView {
                names: o.names.clone(),
                replaces: o.replaces.clone(),
                profile: o.profile.clone(),
                status: o.status.clone(),
                error: o.error.clone(),
            })
            .collect()
    }

    /// The challenge type used per validated name, in order.
    pub fn validations(&self) -> Vec<(String, String)> {
        let ca = self.0.lock().unwrap();
        ca.authz.iter().filter_map(|a| a.kind.clone().map(|k| (a.name.clone(), k))).collect()
    }

    /// Certificates issued.
    pub fn issued(&self) -> usize {
        self.0.lock().unwrap().issued.len()
    }

    /// Renewal information requests served.
    pub fn ari_requests(&self) -> u32 {
        self.0.lock().unwrap().ari_requests
    }

    /// The accounts registered.
    pub fn accounts(&self) -> usize {
        self.0.lock().unwrap().accounts.len()
    }
}

fn b64d(s: &str) -> Vec<u8> {
    B64.decode(s.trim_end_matches('=')).unwrap_or_default()
}

fn thumbprint(jwk: &Value) -> String {
    let canon = match jwk["kty"].as_str() {
        Some("EC") => json!({"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}),
        Some("RSA") => json!({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}),
        _ => json!({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}),
    };
    // serde_json keeps the keys sorted (no preserve_order), as RFC 7638 needs.
    B64.encode(Sha256::digest(canon.to_string().as_bytes()))
}

struct Reply {
    status: u16,
    location: Option<String>,
    ctype: &'static str,
    body: String,
    retry_after: Option<u64>,
}

fn reply(status: u16, body: Value) -> Reply {
    Reply { status, location: None, ctype: "application/json", body: body.to_string(), retry_after: None }
}

fn problem(status: u16, kind: &str, detail: &str) -> Reply {
    Reply {
        status,
        location: None,
        ctype: "application/problem+json",
        body: json!({"type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail}).to_string(),
        retry_after: None,
    }
}

enum Step {
    Done(Reply),
    Validate { authz: usize, kind: String, name: String, ka: String, checks: Checks },
}

impl Ca {
    fn order_json(&self, i: usize) -> Value {
        let o = &self.orders[i];
        let mut v = json!({
            "status": o.status,
            "identifiers": o.names.iter().map(|n| json!({"type": "dns", "value": n})).collect::<Vec<_>>(),
            "authorizations": o.authz.iter().map(|a| format!("{BASE}/authz/{a}")).collect::<Vec<_>>(),
            "finalize": format!("{BASE}/finalize/{i}"),
        });
        if let Some(c) = o.cert {
            v["certificate"] = json!(format!("{BASE}/cert/{c}"));
        }
        if let Some(r) = &o.replaces {
            v["replaces"] = json!(r);
        }
        if let Some(p) = &o.profile {
            v["profile"] = json!(p);
        }
        if let Some(e) = &o.error {
            v["error"] = json!({"type": "urn:ietf:params:acme:error:unauthorized", "detail": e});
        }
        v
    }

    fn chall_json(&self, a: usize, kind: &str) -> Value {
        let z = &self.authz[a];
        let status = match (&z.kind, z.status.as_str()) {
            (Some(k), s) if k == kind => s,
            _ => "pending",
        };
        json!({"type": kind, "url": format!("{BASE}/chall/{a}/{kind}"), "token": z.token, "status": status})
    }

    fn authz_json(&self, a: usize) -> Value {
        let z = &self.authz[a];
        let kinds: &[&str] = if z.wildcard { &["dns-01"] } else { &["http-01", "tls-alpn-01", "dns-01"] };
        json!({
            "identifier": {"type": "dns", "value": z.name},
            "status": z.status,
            "wildcard": z.wildcard,
            "challenges": kinds.iter().map(|k| self.chall_json(a, k)).collect::<Vec<_>>(),
        })
    }

    fn refresh_order(&mut self, i: usize) {
        if self.orders[i].status != "pending" {
            return;
        }
        let st: Vec<&str> = self.orders[i].authz.iter().map(|a| self.authz[*a].status.as_str()).collect();
        if st.contains(&"invalid") {
            self.orders[i].status = "invalid".into();
        } else if st.iter().all(|s| *s == "valid") {
            self.orders[i].status = "ready".into();
        }
    }

    fn issue(&mut self, i: usize, csr_der: &[u8]) -> std::result::Result<(), String> {
        let csr = rcgen::CertificateSigningRequestParams::from_der(&csr_der.to_vec().into()).map_err(|e| format!("bad CSR: {e}"))?;
        let mut asked: Vec<String> = csr
            .params
            .subject_alt_names
            .iter()
            .filter_map(|s| match s {
                rcgen::SanType::DnsName(n) => Some(n.as_str().to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        let mut want = self.orders[i].names.clone();
        asked.sort();
        want.sort();
        if asked != want {
            return Err(format!("CSR names {asked:?} do not match the order {want:?}"));
        }
        let mut p = csr.params.clone();
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::seconds(60);
        p.not_after = p.not_before + self.lifetime;
        self.serial += 1;
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&self.serial.to_be_bytes()));
        p.use_authority_key_identifier_extension = true;
        p.distinguished_name = rcgen::DistinguishedName::new();
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let c = p.signed_by(&csr.public_key, &issuer).map_err(|e| e.to_string())?;
        let pem = format!("{}{}", c.pem(), self.root_pem);
        self.issued.push(Issued { pem, der: c.der().to_vec() });
        self.orders[i].cert = Some(self.issued.len() - 1);
        self.orders[i].status = "valid".into();
        Ok(())
    }

    fn handle(&mut self, method: &str, path: &str, body: &[u8]) -> Step {
        let jws: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let protected: Value = serde_json::from_slice(&b64d(jws["protected"].as_str().unwrap_or(""))).unwrap_or(Value::Null);
        let payload_raw = b64d(jws["payload"].as_str().unwrap_or(""));
        let payload: Value = serde_json::from_slice(&payload_raw).unwrap_or(Value::Null);
        let acct = protected["kid"].as_str().and_then(|k| k.rsplit('/').next()).and_then(|n| n.parse::<usize>().ok());
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let idx = |i: usize| parts.get(i).and_then(|s| s.parse::<usize>().ok());
        Step::Done(match (method, parts.as_slice()) {
            (_, ["dir"]) => {
                let mut d = json!({
                    "newNonce": format!("{BASE}/nonce"),
                    "newAccount": format!("{BASE}/acct"),
                    "newOrder": format!("{BASE}/order"),
                    "revokeCert": format!("{BASE}/revoke"),
                    "meta": {"profiles": {"classic": "90 days", "shortlived": "a week"}},
                });
                if self.ari {
                    d["renewalInfo"] = json!(format!("{BASE}/ari"));
                }
                reply(200, d)
            }
            (_, ["nonce"]) => Reply { status: 200, location: None, ctype: "text/plain", body: String::new(), retry_after: None },
            ("POST", ["acct"]) => {
                self.accounts.push(thumbprint(&protected["jwk"]));
                let mut r = reply(201, json!({"status": "valid", "contact": payload["contact"]}));
                r.location = Some(format!("{BASE}/acct/{}", self.accounts.len() - 1));
                r
            }
            ("POST", ["order"]) => {
                let Some(a) = acct.filter(|a| *a < self.accounts.len()) else { return Step::Done(problem(401, "accountDoesNotExist", "no account")) };
                let names: Vec<String> = payload["identifiers"]
                    .as_array()
                    .map(|v| v.iter().filter_map(|i| i["value"].as_str().map(str::to_ascii_lowercase)).collect())
                    .unwrap_or_default();
                if names.is_empty() {
                    return Step::Done(problem(400, "malformed", "no identifiers"));
                }
                let replaces = payload["replaces"].as_str().map(str::to_string);
                if let Some(r) = &replaces {
                    if !self.ari {
                        return Step::Done(problem(400, "malformed", "replaces without ARI"));
                    }
                    let known = self.issued.iter().any(|c| crate::cert::info(&c.der).ok().and_then(|i| i.ari_id).as_deref() == Some(r.as_str()));
                    if !known {
                        return Step::Done(problem(400, "malformed", "replaces names an unknown certificate"));
                    }
                }
                let profile = payload["profile"].as_str().map(str::to_string);
                if let Some(p) = &profile
                    && p != "classic"
                    && p != "shortlived"
                {
                    return Step::Done(problem(400, "invalidProfile", "unknown profile"));
                }
                let mut authz = Vec::new();
                for n in &names {
                    self.authz.push(Authz {
                        name: n.trim_start_matches("*.").to_string(),
                        wildcard: n.starts_with("*."),
                        token: format!("tok{}", self.authz.len()),
                        thumb: self.accounts[a].clone(),
                        status: "pending".into(),
                        kind: None,
                    });
                    authz.push(self.authz.len() - 1);
                }
                self.orders.push(Order { names, authz, status: "pending".into(), error: None, cert: None, replaces, profile });
                let i = self.orders.len() - 1;
                let mut r = reply(201, self.order_json(i));
                r.location = Some(format!("{BASE}/order/{i}"));
                r
            }
            ("POST", ["order", _]) => match idx(1).filter(|i| *i < self.orders.len()) {
                Some(i) => {
                    self.refresh_order(i);
                    reply(200, self.order_json(i))
                }
                None => problem(404, "malformed", "no such order"),
            },
            ("POST", ["authz", _]) => match idx(1).filter(|i| *i < self.authz.len()) {
                Some(a) => reply(200, self.authz_json(a)),
                None => problem(404, "malformed", "no such authorization"),
            },
            ("POST", ["chall", _, kind]) => {
                let Some(a) = idx(1).filter(|i| *i < self.authz.len()) else { return Step::Done(problem(404, "malformed", "no such challenge")) };
                if payload_raw.is_empty() || self.authz[a].status != "pending" {
                    return Step::Done(reply(200, self.chall_json(a, kind)));
                }
                let z = &self.authz[a];
                return Step::Validate {
                    authz: a,
                    kind: kind.to_string(),
                    name: z.name.clone(),
                    ka: format!("{}.{}", z.token, z.thumb),
                    checks: if self.fail { Checks { fail: true, ..Checks::default() } } else { self.checks.clone() },
                };
            }
            ("POST", ["finalize", _]) => {
                let Some(i) = idx(1).filter(|i| *i < self.orders.len()) else { return Step::Done(problem(404, "malformed", "no such order")) };
                self.refresh_order(i);
                if self.orders[i].status != "ready" {
                    return Step::Done(problem(403, "orderNotReady", "the order is not ready"));
                }
                let csr = b64d(payload["csr"].as_str().unwrap_or(""));
                match self.issue(i, &csr) {
                    Ok(()) => reply(200, self.order_json(i)),
                    Err(e) => problem(400, "badCSR", &e),
                }
            }
            ("POST", ["cert", _]) => match idx(1).and_then(|i| self.issued.get(i)) {
                Some(c) => Reply { status: 200, location: None, ctype: "application/pem-certificate-chain", body: c.pem.clone(), retry_after: None },
                None => problem(404, "malformed", "no such certificate"),
            },
            ("GET", ["ari", id]) if self.ari => {
                self.ari_requests += 1;
                let Some(c) = self.issued.iter().find(|c| crate::cert::info(&c.der).ok().and_then(|i| i.ari_id).as_deref() == Some(*id)) else {
                    return Step::Done(problem(404, "malformed", "unknown certificate"));
                };
                let i = crate::cert::info(&c.der).expect("issued cert");
                let w = self.window.unwrap_or_else(|| {
                    let life = i.lifetime();
                    Window { start: i.not_before + life * 2 / 3, end: i.not_before + life * 3 / 4 }
                });
                let fmt = |t: SystemTime| time::OffsetDateTime::from(t).format(&time::format_description::well_known::Rfc3339).unwrap();
                let mut r = reply(200, json!({"suggestedWindow": {"start": fmt(w.start), "end": fmt(w.end)}}));
                r.retry_after = Some(21600);
                r
            }
            _ => problem(404, "malformed", &format!("no {method} {path}")),
        })
    }

    fn validated(&mut self, a: usize, kind: &str, ok: Option<String>) -> Reply {
        let z = &mut self.authz[a];
        z.kind = Some(kind.to_string());
        z.status = if ok.is_none() { "valid".into() } else { "invalid".into() };
        if let Some(why) = ok {
            for o in self.orders.iter_mut().filter(|o| o.authz.contains(&a)) {
                o.error = Some(format!("{kind} for {}: {why}", self.authz[a].name));
            }
        }
        for i in 0..self.orders.len() {
            self.refresh_order(i);
        }
        reply(200, self.chall_json(a, kind))
    }
}

async fn check(kind: &str, name: &str, ka: &str, c: &Checks) -> Option<String> {
    let digest = Sha256::digest(ka.as_bytes()).to_vec();
    if c.fail {
        return Some("the mock CA fails every validation".into());
    }
    match kind {
        "http-01" => {
            let Some(addr) = c.http01 else { return Some("no HTTP-01 address".into()) };
            let token = ka.split('.').next().unwrap_or("");
            match http_get(addr, name, &format!("/.well-known/acme-challenge/{token}")).await {
                Ok(b) if b.trim() == ka => None,
                Ok(b) => Some(format!("wrong answer {b:?}")),
                Err(e) => Some(e),
            }
        }
        "tls-alpn-01" => {
            let Some(addr) = c.tls_alpn else { return Some("no TLS-ALPN-01 address".into()) };
            let name = name.to_string();
            tokio::task::spawn_blocking(move || alpn_check(addr, &name, &digest)).await.unwrap_or_else(|e| Some(e.to_string()))
        }
        "dns-01" => {
            let Some(dns) = &c.dns else { return Some("no DNS".into()) };
            let want = B64.encode(&digest);
            if dns.txt(&format!("_acme-challenge.{name}")).contains(&want) { None } else { Some("TXT record not found".into()) }
        }
        _ => Some("unknown challenge".into()),
    }
}

async fn http_get(addr: SocketAddr, host: &str, path: &str) -> std::result::Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).await.map_err(|e| e.to_string())?;
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    if !head.starts_with("HTTP/1.1 200") {
        return Err(head.lines().next().unwrap_or("").to_string());
    }
    Ok(body.to_string())
}

/// Accepts any certificate: the TLS-ALPN-01 validator only reads the extension (webpki
/// refuses the critical acmeIdentifier extension).
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let _ = (m, c, d);
        // Signature checks parse the leaf with webpki, which refuses the critical
        // acmeIdentifier extension; the validator only reads the extension.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let _ = (m, c, d);
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn alpn_check(addr: SocketAddr, name: &str, digest: &[u8]) -> Option<String> {
    let p = crate::crypto_provider();
    let mut cc = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        .with_no_client_auth();
    cc.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    let sn = rustls::pki_types::ServerName::try_from(name.to_string()).ok()?;
    let mut conn = rustls::ClientConnection::new(Arc::new(cc), sn).ok()?;
    let mut s = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => return Some(e.to_string()),
    };
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut s) {
            return Some(format!("handshake: {e}"));
        }
    }
    if conn.alpn_protocol() != Some(ACME_TLS_ALPN) {
        return Some("acme-tls/1 not negotiated".into());
    }
    let leaf = conn.peer_certificates()?.first()?.to_vec();
    let (_, c) = x509_parser::parse_x509_certificate(&leaf).ok()?;
    let ext = c.extensions().iter().find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31");
    let mut want = vec![0x04, 0x20];
    want.extend_from_slice(digest);
    match ext {
        Some(e) if e.critical && e.value == want.as_slice() => {
            let covers = crate::cert::info(&leaf).map(|i| i.names == [name.to_string()]).unwrap_or(false);
            if covers { None } else { Some("the challenge cert names something else".into()) }
        }
        Some(_) => Some("wrong acmeIdentifier".into()),
        None => Some("no acmeIdentifier extension".into()),
    }
}

impl HttpClient for MockCa {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> std::pin::Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, instant_acme::Error>> + Send>> {
        let ca = self.0.clone();
        Box::pin(async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let step = ca.lock().unwrap().handle(&method, &path, &body);
            let r = match step {
                Step::Done(r) => r,
                Step::Validate { authz, kind, name, ka, checks } => {
                    let res = check(&kind, &name, &ka, &checks).await;
                    ca.lock().unwrap().validated(authz, &kind, res)
                }
            };
            let mut b = http::Response::builder().status(r.status).header("Replay-Nonce", "mock-nonce").header("Content-Type", r.ctype);
            if let Some(l) = r.location {
                b = b.header("Location", l);
            }
            if let Some(s) = r.retry_after {
                b = b.header("Retry-After", s.to_string());
            }
            Ok(BytesResponse::from(b.body(Full::new(Bytes::from(r.body))).expect("response")))
        })
    }
}

/// An in-memory DNS zone for DNS-01 tests: a [`DnsChallenge`] that the mock CA can read.
#[derive(Debug, Default)]
pub struct MockDns {
    records: Mutex<HashMap<String, Vec<String>>>,
    log: Mutex<Vec<String>>,
}

impl MockDns {
    /// An empty zone.
    pub fn new() -> Self {
        Self::default()
    }

    /// The TXT values at `name`.
    pub fn txt(&self, name: &str) -> Vec<String> {
        self.records.lock().unwrap().get(&crate::cert::normalize(name)).cloned().unwrap_or_default()
    }

    /// `present NAME` and `cleanup NAME` lines, in order.
    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl DnsChallenge for MockDns {
    fn present<'a>(&'a self, r: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
        self.records.lock().unwrap().entry(r.name.clone()).or_default().push(r.value.clone());
        self.log.lock().unwrap().push(format!("present {}", r.name));
        Box::pin(async { Ok(()) })
    }
    fn cleanup<'a>(&'a self, r: &'a DnsRecord) -> BoxFuture<'a, Result<()>> {
        if let Some(v) = self.records.lock().unwrap().get_mut(&r.name) {
            v.retain(|x| *x != r.value);
        }
        self.log.lock().unwrap().push(format!("cleanup {}", r.name));
        Box::pin(async { Ok(()) })
    }
}
