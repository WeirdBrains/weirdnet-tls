# weirdnet-tls

TLS certificates for Weirdnet hosts and apps: ACME issuance and renewal, certificate stores,
and a rustls SNI resolver. It is the shared replacement for the ACME code in Mouser, Muninn,
itcmdr and TAUR.

- **ACME** over [instant-acme](https://docs.rs/instant-acme): an account per directory kept
  in the store, several names per certificate, wildcards, ACME profiles (optionally falling
  back to the CA's default), Let's Encrypt production or staging, or any RFC 8555 directory.
  Names a public CA refuses (`localhost`, `*.localhost`, IP addresses, all-digit top labels)
  fail `AcmeConfig::validate`; `AcmeConfig::private_names` allows them for a private CA.
- **Challenges**: TLS-ALPN-01 answered by the resolver on your port 443, HTTP-01 from a token
  board (serve it with `serve_http01` or your own router through `Http01Board::answer`), and
  DNS-01 through the `DnsChallenge` trait: a hook command, a manual prompt, or (feature
  `grindvakt`) a [grindvakt-core](https://docs.rs/grindvakt-core) DNS provider. When the
  app's own listener isn't running (a CLI renewing while the app is stopped),
  `Acme::serve_challenge` answers TLS-ALPN-01 (`challenge::serve_tls_alpn01`: handshakes only,
  never a real certificate) or HTTP-01 on a listener of its own.
- **Stores**: the `CertStore` trait, `FileStore` (files 0600 in directories 0700, atomic
  writes), `MemoryStore`, and (feature `storage`) `SqlStore` in an encrypted weirdnet-storage
  database. `Acme::import` (or `store::import`) copies an app's earlier files (its own layout or
  an older version's: account credentials, chain and key, renewal state) into the store once,
  never overwriting, so an app can move onto weirdnet-tls without a new certificate.
- **Resolver**: per-name certificates swapped without a restart. A handshake gets a pinned
  certificate first (internal names, a private CA), then the user's own, then ACME, then
  self-signed, skipping expired ones. A default answers handshakes without SNI or for an
  unknown name; `Acme::with_default_cert(true)` makes it the ACME certificate.
- **Renewal**: at a point in the CA's ACME Renewal Information window (RFC 9773) with
  `replaces`, else two thirds into the lifetime; failures back off from 1 hour to 1 day; a
  forced renewal within a day of the last issue is refused (`Acme::trigger_renewal` asks the
  running renewer for one, `Acme::trigger` only for a check); `Acme::watch` gives a typed
  `Status`. `acme::schedule(store, cfg, now)` says when the next renewal is due from the store
  alone (cached ARI window, backoff), for status commands while the app isn't running. A failed order never drops TLS: the last certificate stays in service.
- **Crypto**: `ring` (default) or `aws-lc-rs`.
- **Tests**: `testing::MockCa` (feature `testing`) is an in-process ACME CA that validates the
  real HTTP-01, TLS-ALPN-01 and DNS-01 answers and serves ARI.

HTTP servers and port forwarding are out of scope.

```rust,no_run
use std::sync::Arc;
use weirdnet_tls::*;

# async fn run() -> weirdnet_tls::Result<()> {
let names = vec!["example.com".to_string(), "www.example.com".to_string()];
let resolver = Arc::new(Resolver::with_self_signed(&names)?);
let mut cfg = AcmeConfig::new("main", names);
cfg.contact = vec!["admin@example.com".into()];
let acme = Arc::new(Acme::new(cfg, Arc::new(FileStore::new("/var/lib/myapp/tls")), resolver.clone())?);
acme.load()?;
let _renewer = acme.clone().spawn();
let tls = resolver.server_config(&[b"h2", b"http/1.1"])?; // hand to tokio-rustls, hyper, ...
# let _ = tls; Ok(()) }
```

DNS-01 hooks get `WEIRDNET_TLS_ACTION` (`present` or `cleanup`), `WEIRDNET_TLS_DOMAIN`,
`WEIRDNET_TLS_NAME` and `WEIRDNET_TLS_TXT`. `HookDns::with_prefix("MYAPP_ACME_")` sets the
same four under an app's own prefix (`MYAPP_ACME_TXT`), and `HookDns::with_env` adds fixed
variables; they are in the environment before the shell reads the command, so `$MYAPP_ACME_TXT`
(`sh -c`) or `%MYAPP_ACME_TXT%` (`cmd /S /C`, on Windows) expands directly. grindvakt-core providers cannot delete records,
so with `GrindvaktDns` the `_acme-challenge` TXT record is overwritten on each order and left
in place afterwards.

## Platforms

Linux, macOS and Windows are tested in CI; Android (aarch64, API 26) and iOS (aarch64) build.

## License

BSD-3-Clause.
