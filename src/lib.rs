//! TLS certificates for Weirdnet hosts.
//!
//! - [`acme`]: certificates from an ACME CA (Let's Encrypt or any RFC 8555 directory) over
//!   [instant-acme](https://docs.rs/instant-acme), with TLS-ALPN-01, HTTP-01 and DNS-01, several
//!   names per certificate, and the account kept in a [`CertStore`].
//! - [`challenge`]: the HTTP-01 token board and listener, a TLS-ALPN-01 challenge-only
//!   listener, and DNS-01 publishers (a hook command,
//!   a manual prompt, and [grindvakt-core](https://docs.rs/grindvakt-core) providers with the
//!   `grindvakt` feature).
//! - [`store`]: the [`CertStore`] trait, a file store (files 0600), a memory store, and with the
//!   `storage` feature a store in an encrypted weirdnet-storage database; [`store::import`]
//!   moves an app's earlier files in.
//! - [`resolver`]: a rustls SNI [`Resolver`] with per-name hot swap, source order user, ACME,
//!   self-signed, pinned certificates for internal names, and the TLS-ALPN-01 answers.
//! - [`renew`]: when to renew (ACME Renewal Information, else two thirds of the lifetime),
//!   failure backoff from 1 hour to 1 day, a guard on forced renewals, a typed [`Status`], and
//!   an offline [`Schedule`] read from the store ([`acme::schedule`]).
//! - [`testing`] (feature `testing`): a mock ACME CA that validates the real challenge answers.
//!
//! The crate never serves plain HTTP in place of HTTPS: when an order fails, the resolver keeps
//! serving the previous certificate (or the self-signed one), and the HTTP-01 listener answers
//! only challenge tokens.
//!
//! Pick a crypto provider with the `ring` (default) or `aws-lc-rs` feature.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("weirdnet-tls needs the `ring` or the `aws-lc-rs` feature");

pub mod acme;
pub mod cert;
pub mod challenge;
mod error;
pub mod renew;
pub mod resolver;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;

pub use acme::{Acme, AcmeConfig, ChallengeKind, Directory};
pub use cert::{CertInfo, CertPair};
pub use challenge::{DnsChallenge, DnsRecord, HookDns, Http01Board, ManualDns};
pub use error::{Error, Result};
pub use instant_acme;
pub use renew::{Outcome, Schedule, State, Status};
pub use resolver::{Resolver, Source};
pub use rustls;
pub use store::{CertStore, FileStore, MemoryStore};

/// The ALPN protocol of TLS-ALPN-01 validation (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// The rustls crypto provider picked by the features: aws-lc-rs when on, else ring.
pub fn crypto_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "aws-lc-rs")]
    let p = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let p = rustls::crypto::ring::default_provider();
    std::sync::Arc::new(p)
}
