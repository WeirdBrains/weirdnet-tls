use std::time::SystemTime;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration is not usable.
    #[error("config: {0}")]
    Config(String),
    /// A certificate or key could not be read or made.
    #[error("certificate: {0}")]
    Cert(String),
    /// The ACME CA refused or failed a request.
    #[error("acme: {0}")]
    Acme(String),
    /// A challenge answer could not be published.
    #[error("challenge: {0}")]
    Challenge(String),
    /// The certificate store failed.
    #[error("store: {0}")]
    Store(String),
    /// A forced renewal came too soon after the last issue; try again after the time given.
    #[error("the last certificate was issued too recently to force a renewal")]
    TooSoon(SystemTime),
    /// An I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<instant_acme::Error> for Error {
    fn from(e: instant_acme::Error) -> Self {
        Error::Acme(e.to_string())
    }
}

impl From<rcgen::Error> for Error {
    fn from(e: rcgen::Error) -> Self {
        Error::Cert(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Store(e.to_string())
    }
}
