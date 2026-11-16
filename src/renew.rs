//! When to renew, failure backoff, and the typed status.

use crate::resolver::Source;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// The first retry after a failure; doubles per failure.
pub const BACKOFF_MIN: Duration = Duration::from_secs(3600);
/// The longest wait between failed attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(86400);
/// A forced renewal is refused this soon after the last issue (CA rate limits).
pub const FORCE_MIN_AGE: Duration = Duration::from_secs(86400);
/// How long an ARI answer is used when the CA gives no Retry-After.
pub const ARI_DEFAULT_RECHECK: Duration = Duration::from_secs(6 * 3600);

/// The wait after `failures` failed attempts in a row: 1h, 2h, 4h, ... up to 24h.
pub fn backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let f = 1u64 << (failures - 1).min(16);
    (BACKOFF_MIN * f as u32).min(BACKOFF_MAX)
}

/// A renewal window suggested by the CA (RFC 9773).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    /// Start.
    pub start: SystemTime,
    /// End.
    pub end: SystemTime,
}

/// Renewal state kept in the store per certificate set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persisted {
    /// Failed attempts in a row.
    pub failures: u32,
    /// The last failed attempt.
    pub last_failure: Option<SystemTime>,
    /// Its error.
    pub last_error: Option<String>,
    /// When the current certificate was issued here.
    pub last_issued: Option<SystemTime>,
    /// The last ARI window, for the certificate with this ARI id.
    pub ari: Option<(String, Window)>,
    /// When to ask for ARI again.
    pub ari_recheck: Option<SystemTime>,
}

/// A point in `w` picked from `seed` (so many hosts spread over the window, but one host
/// keeps its pick across restarts).
pub fn pick(w: Window, seed: &str) -> SystemTime {
    use sha2::Digest;
    let span = w.end.duration_since(w.start).unwrap_or_default();
    if span.is_zero() {
        return w.start;
    }
    let h = sha2::Sha256::digest(seed.as_bytes());
    let x = u64::from_be_bytes(h[..8].try_into().unwrap());
    w.start + Duration::from_secs(x % span.as_secs().max(1))
}

/// The renewal time without ARI: two thirds into the lifetime.
pub fn fallback(not_before: SystemTime, not_after: SystemTime) -> SystemTime {
    let life = not_after.duration_since(not_before).unwrap_or_default();
    not_before + life * 2 / 3
}

/// When to try next: `due` (from ARI or the fallback), or later after failures.
pub fn next_attempt(due: SystemTime, st: &Persisted) -> SystemTime {
    match st.last_failure {
        Some(t) if st.failures > 0 => (t + backoff(st.failures)).max(due),
        _ => due,
    }
}

/// What a renewal pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new certificate was issued and installed.
    Renewed(crate::CertInfo),
    /// Nothing to do before this time.
    NotDue(SystemTime),
}

/// The state of a certificate set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// No certificate yet.
    Missing,
    /// An order is in progress.
    Issuing,
    /// A valid certificate is served.
    Valid,
    /// The last attempt failed; the previous certificate (if any) is still served.
    Failing,
    /// The served certificate has expired.
    Expired,
}

/// A certificate set's status, for status pages and health checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The set.
    pub set: String,
    /// The names asked for.
    pub names: Vec<String>,
    /// The state.
    pub state: State,
    /// The served certificate's source, if any.
    pub source: Option<Source>,
    /// The served certificate's expiry.
    pub not_after: Option<SystemTime>,
    /// The next renewal attempt.
    pub next_attempt: Option<SystemTime>,
    /// Failed attempts in a row.
    pub failures: u32,
    /// The last error.
    pub last_error: Option<String>,
    /// True if the renewal time came from the CA's ARI window.
    pub ari: bool,
}

impl Status {
    /// A status with nothing known yet.
    pub fn missing(set: &str, names: &[String]) -> Self {
        Self {
            set: set.to_string(),
            names: names.to_vec(),
            state: State::Missing,
            source: None,
            not_after: None,
            next_attempt: None,
            failures: 0,
            last_error: None,
            ari: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_day() {
        let h = |n| backoff(n).as_secs() / 3600;
        assert_eq!([h(0), h(1), h(2), h(3), h(5), h(6), h(40)], [0, 1, 2, 4, 16, 24, 24]);
    }

    #[test]
    fn fallback_is_two_thirds() {
        let nb = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        assert_eq!(fallback(nb, nb + Duration::from_secs(90 * 86400)), nb + Duration::from_secs(60 * 86400));
    }

    #[test]
    fn picks_stay_in_the_window_and_are_stable() {
        let s = SystemTime::now();
        let w = Window { start: s, end: s + Duration::from_secs(86400) };
        let a = pick(w, "serial-a");
        assert!(a >= w.start && a < w.end);
        assert_eq!(a, pick(w, "serial-a"));
        assert_ne!(a, pick(w, "serial-b"));
        assert_eq!(pick(Window { start: s, end: s }, "x"), s);
    }

    #[test]
    fn failures_push_the_next_attempt() {
        let now = SystemTime::now();
        let st = Persisted { failures: 2, last_failure: Some(now), ..Default::default() };
        assert_eq!(next_attempt(now - Duration::from_secs(10), &st), now + Duration::from_secs(7200));
        assert_eq!(next_attempt(now, &Persisted::default()), now);
    }
}
