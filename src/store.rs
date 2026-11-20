//! Where certificates, keys, ACME accounts and renewal state are kept.
//!
//! A [`CertStore`] is a small key-value store. Keys are short paths such as
//! `cert/<set>.json`, made of `a-z`, `0-9`, `.`, `_`, `-` and `/`. Values hold private keys and
//! account credentials, so stores must keep them private: [`FileStore`] writes files 0600 in
//! directories 0700, and the `storage` feature's [`SqlStore`] keeps them in an encrypted
//! weirdnet-storage (SQLCipher) database.

use crate::cert::CertPair;
use crate::{Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A private key-value store for certificates, keys, accounts and state.
pub trait CertStore: Send + Sync {
    /// The value at `key`, if any.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Sets `key` to `value`, replacing it atomically.
    fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    /// Removes `key` (no error if missing).
    fn delete(&self, key: &str) -> Result<()>;
}

/// Checks a store key.
pub fn check_key(key: &str) -> Result<()> {
    let ok = !key.is_empty()
        && key.len() <= 200
        && !key.starts_with('/')
        && key.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
        && key.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'/'));
    if ok { Ok(()) } else { Err(Error::Store(format!("bad store key {key:?}"))) }
}

/// Reads `key` as JSON.
pub fn get_json<T: DeserializeOwned>(s: &dyn CertStore, key: &str) -> Result<Option<T>> {
    match s.get(key)? {
        Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
        None => Ok(None),
    }
}

/// Writes `value` as JSON at `key`.
pub fn put_json<T: Serialize>(s: &dyn CertStore, key: &str, value: &T) -> Result<()> {
    s.put(key, &serde_json::to_vec_pretty(value)?)
}

/// The key of certificate set `set`'s chain and key.
pub fn cert_key(set: &str) -> String {
    format!("cert/{set}.json")
}

/// The key of certificate set `set`'s renewal state.
pub fn state_key(set: &str) -> String {
    format!("state/{set}.json")
}

/// The key of the ACME account for directory URL `dir`.
pub fn account_key(dir: &str) -> String {
    use sha2::Digest;
    let tag: String = sha2::Sha256::digest(dir.as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("account/{tag}.json")
}

/// Loads certificate set `set`.
pub fn load_cert(s: &dyn CertStore, set: &str) -> Result<Option<CertPair>> {
    get_json(s, &cert_key(set))
}

/// Saves certificate set `set`.
pub fn save_cert(s: &dyn CertStore, set: &str, pair: &CertPair) -> Result<()> {
    put_json(s, &cert_key(set), pair)
}

/// What an app kept before it used a [`CertStore`] (its own file layout, an older version's
/// files), for [`import`]. Build it with [`Legacy::from_files`] or set the fields.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Legacy {
    /// The ACME account: instant-acme `AccountCredentials` JSON.
    pub account: Option<Vec<u8>>,
    /// The certificate chain and key.
    pub cert: Option<CertPair>,
    /// The renewal state that goes with the certificate (converted by the app).
    pub state: Option<crate::renew::Persisted>,
}

impl std::fmt::Debug for Legacy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Legacy")
            .field("account", &self.account.as_ref().map(|_| "<redacted>"))
            .field("cert", &self.cert)
            .field("state", &self.state)
            .finish()
    }
}

fn read_opt(p: Option<&Path>) -> Result<Option<Vec<u8>>> {
    match p.map(std::fs::read) {
        None => Ok(None),
        Some(Ok(b)) => Ok(Some(b)),
        Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Some(Err(e)) => Err(e.into()),
    }
}

impl Legacy {
    /// Nothing to import.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads an account credentials JSON file, and a PEM chain and key file, skipping files
    /// that don't exist (the certificate needs both).
    pub fn from_files(account: Option<&Path>, chain_pem: Option<&Path>, key_pem: Option<&Path>) -> Result<Self> {
        let text = |b: Vec<u8>| String::from_utf8(b).map_err(|_| Error::Store("a legacy PEM file is not text".into()));
        let cert = match (read_opt(chain_pem)?, read_opt(key_pem)?) {
            (Some(c), Some(k)) => Some(CertPair { chain_pem: text(c)?, key_pem: text(k)? }),
            _ => None,
        };
        Ok(Self { account: read_opt(account)?, cert, state: None })
    }

    /// Adds the renewal state that goes with the certificate.
    pub fn with_state(mut self, state: crate::renew::Persisted) -> Self {
        self.state = Some(state);
        self
    }
}

/// What [`import`] copied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Imported {
    /// The account.
    pub account: bool,
    /// The certificate.
    pub cert: bool,
    /// The renewal state.
    pub state: bool,
}

impl Imported {
    /// True if anything was copied.
    pub fn any(&self) -> bool {
        self.account || self.cert || self.state
    }
}

/// Copies `legacy` into `store` for certificate set `set` and ACME directory URL `directory`,
/// never overwriting: the account only if the store has none for the directory, the
/// certificate only if the set has none, and the state only with the certificate and if the set
/// has none. Everything is checked first (the account must be ACME credentials, the chain and
/// key must belong together), and nothing is written if a part is bad. Run it before
/// [`crate::Acme::load`]; it is safe to run on every start. The legacy files are left alone.
pub fn import(store: &dyn CertStore, set: &str, directory: &str, legacy: &Legacy) -> Result<Imported> {
    if let Some(a) = &legacy.account {
        let _creds: instant_acme::AccountCredentials =
            serde_json::from_slice(a).map_err(|_| Error::Store("the legacy ACME account is not account credentials".into()))?;
    }
    if let Some(p) = &legacy.cert {
        crate::cert::certified_key(p)?;
    }
    let mut done = Imported::default();
    let akey = account_key(directory);
    if let Some(a) = &legacy.account
        && store.get(&akey)?.is_none()
    {
        store.put(&akey, a)?;
        done.account = true;
    }
    if let Some(p) = &legacy.cert
        && load_cert(store, set)?.is_none()
    {
        save_cert(store, set, p)?;
        done.cert = true;
        let skey = state_key(set);
        if let Some(st) = &legacy.state
            && store.get(&skey)?.is_none()
        {
            put_json(store, &skey, st)?;
            done.state = true;
        }
    }
    Ok(done)
}

/// Keeps everything in memory (tests, or callers that persist elsewhere).
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The keys present, sorted.
    pub fn keys(&self) -> Vec<String> {
        let mut k: Vec<String> = self.0.lock().unwrap().keys().cloned().collect();
        k.sort();
        k
    }
}

impl CertStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        check_key(key)?;
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        check_key(key)?;
        self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        check_key(key)?;
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Files under a directory: each key is a file, written to a temporary file and renamed,
/// mode 0600 in directories 0700 on Unix.
#[derive(Debug, Clone)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// A store rooted at `root` (created on the first write).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        check_key(key)?;
        Ok(self.root.join(key))
    }
}

fn private_dir(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)?;
    Ok(())
}

/// Writes `data` to `path` with mode 0600 (Unix), through a temporary file and a rename.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| Error::Store("no parent directory".into()))?;
    private_dir(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("x");
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let res = (|| {
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(res?)
}

impl CertStore for FileStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(key)?) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        write_private(&self.path(key)?, value)
    }
    fn delete(&self, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(key)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "storage")]
pub use sql::SqlStore;

#[cfg(feature = "storage")]
mod sql {
    use super::{CertStore, check_key};
    use crate::{Error, Result};
    use std::sync::{Arc, Mutex};
    use weirdnet_storage::rusqlite::{self, OptionalExtension};

    /// A table in a weirdnet-storage database, so certificates and keys share the app's
    /// SQLCipher encryption. The table (`weirdnet_tls`, by default) is created when missing.
    pub struct SqlStore {
        conn: Arc<Mutex<rusqlite::Connection>>,
        table: String,
    }

    fn db(e: rusqlite::Error) -> Error {
        Error::Store(e.to_string())
    }

    impl SqlStore {
        /// Uses table `weirdnet_tls` in `conn`.
        pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Result<Self> {
            Self::with_table(conn, "weirdnet_tls")
        }

        /// Uses table `table` in `conn`.
        pub fn with_table(conn: Arc<Mutex<rusqlite::Connection>>, table: &str) -> Result<Self> {
            let table = weirdnet_storage::quote_ident(table);
            conn.lock()
                .unwrap()
                .execute_batch(&format!("CREATE TABLE IF NOT EXISTS {table} (k TEXT PRIMARY KEY NOT NULL, v BLOB NOT NULL)"))
                .map_err(db)?;
            Ok(Self { conn, table })
        }
    }

    impl CertStore for SqlStore {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            check_key(key)?;
            let c = self.conn.lock().unwrap();
            c.query_row(&format!("SELECT v FROM {} WHERE k = ?1", self.table), [key], |r| r.get(0)).optional().map_err(db)
        }
        fn put(&self, key: &str, value: &[u8]) -> Result<()> {
            check_key(key)?;
            let c = self.conn.lock().unwrap();
            c.execute(
                &format!("INSERT INTO {} (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", self.table),
                rusqlite::params![key, value],
            )
            .map_err(db)?;
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<()> {
            check_key(key)?;
            let c = self.conn.lock().unwrap();
            c.execute(&format!("DELETE FROM {} WHERE k = ?1", self.table), [key]).map_err(db)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked() {
        for bad in ["", "/a", "a/../b", "a//b", "A", "a b", "./a"] {
            assert!(check_key(bad).is_err(), "{bad:?}");
        }
        check_key("cert/main.json").unwrap();
        assert!(account_key("https://acme-v02.api.letsencrypt.org/directory").starts_with("account/"));
    }

    #[test]
    fn file_store_is_private_and_atomic() {
        let d = tempfile::tempdir().unwrap();
        let s = FileStore::new(d.path().join("tls"));
        assert_eq!(s.get("cert/a.json").unwrap(), None);
        s.put("cert/a.json", b"one").unwrap();
        s.put("cert/a.json", b"two").unwrap();
        assert_eq!(s.get("cert/a.json").unwrap().as_deref(), Some(&b"two"[..]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(d.path().join("tls/cert/a.json")).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
            let m = std::fs::metadata(d.path().join("tls/cert")).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o700);
        }
        assert_eq!(std::fs::read_dir(d.path().join("tls/cert")).unwrap().count(), 1, "no temp files left");
        s.delete("cert/a.json").unwrap();
        s.delete("cert/a.json").unwrap();
        assert_eq!(s.get("cert/a.json").unwrap(), None);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn sql_store_round_trip() {
        use std::sync::{Arc, Mutex};
        let conn = weirdnet_storage::rusqlite::Connection::open_in_memory().unwrap();
        let s = SqlStore::new(Arc::new(Mutex::new(conn))).unwrap();
        assert_eq!(s.get("cert/a.json").unwrap(), None);
        s.put("cert/a.json", b"one").unwrap();
        s.put("cert/a.json", b"two").unwrap();
        assert_eq!(s.get("cert/a.json").unwrap().as_deref(), Some(&b"two"[..]));
        s.delete("cert/a.json").unwrap();
        assert_eq!(s.get("cert/a.json").unwrap(), None);
        assert!(s.put("../x", b"").is_err());
    }

    #[test]
    fn json_round_trip() {
        let s = MemoryStore::new();
        let p = CertPair { chain_pem: "c".into(), key_pem: "k".into() };
        save_cert(&s, "main", &p).unwrap();
        assert_eq!(load_cert(&s, "main").unwrap(), Some(p));
        assert_eq!(s.keys(), vec!["cert/main.json"]);
    }
}
