use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use btls::ssl::{SslSession, SslVersion};
use serde::{Deserialize, Serialize};
use url::Url;

/// Tickets kept per key. Servers usually issue two per connection; keeping both lets two new
/// connections resume without reusing a ticket.
const MAX_SESSIONS_PER_KEY: usize = 2;

/// Most keys kept. With proxy rotation every proxy/origin pair is a key, and a session holds the
/// server's certificate chain (several KB); the least recently used key goes first.
const MAX_KEYS: usize = 2000;

/// Exported TLS session cache data for save/load. Each entry maps a cache key (`host:port`, plus
/// `|proxy` for sessions established through a proxy) to a base64-encoded DER-serialized session.
/// The proxy part never contains the proxy's password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCacheExport {
    /// Cache key to base64-encoded DER session mapping.
    pub sessions: HashMap<String, String>,
}

struct Entry {
    /// Oldest first.
    sessions: VecDeque<SslSession>,
    /// When the key was last stored or taken from, for LRU eviction.
    last_used: u64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Entry>,
    clock: u64,
}

impl Inner {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Make room for a new key: drop expired sessions, then the least recently used key.
    fn make_room(&mut self) {
        if self.map.len() < MAX_KEYS {
            return;
        }
        let now = unix_now();
        self.map.retain(|_, entry| {
            entry.sessions.retain(|s| !expired(s, now));
            !entry.sessions.is_empty()
        });
        if self.map.len() >= MAX_KEYS {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                self.map.remove(&key);
            }
        }
    }
}

/// Thread-safe TLS session cache for session resumption. Sessions are scoped to origin and proxy,
/// so a ticket never links connections that leave through different proxies. TLS 1.3 tickets are
/// single-use (RFC 8446 Appendix C.4), as in browsers: a ticket is removed when a connection offers
/// it. Expired sessions are never offered, and the cache keeps at most 2000 keys.
#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<Inner>>,
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache key for sessions to `host:port`, optionally through `proxy`.
pub fn session_key(host: &str, port: u16, proxy: Option<&Url>) -> String {
    match proxy {
        Some(proxy) => format!("{host}:{port}|{}", proxy_id(proxy)),
        None => format!("{host}:{port}"),
    }
}

/// A proxy as it appears in a session key: scheme, user name, host and port. The user name often
/// selects the exit (rotating residential proxies); the password stays out, since keys are exported
/// to disk.
fn proxy_id(proxy: &Url) -> String {
    let mut id = format!("{}://", proxy.scheme());
    if !proxy.username().is_empty() {
        id.push_str(proxy.username());
        id.push('@');
    }
    id.push_str(proxy.host_str().unwrap_or_default());
    if let Some(port) = proxy.port() {
        id.push_str(&format!(":{port}"));
    }
    id
}

/// Whether `key` has the form [`session_key`] gives it: `host:port`, plus `|proxy` with the proxy
/// as [`proxy_id`] writes it (no password).
pub fn is_session_key(key: &str) -> bool {
    let (origin, proxy) = match key.split_once('|') {
        Some((origin, proxy)) => (origin, Some(proxy)),
        None => (key, None),
    };
    let origin_ok = origin
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    origin_ok
        && proxy.is_none_or(|proxy| Url::parse(proxy).is_ok_and(|url| proxy_id(&url) == proxy))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether a session is past its lifetime (for TLS 1.3, the ticket lifetime the server announced).
fn expired(session: &SslSession, now: u64) -> bool {
    session.time().saturating_add(u64::from(session.timeout())) <= now
}

impl SessionCache {
    /// Create an empty session cache.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Store a session under `key`, keeping the newest ones.
    pub fn insert(&self, key: &str, session: SslSession) {
        let mut inner = crate::util::lock_recover(&self.inner);
        if !inner.map.contains_key(key) {
            inner.make_room();
        }
        let now = inner.tick();
        let entry = inner.map.entry(key.to_string()).or_insert_with(|| Entry {
            sessions: VecDeque::new(),
            last_used: now,
        });
        entry.last_used = now;
        entry.sessions.push_back(session);
        while entry.sessions.len() > MAX_SESSIONS_PER_KEY {
            entry.sessions.pop_front();
        }
    }

    /// Get a session to offer for `key`. TLS 1.3 sessions are removed from the cache (single use);
    /// TLS 1.2 sessions stay. Expired sessions are dropped.
    pub fn take(&self, key: &str) -> Option<SslSession> {
        let mut inner = crate::util::lock_recover(&self.inner);
        let now = inner.tick();
        let entry = inner.map.get_mut(key)?;
        let unix = unix_now();
        entry.sessions.retain(|s| !expired(s, unix));
        entry.last_used = now;
        let session = match entry.sessions.back() {
            Some(newest) if newest.protocol_version() == SslVersion::TLS1_3 => {
                entry.sessions.pop_back()
            }
            Some(newest) => Some(newest.clone()),
            None => None,
        };
        if entry.sessions.is_empty() {
            inner.map.remove(key);
        }
        session
    }

    /// Export the newest session per key as base64-encoded DER.
    pub fn export(&self) -> SessionCacheExport {
        let engine = base64::engine::general_purpose::STANDARD;
        let inner = crate::util::lock_recover(&self.inner);
        let sessions = inner
            .map
            .iter()
            .filter_map(|(key, entry)| {
                let der = entry.sessions.back()?.to_der().ok()?;
                Some((key.clone(), engine.encode(der)))
            })
            .collect();
        SessionCacheExport { sessions }
    }

    /// Import sessions from a previously exported `SessionCacheExport`. Existing sessions under the
    /// same key are replaced.
    pub fn import(&self, export: &SessionCacheExport) {
        let engine = base64::engine::general_purpose::STANDARD;
        let mut inner = crate::util::lock_recover(&self.inner);
        for (key, b64) in &export.sessions {
            let Ok(der) = engine.decode(b64) else {
                continue;
            };
            let Ok(session) = SslSession::from_der(&der) else {
                continue;
            };
            if !inner.map.contains_key(key) {
                inner.make_room();
            }
            let now = inner.tick();
            inner.map.insert(
                key.clone(),
                Entry {
                    sessions: VecDeque::from([session]),
                    last_used: now,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_keeps_the_proxy_password_out() {
        let proxy = Url::parse("http://user-session-7:secret@proxy.test:8080").unwrap();
        assert_eq!(
            session_key("a.com", 443, Some(&proxy)),
            "a.com:443|http://user-session-7@proxy.test:8080"
        );
        let proxy = Url::parse("socks5://proxy.test").unwrap();
        assert_eq!(
            session_key("a.com", 443, Some(&proxy)),
            "a.com:443|socks5://proxy.test"
        );
        assert_eq!(session_key("a.com", 8443, None), "a.com:8443");
    }

    #[test]
    fn test_only_keys_of_session_key_form_are_valid() {
        let proxy = Url::parse("http://user-session-7:secret@proxy.test:8080").unwrap();
        for key in [
            session_key("a.com", 443, None),
            session_key("a.com", 8443, Some(&proxy)),
            session_key("::1", 443, None),
        ] {
            assert!(is_session_key(&key), "{key}");
        }
        for key in [
            "a.com",
            ":443",
            "a.com:https",
            "a.com:443|http://u:pw@proxy.test:8080/",
            "a.com:443|HTTP://proxy.test",
            "a.com:443|not a url",
        ] {
            assert!(!is_session_key(key), "{key}");
        }
    }
}
