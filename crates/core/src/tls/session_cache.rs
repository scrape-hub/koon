use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use btls::ssl::{SslSession, SslVersion};
use serde::{Deserialize, Serialize};
use url::Url;

const MAX_SESSIONS_PER_KEY: usize = 2;

const MAX_KEYS: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCacheExport {
    pub sessions: HashMap<String, String>,
}

struct Entry {
    sessions: VecDeque<SslSession>,
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

#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<Inner>>,
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn session_key(host: &str, port: u16, proxy: Option<&Url>) -> String {
    match proxy {
        Some(proxy) => format!("{host}:{port}|{}", proxy_id(proxy)),
        None => format!("{host}:{port}"),
    }
}

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

fn expired(session: &SslSession, now: u64) -> bool {
    session.time().saturating_add(u64::from(session.timeout())) <= now
}

impl SessionCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

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
