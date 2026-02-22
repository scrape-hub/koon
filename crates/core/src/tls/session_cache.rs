use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use boring2::ssl::SslSession;
use serde::{Deserialize, Serialize};

/// Exported TLS session cache data for save/load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCacheExport {
    /// hostname → base64-encoded DER bytes
    pub sessions: HashMap<String, String>,
}

/// Thread-safe TLS session cache for session resumption.
///
/// Stores `SslSession` objects keyed by hostname. When a client reconnects
/// to the same host, the cached session enables TLS session resumption,
/// which skips the full handshake — just like real browsers do.
#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<HashMap<String, SslSession>>>,
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCache {
    pub fn new() -> Self {
        SessionCache {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store a session for the given hostname (replaces any existing).
    pub fn insert(&self, host: &str, session: SslSession) {
        self.inner.lock().unwrap().insert(host.to_string(), session);
    }

    /// Retrieve a cached session for the given hostname.
    pub fn get(&self, host: &str) -> Option<SslSession> {
        self.inner.lock().unwrap().get(host).cloned()
    }

    /// Export all cached sessions as base64-encoded DER data.
    pub fn export(&self) -> SessionCacheExport {
        let engine = base64::engine::general_purpose::STANDARD;
        let map = self.inner.lock().unwrap();
        let mut sessions = HashMap::new();
        for (host, session) in map.iter() {
            if let Ok(der) = session.to_der() {
                sessions.insert(host.clone(), engine.encode(&der));
            }
        }
        SessionCacheExport { sessions }
    }

    /// Import sessions from a previously exported `SessionCacheExport`.
    /// Existing sessions are replaced.
    pub fn import(&self, export: &SessionCacheExport) {
        let engine = base64::engine::general_purpose::STANDARD;
        let mut map = self.inner.lock().unwrap();
        for (host, b64) in &export.sessions {
            if let Ok(der) = engine.decode(b64) {
                if let Ok(session) = SslSession::from_der(&der) {
                    map.insert(host.clone(), session);
                }
            }
        }
    }
}
