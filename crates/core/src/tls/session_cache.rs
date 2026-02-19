use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use boring2::ssl::SslSession;

/// Thread-safe TLS session cache for session resumption.
///
/// Stores `SslSession` objects keyed by hostname. When a client reconnects
/// to the same host, the cached session enables TLS session resumption,
/// which skips the full handshake — just like real browsers do.
#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<HashMap<String, SslSession>>>,
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
}
