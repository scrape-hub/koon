use std::collections::HashMap;
use std::sync::Mutex;

use bytes::Bytes;
use http2::client::SendRequest;
use tokio::net::TcpStream;
use tokio_boring2::SslStream;

/// Pool key: one connection per origin (host + port), like a real browser.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct PoolKey {
    host: String,
    port: u16,
}

/// A cached connection to an origin — either H2 (multiplexed) or H1.1 (single stream).
enum PoolEntry {
    Http2(SendRequest<Bytes>),
    Http11(SslStream<TcpStream>),
}

/// Thread-safe connection pool supporting both HTTP/2 and HTTP/1.1.
///
/// Stores one connection per origin — this matches real browser behavior
/// where a single H2 connection is multiplexed, or a single H1.1 keep-alive
/// connection is reused.
pub(crate) struct ConnectionPool {
    connections: Mutex<HashMap<PoolKey, PoolEntry>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        ConnectionPool {
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Try to get an existing H2 connection for the given origin.
    pub fn try_get_h2(&self, host: &str, port: u16) -> Option<SendRequest<Bytes>> {
        let key = PoolKey {
            host: host.to_string(),
            port,
        };
        let conns = self.connections.lock().unwrap();
        match conns.get(&key) {
            Some(PoolEntry::Http2(sender)) => Some(sender.clone()),
            _ => None,
        }
    }

    /// Try to take an existing H1.1 connection for the given origin.
    /// Unlike H2, H1.1 connections are taken (removed) from the pool since they are not multiplexed.
    pub fn try_take_h1(&self, host: &str, port: u16) -> Option<SslStream<TcpStream>> {
        let key = PoolKey {
            host: host.to_string(),
            port,
        };
        let mut conns = self.connections.lock().unwrap();
        match conns.get(&key) {
            Some(PoolEntry::Http11(_)) => match conns.remove(&key) {
                Some(PoolEntry::Http11(stream)) => Some(stream),
                _ => None,
            },
            _ => None,
        }
    }

    /// Store an H2 connection in the pool.
    pub fn insert_h2(&self, host: &str, port: u16, sender: SendRequest<Bytes>) {
        let key = PoolKey {
            host: host.to_string(),
            port,
        };
        self.connections
            .lock()
            .unwrap()
            .insert(key, PoolEntry::Http2(sender));
    }

    /// Store an H1.1 connection in the pool for keep-alive reuse.
    pub fn insert_h1(&self, host: &str, port: u16, stream: SslStream<TcpStream>) {
        let key = PoolKey {
            host: host.to_string(),
            port,
        };
        self.connections
            .lock()
            .unwrap()
            .insert(key, PoolEntry::Http11(stream));
    }

    /// Remove a dead connection from the pool.
    pub fn remove(&self, host: &str, port: u16) {
        let key = PoolKey {
            host: host.to_string(),
            port,
        };
        self.connections.lock().unwrap().remove(&key);
    }
}
