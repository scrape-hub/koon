use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http2::client::SendRequest;
use tokio::net::TcpStream;
use tokio_boring2::SslStream;

/// Pool key: one connection per origin (host + port) + proxy index.
/// When proxy rotation is active, each proxy gets its own connections per origin.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct PoolKey {
    host: String,
    port: u16,
    proxy_index: Option<usize>,
}

/// A cached connection to an origin — H2, H1.1, or H3.
enum PoolEntry {
    Http2(SendRequest<Bytes>),
    Http11(SslStream<TcpStream>),
    Http3(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>),
}

/// Wraps a pool entry with its insertion timestamp for TTL eviction.
struct TimedEntry {
    entry: PoolEntry,
    inserted_at: Instant,
}

/// Thread-safe connection pool supporting HTTP/2, HTTP/1.1, and HTTP/3.
///
/// Stores one connection per origin — this matches real browser behavior
/// where a single H2 connection is multiplexed, or a single H1.1 keep-alive
/// connection is reused.
///
/// Idle connections are evicted after `ttl` (default 90s, matching Chrome),
/// and the pool is capped at `max_size` entries.
pub(crate) struct ConnectionPool {
    connections: Mutex<HashMap<PoolKey, TimedEntry>>,
    max_size: usize,
    ttl: Duration,
}

impl ConnectionPool {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        ConnectionPool {
            connections: Mutex::new(HashMap::new()),
            max_size,
            ttl,
        }
    }

    /// Remove all entries whose TTL has expired. Must be called with lock held.
    fn evict_expired(connections: &mut HashMap<PoolKey, TimedEntry>, ttl: Duration) {
        let now = Instant::now();
        connections.retain(|_, entry| now.duration_since(entry.inserted_at) < ttl);
    }

    /// If the pool is at capacity, remove the oldest entry. Must be called with lock held.
    fn evict_oldest(connections: &mut HashMap<PoolKey, TimedEntry>, max_size: usize) {
        if connections.len() >= max_size {
            if let Some(oldest_key) = connections
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone())
            {
                connections.remove(&oldest_key);
            }
        }
    }

    /// Try to get an existing H2 connection for the given origin.
    pub fn try_get_h2(&self, host: &str, port: u16, proxy_index: Option<usize>) -> Option<SendRequest<Bytes>> {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        let mut conns = self.connections.lock().unwrap();
        match conns.get(&key) {
            Some(timed) if Instant::now().duration_since(timed.inserted_at) < self.ttl => {
                match &timed.entry {
                    PoolEntry::Http2(sender) => Some(sender.clone()),
                    _ => None,
                }
            }
            Some(_) => {
                conns.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Try to take an existing H1.1 connection for the given origin.
    /// Unlike H2, H1.1 connections are taken (removed) from the pool since they are not multiplexed.
    pub fn try_take_h1(&self, host: &str, port: u16, proxy_index: Option<usize>) -> Option<SslStream<TcpStream>> {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        let mut conns = self.connections.lock().unwrap();
        match conns.get(&key) {
            Some(timed) if Instant::now().duration_since(timed.inserted_at) < self.ttl => {
                match &timed.entry {
                    PoolEntry::Http11(_) => match conns.remove(&key) {
                        Some(TimedEntry {
                            entry: PoolEntry::Http11(stream),
                            ..
                        }) => Some(stream),
                        _ => None,
                    },
                    _ => None,
                }
            }
            Some(_) => {
                conns.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Store an H2 connection in the pool.
    pub fn insert_h2(&self, host: &str, port: u16, proxy_index: Option<usize>, sender: SendRequest<Bytes>) {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        let mut conns = self.connections.lock().unwrap();
        Self::evict_expired(&mut conns, self.ttl);
        Self::evict_oldest(&mut conns, self.max_size);
        conns.insert(
            key,
            TimedEntry {
                entry: PoolEntry::Http2(sender),
                inserted_at: Instant::now(),
            },
        );
    }

    /// Store an H1.1 connection in the pool for keep-alive reuse.
    pub fn insert_h1(&self, host: &str, port: u16, proxy_index: Option<usize>, stream: SslStream<TcpStream>) {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        let mut conns = self.connections.lock().unwrap();
        Self::evict_expired(&mut conns, self.ttl);
        Self::evict_oldest(&mut conns, self.max_size);
        conns.insert(
            key,
            TimedEntry {
                entry: PoolEntry::Http11(stream),
                inserted_at: Instant::now(),
            },
        );
    }

    /// Try to get an existing H3 connection for the given origin.
    pub fn try_get_h3(
        &self,
        host: &str,
        port: u16,
        proxy_index: Option<usize>,
    ) -> Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        let mut conns = self.connections.lock().unwrap();
        match conns.get(&key) {
            Some(timed) if Instant::now().duration_since(timed.inserted_at) < self.ttl => {
                match &timed.entry {
                    PoolEntry::Http3(sender) => Some(sender.clone()),
                    _ => None,
                }
            }
            Some(_) => {
                conns.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Store an H3 connection in the pool.
    pub fn insert_h3(
        &self,
        host: &str,
        port: u16,
        proxy_index: Option<usize>,
        sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    ) {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        let mut conns = self.connections.lock().unwrap();
        Self::evict_expired(&mut conns, self.ttl);
        Self::evict_oldest(&mut conns, self.max_size);
        conns.insert(
            key,
            TimedEntry {
                entry: PoolEntry::Http3(sender),
                inserted_at: Instant::now(),
            },
        );
    }

    /// Remove a dead connection from the pool.
    pub fn remove(&self, host: &str, port: u16, proxy_index: Option<usize>) {
        let key = PoolKey {
            host: host.to_string(),
            port,
            proxy_index,
        };
        self.connections.lock().unwrap().remove(&key);
    }
}
