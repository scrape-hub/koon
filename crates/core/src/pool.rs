use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::OwnedMutexGuard;

use crate::client::BoxedIo;

/// Most idle HTTP/1.1 connections kept per origin (Chrome allows 6 active sockets per group).
const MAX_IDLE_H1_PER_ORIGIN: usize = 6;

/// Most origins remembered as speaking HTTP/2 or HTTP/3.
const MAX_MULTIPLEXED_ORIGINS: usize = 1024;

/// Pool key: scheme, origin and the proxy the connection goes through. Connections are never shared
/// across proxies: a different proxy URL (including its credentials, which often carry a session
/// ID) is a different exit.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub(crate) struct PoolKey {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub proxy: Option<String>,
    /// The HTTP/2 connections Firefox opens for `WebSockets`, apart from those of its requests (see
    /// [`crate::websocket`]).
    pub for_websockets: bool,
}

/// Facts about a connection that every request on it reports.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnInfo {
    /// IP address of the TCP peer (the proxy when one is used).
    pub peer_addr: Option<String>,
    /// Whether the TLS handshake resumed a session.
    pub tls_resumed: bool,
    /// Plain HTTP through an HTTP proxy: requests use absolute-form targets.
    pub absolute_form: bool,
    /// An HTTP/3 connection to an Alt-Svc alternative: its authority, which Firefox names in an
    /// Alt-Used header.
    pub alt_used: Option<String>,
    /// The `ACCEPT_CH` entries of the server's ALPS data: (origin, value).
    pub accept_ch: Option<std::sync::Arc<[(String, String)]>>,
}

impl ConnInfo {
    /// The `ACCEPT_CH` value the server's ALPS data carries for `origin`.
    pub(crate) fn accept_ch_for(&self, origin: &str) -> Option<&str> {
        self.accept_ch
            .as_deref()?
            .iter()
            .find(|(o, _)| o == origin)
            .map(|(_, value)| value.as_str())
    }
}

pub(crate) type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// A multiplexed connection: requests go out on clones of its handle.
#[derive(Clone)]
pub(crate) enum Mux {
    H2(crate::client::H2Conn),
    H3(crate::client::H3Conn),
}

/// A multiplexed connection handed out by the pool, with the ID that [`ConnectionPool::remove_mux`]
/// takes.
pub(crate) struct PooledMux {
    pub mux: Mux,
    pub info: ConnInfo,
    pub id: u64,
}

struct Entry<T> {
    conn: T,
    info: ConnInfo,
    last_used: Instant,
}

/// The connections of one key: at most one multiplexed connection, and idle HTTP/1.1 connections
/// (most recently used last).
#[derive(Default)]
struct Slot {
    mux: Option<Entry<(Mux, u64)>>,
    idle: Vec<Entry<BoxedIo>>,
}

impl Slot {
    fn len(&self) -> usize {
        usize::from(self.mux.is_some()) + self.idle.len()
    }
}

/// Thread-safe connection pool for HTTP/1.1, HTTP/2 and HTTP/3.
///
/// HTTP/2 and HTTP/3 keep one multiplexed connection per key; HTTP/1.1 keeps up to six idle
/// connections per key. Connections idle for longer than `idle_timeout` are dropped, and the pool
/// holds at most `max_size` connections, evicting the least recently used.
///
/// The pool also remembers which keys speak HTTP/2 or HTTP/3, beyond the life of their connections,
/// and gates new connections to them.
pub(crate) struct ConnectionPool {
    slots: Mutex<HashMap<PoolKey, Slot>>,
    max_size: usize,
    idle_timeout: Duration,
    next_id: AtomicU64,
    /// Keys known to be multiplexed, each with the gate a request holds while it opens a connection
    /// to it.
    multiplexed: Mutex<HashMap<PoolKey, Arc<tokio::sync::Mutex<()>>>>,
}

impl ConnectionPool {
    pub fn new(max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            max_size,
            idle_timeout,
            next_id: AtomicU64::new(0),
            multiplexed: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<PoolKey, Slot>> {
        crate::util::lock_recover(&self.slots)
    }

    fn prune(&self, map: &mut HashMap<PoolKey, Slot>) {
        let now = Instant::now();
        let fresh = |last_used: Instant| now.duration_since(last_used) < self.idle_timeout;
        map.retain(|_, slot| {
            slot.idle.retain(|e| fresh(e.last_used));
            if slot.mux.as_ref().is_some_and(|e| !fresh(e.last_used)) {
                slot.mux = None;
            }
            slot.len() > 0
        });
        let total: usize = map.values().map(Slot::len).sum();
        if total < self.max_size {
            return;
        }
        // Evict least recently used connections until there is room.
        let mut ages: Vec<(Instant, PoolKey)> = map
            .iter()
            .flat_map(|(k, slot)| {
                let mux = slot.mux.as_ref().map(|e| e.last_used);
                let idle = slot.idle.iter().map(|e| e.last_used);
                mux.into_iter().chain(idle).map(move |t| (t, k.clone()))
            })
            .collect();
        ages.sort_by_key(|(t, _)| *t);
        for (t, key) in ages.into_iter().take(total + 1 - self.max_size) {
            let Some(slot) = map.get_mut(&key) else {
                continue;
            };
            if slot.mux.as_ref().is_some_and(|e| e.last_used == t) {
                slot.mux = None;
            } else if let Some(pos) = slot.idle.iter().position(|e| e.last_used == t) {
                slot.idle.remove(pos);
            }
            if slot.len() == 0 {
                map.remove(&key);
            }
        }
    }

    /// Take an idle HTTP/1.1 connection (most recently used first).
    pub fn take_h1(&self, key: &PoolKey) -> Option<(BoxedIo, ConnInfo)> {
        let mut map = self.lock();
        let slot = map.get_mut(key)?;
        let now = Instant::now();
        let mut found = None;
        while let Some(entry) = slot.idle.pop() {
            if now.duration_since(entry.last_used) < self.idle_timeout {
                found = Some((entry.conn, entry.info));
                break;
            }
        }
        if slot.len() == 0 {
            map.remove(key);
        }
        found
    }

    /// Return an HTTP/1.1 connection to the pool after a completed exchange.
    pub fn put_h1(&self, key: PoolKey, conn: BoxedIo, info: ConnInfo) {
        // Held for the whole function body, which is exactly as long as it's needed.
        #[allow(clippy::significant_drop_tightening)]
        let mut map = self.lock();
        self.prune(&mut map);
        let slot = map.entry(key).or_default();
        if slot.idle.len() >= MAX_IDLE_H1_PER_ORIGIN {
            return; // dropped: closes the connection
        }
        slot.idle.push(Entry {
            conn,
            info,
            last_used: Instant::now(),
        });
    }

    /// The multiplexed connection for `key`.
    pub fn get_mux(&self, key: &PoolKey) -> Option<PooledMux> {
        #[allow(clippy::significant_drop_tightening)] // see put_h1
        let mut map = self.lock();
        let slot = map.get_mut(key)?;
        let entry = slot.mux.as_mut()?;
        if entry.last_used.elapsed() >= self.idle_timeout {
            slot.mux = None;
            if slot.len() == 0 {
                map.remove(key);
            }
            return None;
        }
        entry.last_used = Instant::now();
        let (mux, id) = &entry.conn;
        Some(PooledMux {
            mux: mux.clone(),
            info: entry.info.clone(),
            id: *id,
        })
    }

    /// Pool a new multiplexed connection for `key`, returning its ID (`None` if not pooled);
    /// requests in flight on the current one still complete when it's replaced. A new HTTP/2
    /// connection always replaces the current one; HTTP/3 replaces HTTP/2 but not another HTTP/3:
    /// a QUIC connection that wins after TCP takes over, as Chrome prefers a QUIC session once it
    /// has one.
    pub fn put_mux(&self, key: PoolKey, mux: Mux, info: ConnInfo) -> Option<u64> {
        self.set_multiplexed(&key, true);
        #[allow(clippy::significant_drop_tightening)] // see put_h1
        let mut map = self.lock();
        self.prune(&mut map);
        let slot = map.entry(key).or_default();
        let current_is_h3 = slot
            .mux
            .as_ref()
            .is_some_and(|e| matches!(e.conn.0, Mux::H3(_)));
        if matches!(mux, Mux::H3(_)) && current_is_h3 {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        slot.mux = Some(Entry {
            conn: (mux, id),
            info,
            last_used: Instant::now(),
        });
        Some(id)
    }

    /// Drop the multiplexed connection `id` of `key` after it failed. A connection that has
    /// replaced it stays.
    pub fn remove_mux(&self, key: &PoolKey, id: u64) {
        let mut map = self.lock();
        if let Some(slot) = map.get_mut(key) {
            if slot.mux.as_ref().is_some_and(|e| e.conn.1 == id) {
                slot.mux = None;
            }
            if slot.len() == 0 {
                map.remove(key);
            }
        }
    }

    /// Remember whether `key` speaks HTTP/2 or HTTP/3.
    pub fn set_multiplexed(&self, key: &PoolKey, multiplexed: bool) {
        let mut known = crate::util::lock_recover(&self.multiplexed);
        if !multiplexed {
            known.remove(key);
            return;
        }
        if known.contains_key(key) {
            return;
        }
        if known.len() >= MAX_MULTIPLEXED_ORIGINS {
            // Forget origins nobody is waiting on.
            known.retain(|_, gate| Arc::strong_count(gate) > 1);
            // Every known origin has a live waiter right now: evict one anyway so the map stays
            // bounded, as `alt_svc.rs`'s and `HostCache`'s caches both already guarantee.
            if known.len() >= MAX_MULTIPLEXED_ORIGINS {
                if let Some(oldest) = known.keys().next().cloned() {
                    known.remove(&oldest);
                }
            }
        }
        known.insert(key.clone(), Arc::default());
    }

    /// For a key known to be multiplexed, wait until no other request is opening a connection to
    /// it, and hold that turn: the connection a request opens is then shared by the ones waiting
    /// behind it, as in Chrome. `None` for other keys, whose requests connect in parallel.
    pub async fn connect_gate(&self, key: &PoolKey) -> Option<OwnedMutexGuard<()>> {
        let gate = crate::util::lock_recover(&self.multiplexed)
            .get(key)?
            .clone();
        Some(gate.lock_owned().await)
    }

    /// Drop all pooled connections immediately.
    pub fn clear(&self) {
        drop(self.take_all());
    }

    /// Take all pooled connections out of the pool. They are released when the returned value is
    /// dropped.
    pub fn take_all(&self) -> Taken {
        Taken {
            _slots: std::mem::take(&mut *self.lock()),
        }
    }
}

/// Connections taken out of the pool (see [`ConnectionPool::take_all`]).
pub(crate) struct Taken {
    _slots: HashMap<PoolKey, Slot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: usize) -> PoolKey {
        PoolKey {
            secure: true,
            host: format!("h{i}.test"),
            port: 443,
            proxy: None,
            for_websockets: false,
        }
    }

    /// If every known origin happens to have a live waiter at once, `retain` frees no room; the
    /// insert below it must still not let `known` grow past the cap.
    #[tokio::test]
    async fn set_multiplexed_stays_bounded_when_every_known_key_has_a_waiter() {
        let pool = ConnectionPool::new(256, Duration::from_secs(90));
        let mut guards = Vec::new();
        for i in 0..MAX_MULTIPLEXED_ORIGINS {
            let k = key(i);
            pool.set_multiplexed(&k, true);
            guards.push(
                pool.connect_gate(&k)
                    .await
                    .expect("just marked multiplexed"),
            );
        }
        pool.set_multiplexed(&key(MAX_MULTIPLEXED_ORIGINS), true);
        assert_eq!(
            crate::util::lock_recover(&pool.multiplexed).len(),
            MAX_MULTIPLEXED_ORIGINS
        );
        drop(guards);
    }
}
