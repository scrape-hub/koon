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

/// Keys with HTTP/1.1 slot counters kept once none is in use (see [`ConnectionPool::h1_slot`]).
const MAX_IDLE_H1_SLOT_KEYS: usize = 1024;

/// How long a browser keeps an idle connection, HTTP/1.1 and multiplexed (HTTP/2, HTTP/3) apart;
/// `None` keeps it until the server closes it. Checked when the pool is next used, as Chromium does
/// (`CleanupIdleSockets` on a socket request).
#[derive(Clone, Copy, Debug)]
pub(crate) struct IdleTimeouts {
    pub h1: Duration,
    pub mux: Option<Duration>,
}

impl IdleTimeouts {
    fn h1_fresh(&self, last_used: Instant, now: Instant) -> bool {
        now.duration_since(last_used) < self.h1
    }

    fn mux_fresh(&self, last_used: Instant, now: Instant) -> bool {
        self.mux
            .is_none_or(|timeout| now.duration_since(last_used) < timeout)
    }
}

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
/// connections per key. Connections idle for longer than their [`IdleTimeouts`] are dropped, and
/// the pool holds at most `max_size` connections, evicting the least recently used.
///
/// The pool also remembers which keys speak HTTP/2 or HTTP/3, beyond the life of their connections,
/// and gates new connections to them.
pub(crate) struct ConnectionPool {
    slots: Mutex<HashMap<PoolKey, Slot>>,
    max_size: usize,
    timeouts: IdleTimeouts,
    next_id: AtomicU64,
    /// Keys known to be multiplexed, each with the gate a request holds while it opens a connection
    /// to it.
    multiplexed: Mutex<HashMap<PoolKey, Arc<tokio::sync::Mutex<()>>>>,
    /// The HTTP/1.1 connections in use per key, as slots (see [`h1_slot`](Self::h1_slot)).
    h1_slots: Mutex<HashMap<PoolKey, Arc<tokio::sync::Semaphore>>>,
}

impl ConnectionPool {
    pub fn new(max_size: usize, timeouts: IdleTimeouts) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            max_size,
            timeouts,
            next_id: AtomicU64::new(0),
            multiplexed: Mutex::new(HashMap::new()),
            h1_slots: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<PoolKey, Slot>> {
        crate::util::lock_recover(&self.slots)
    }

    fn prune(&self, map: &mut HashMap<PoolKey, Slot>) {
        let now = Instant::now();
        map.retain(|_, slot| {
            slot.idle
                .retain(|e| self.timeouts.h1_fresh(e.last_used, now));
            if slot
                .mux
                .as_ref()
                .is_some_and(|e| !self.timeouts.mux_fresh(e.last_used, now))
            {
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
            if self.timeouts.h1_fresh(entry.last_used, now) {
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
        if !self.timeouts.mux_fresh(entry.last_used, Instant::now()) {
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
    /// Whether `key` is known to speak HTTP/2 or HTTP/3.
    pub fn is_multiplexed(&self, key: &PoolKey) -> bool {
        crate::util::lock_recover(&self.multiplexed).contains_key(key)
    }

    /// Wait for one of `limit` slots of `key`: a request holds one while it opens or uses an
    /// HTTP/1.1 connection, and further requests queue for it, as a browser keeps at most a few
    /// such connections per origin. Dropping the permit frees the slot.
    pub async fn h1_slot(
        &self,
        key: &PoolKey,
        limit: usize,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let semaphore = {
            let mut slots = crate::util::lock_recover(&self.h1_slots);
            if slots.len() >= MAX_IDLE_H1_SLOT_KEYS {
                // A key nobody holds or waits for has all its slots free: forget it.
                slots.retain(|_, slots| Arc::strong_count(slots) > 1);
            }
            slots
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(limit)))
                .clone()
        };
        // Never closed, so this always gets a permit.
        semaphore.acquire_owned().await.ok()
    }

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

    const TEST_TIMEOUTS: IdleTimeouts = IdleTimeouts {
        h1: Duration::from_secs(90),
        mux: Some(Duration::from_secs(90)),
    };

    #[tokio::test]
    async fn idle_connections_last_as_long_as_the_browser_keeps_them() {
        let timeouts = IdleTimeouts {
            h1: Duration::from_millis(50),
            mux: None,
        };
        let pool = ConnectionPool::new(256, timeouts);
        let (io, _peer) = tokio::io::duplex(64);
        pool.put_h1(key(0), Box::new(io), ConnInfo::default());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(pool.take_h1(&key(0)).is_none());

        // Chromium keeps an idle HTTP/2 session until the server closes it.
        let long_ago = Instant::now() - Duration::from_secs(24 * 60 * 60);
        assert!(timeouts.mux_fresh(long_ago, Instant::now()));
        assert!(!TEST_TIMEOUTS.mux_fresh(long_ago, Instant::now()));
    }

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
        let pool = ConnectionPool::new(256, TEST_TIMEOUTS);
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
