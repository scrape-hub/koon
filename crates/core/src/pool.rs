use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::OwnedMutexGuard;

use crate::client::BoxedIo;

const MAX_IDLE_H1_PER_ORIGIN: usize = 6;

const MAX_MULTIPLEXED_ORIGINS: usize = 1024;

const MAX_IDLE_H1_SLOT_KEYS: usize = 1024;

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

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub(crate) struct PoolKey {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub proxy: Option<String>,
    pub for_websockets: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ConnInfo {
    pub peer_addr: Option<String>,
    pub tls_resumed: bool,
    pub absolute_form: bool,
    pub alt_used: Option<String>,
    pub accept_ch: Option<std::sync::Arc<[(String, String)]>>,
}

impl ConnInfo {
    pub(crate) fn accept_ch_for(&self, origin: &str) -> Option<&str> {
        self.accept_ch
            .as_deref()?
            .iter()
            .find(|(o, _)| o == origin)
            .map(|(_, value)| value.as_str())
    }
}

pub(crate) type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Clone)]
pub(crate) enum Mux {
    H2(crate::client::H2Conn),
    H3(crate::client::H3Conn),
}

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

pub(crate) struct ConnectionPool {
    slots: Mutex<HashMap<PoolKey, Slot>>,
    max_size: usize,
    timeouts: IdleTimeouts,
    next_id: AtomicU64,
    multiplexed: Mutex<HashMap<PoolKey, Arc<tokio::sync::Mutex<()>>>>,
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

    pub fn put_h1(&self, key: PoolKey, conn: BoxedIo, info: ConnInfo) {
        #[allow(clippy::significant_drop_tightening)]
        let mut map = self.lock();
        self.prune(&mut map);
        let slot = map.entry(key).or_default();
        if slot.idle.len() >= MAX_IDLE_H1_PER_ORIGIN {
            return;
        }
        slot.idle.push(Entry {
            conn,
            info,
            last_used: Instant::now(),
        });
    }

    pub fn get_mux(&self, key: &PoolKey) -> Option<PooledMux> {
        #[allow(clippy::significant_drop_tightening)]
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

    pub fn put_mux(&self, key: PoolKey, mux: Mux, info: ConnInfo) -> Option<u64> {
        self.set_multiplexed(&key, true);
        #[allow(clippy::significant_drop_tightening)]
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
            known.retain(|_, gate| Arc::strong_count(gate) > 1);
            if known.len() >= MAX_MULTIPLEXED_ORIGINS {
                if let Some(oldest) = known.keys().next().cloned() {
                    known.remove(&oldest);
                }
            }
        }
        known.insert(key.clone(), Arc::default());
    }

    pub fn is_multiplexed(&self, key: &PoolKey) -> bool {
        crate::util::lock_recover(&self.multiplexed).contains_key(key)
    }

    pub async fn h1_slot(
        &self,
        key: &PoolKey,
        limit: usize,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let semaphore = {
            let mut slots = crate::util::lock_recover(&self.h1_slots);
            if slots.len() >= MAX_IDLE_H1_SLOT_KEYS {
                slots.retain(|_, slots| Arc::strong_count(slots) > 1);
            }
            slots
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(limit)))
                .clone()
        };
        semaphore.acquire_owned().await.ok()
    }

    pub async fn connect_gate(&self, key: &PoolKey) -> Option<OwnedMutexGuard<()>> {
        let gate = crate::util::lock_recover(&self.multiplexed)
            .get(key)?
            .clone();
        Some(gate.lock_owned().await)
    }

    pub fn clear(&self) {
        drop(self.take_all());
    }

    pub fn take_all(&self) -> Taken {
        Taken {
            _slots: std::mem::take(&mut *self.lock()),
        }
    }
}

pub(crate) struct Taken {
    _slots: HashMap<PoolKey, Slot>,
}
