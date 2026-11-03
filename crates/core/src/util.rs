//! Small internal utilities shared across modules.

use std::sync::{Mutex, MutexGuard};

/// Acquire a mutex, recovering from a poisoned state instead of panicking.
///
/// A poisoned mutex means another thread panicked while holding the lock, but the data it protects
/// is still structurally valid. Recovering keeps a single panic from cascading: otherwise every
/// later `.lock().unwrap()` on the same mutex would panic in turn and leave the client permanently
/// unusable.
pub(crate) fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The site of a host: its registrable domain (eTLD+1, Public Suffix List), lowercase; a host
/// without one (an IP address, `localhost`) is its own site.
pub(crate) fn site(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    psl::domain_str(&host).map(str::to_string).unwrap_or(host)
}

/// Whether two hosts belong to the same site.
pub(crate) fn same_site(host1: &str, host2: &str) -> bool {
    site(host1) == site(host2)
}

/// An LRU cache of at most `max` entries that allocates as it fills: `lru::LruCache::new` sizes its
/// map for the whole capacity at once (about 270 KiB for 10,000 entries), in every client.
#[derive(Debug)]
pub(crate) struct GrowingLru<K: std::hash::Hash + Eq, V> {
    cache: lru::LruCache<K, V>,
    max: usize,
}

impl<K: std::hash::Hash + Eq, V> GrowingLru<K, V> {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            cache: lru::LruCache::unbounded(),
            max,
        }
    }

    pub(crate) fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.cache.get(key)
    }

    /// Insert or replace `key`, evicting the least recently used entry past `max`.
    pub(crate) fn put(&mut self, key: K, value: V) {
        self.cache.put(key, value);
        if self.cache.len() > self.max {
            self.cache.pop_lru();
        }
    }

    pub(crate) fn pop<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.cache.pop(key)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.cache.len()
    }
}
