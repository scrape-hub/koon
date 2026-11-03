use std::sync::{Mutex, MutexGuard};

pub(crate) fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn site(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map(str::to_string).unwrap_or(host)
}

pub(crate) fn same_site(host1: &str, host2: &str) -> bool {
    site(host1) == site(host2)
}

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
}
