//! TTL-bounded cache for HTTPS record lookups, shared by the DoH and the native (plain) resolver:
//! both reuse an answer, positive or negative, for [`HTTPS_CACHE_TTL`] instead of asking again on
//! every connection.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::HttpsRecord;
use crate::Error;

/// How long an HTTPS record (or its absence) is reused.
const HTTPS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Most HTTPS records kept.
const HTTPS_CACHE_SIZE: usize = 1000;

struct Entry {
    records: Vec<HttpsRecord>,
    expires: Instant,
}

/// Cache of HTTPS record lookups, keyed by hostname.
#[derive(Default)]
pub(super) struct HttpsRecordCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl HttpsRecordCache {
    /// A cached answer for `hostname`, unless it expired.
    pub(super) fn get(&self, hostname: &str) -> Option<Vec<HttpsRecord>> {
        let cache = crate::util::lock_recover(&self.entries);
        cache
            .get(hostname)
            .filter(|entry| entry.expires > Instant::now())
            .map(|entry| entry.records.clone())
    }

    /// Cache `records` (none: no record) for `hostname`.
    pub(super) fn insert(&self, hostname: &str, records: Vec<HttpsRecord>) {
        let mut cache = crate::util::lock_recover(&self.entries);
        let now = Instant::now();
        if cache.len() >= HTTPS_CACHE_SIZE {
            cache.retain(|_, entry| entry.expires > now);
        }
        if cache.len() >= HTTPS_CACHE_SIZE {
            let oldest = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(host, _)| host.clone());
            if let Some(host) = oldest {
                cache.remove(&host);
            }
        }
        cache.insert(
            hostname.to_string(),
            Entry {
                records,
                expires: now + HTTPS_CACHE_TTL,
            },
        );
    }

    /// The cached answer for `hostname`, or `fetch`'s result, cached before it is returned. Shared
    /// by [`super::NativeHttpsResolver`] and [`super::DohResolver`], whose `query_https_records`
    /// differ only in how they fetch an answer that isn't cached yet.
    pub(super) async fn get_or_insert_with<F, Fut>(
        &self,
        hostname: &str,
        fetch: F,
    ) -> Result<Vec<HttpsRecord>, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<HttpsRecord>, Error>>,
    {
        if let Some(cached) = self.get(hostname) {
            return Ok(cached);
        }
        let result = fetch().await?;
        self.insert(hostname, result.clone());
        Ok(result)
    }
}
