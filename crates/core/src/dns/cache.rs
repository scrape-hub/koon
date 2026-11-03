use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::HttpsRecord;
use crate::Error;

const HTTPS_CACHE_TTL: Duration = Duration::from_secs(300);

const HTTPS_CACHE_SIZE: usize = 1000;

struct Entry {
    records: Vec<HttpsRecord>,
    expires: Instant,
}

#[derive(Default)]
pub(super) struct HttpsRecordCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl HttpsRecordCache {
    pub(super) fn get(&self, hostname: &str) -> Option<Vec<HttpsRecord>> {
        let cache = crate::util::lock_recover(&self.entries);
        cache
            .get(hostname)
            .filter(|entry| entry.expires > Instant::now())
            .map(|entry| entry.records.clone())
    }

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
