use std::collections::HashMap;
use std::time::{Duration, Instant};

use http::Uri;

use crate::error::Error;

const BROKEN_INITIAL: Duration = Duration::from_secs(300);
const BROKEN_MAX: Duration = Duration::from_secs(48 * 3600);

const MAX_ENTRIES: usize = 1000;

pub(super) struct AltSvcEntry {
    pub(super) h3_port: u16,
    pub(super) expires: Instant,
}

struct Broken {
    until: Instant,
    failures: u32,
}

#[derive(Default)]
pub(super) struct AltSvcCache {
    entries: HashMap<(String, u16), AltSvcEntry>,
    broken: HashMap<(String, u16), Broken>,
}

pub(super) fn make_room<K: Eq + std::hash::Hash + Clone, V>(
    map: &mut HashMap<K, V>,
    limit: usize,
    expires: impl Fn(&V) -> Instant,
) {
    if map.len() < limit {
        return;
    }
    let now = Instant::now();
    map.retain(|_, v| expires(v) > now);
    if map.len() >= limit {
        let first = map
            .iter()
            .min_by_key(|(_, v)| expires(v))
            .map(|(k, _)| k.clone());
        if let Some(key) = first {
            map.remove(&key);
        }
    }
}

impl AltSvcCache {
    pub(super) fn mark_broken(&mut self, host: &str, port: u16) {
        let key = (host.to_string(), port);
        if !self.broken.contains_key(&key) {
            make_room(&mut self.broken, MAX_ENTRIES, |b| b.until);
        }
        let broken = self.broken.entry(key).or_insert(Broken {
            until: Instant::now(),
            failures: 0,
        });
        broken.failures += 1;
        let delay = BROKEN_INITIAL
            .checked_mul(1 << (broken.failures - 1).min(10))
            .unwrap_or(BROKEN_MAX)
            .min(BROKEN_MAX);
        broken.until = Instant::now() + delay;
    }

    pub(super) fn confirm(&mut self, host: &str, port: u16) {
        self.broken.remove(&(host.to_string(), port));
    }

    fn insert(&mut self, key: (String, u16), entry: AltSvcEntry) {
        if !self.entries.contains_key(&key) {
            make_room(&mut self.entries, MAX_ENTRIES, |e| e.expires);
        }
        self.entries.insert(key, entry);
    }
}

pub(super) fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

pub(super) fn resolve_redirect(base: &Uri, location: &str) -> Result<Uri, Error> {
    let base = url::Url::parse(&base.to_string())?;
    let mut next = base.join(location.trim())?;
    if !matches!(next.scheme(), "http" | "https") {
        return Err(Error::UnsupportedScheme(format!(
            "'{}' in redirect target {next}",
            next.scheme()
        )));
    }
    next.set_fragment(None);
    next.as_str()
        .parse()
        .map_err(|_| Error::Url(url::ParseError::InvalidDomainCharacter))
}

fn parse_alt_svc_max_age(entry: &str) -> Option<u64> {
    entry.split(';').find_map(|part| {
        part.trim()
            .strip_prefix("ma=")
            .and_then(|v| v.trim().parse().ok())
    })
}

impl super::Client {
    pub(super) fn follows_alt_svc(&self) -> bool {
        self.profile.quic.as_ref().is_some_and(|quic| quic.alt_svc)
    }

    pub(super) fn follows_https_rr(&self) -> bool {
        self.profile
            .quic
            .as_ref()
            .is_some_and(|quic| quic.https_rr && (!quic.https_rr_doh_only || self.uses_doh()))
    }

    fn uses_doh(&self) -> bool {
        #[cfg(feature = "doh")]
        return self.doh_resolver.is_some();
        #[cfg(not(feature = "doh"))]
        false
    }

    pub(super) fn quic_stack_is_apple(&self) -> bool {
        matches!(
            self.profile.quic.as_ref().map(|q| q.stack),
            Some(crate::quic::QuicStack::Apple)
        )
    }

    pub(super) fn alt_svc_h3_port(&self, host: &str, port: u16) -> Option<u16> {
        if self.h3_broken(host, port) {
            return None;
        }
        let cache = crate::util::lock_recover(&self.alt_svc);
        cache
            .entries
            .get(&(host.to_string(), port))
            .filter(|e| e.expires > Instant::now())
            .map(|e| e.h3_port)
    }

    pub(super) fn h3_broken(&self, host: &str, port: u16) -> bool {
        let cache = crate::util::lock_recover(&self.alt_svc);
        cache
            .broken
            .get(&(host.to_string(), port))
            .is_some_and(|b| b.until > Instant::now())
    }

    pub(super) fn mark_alt_svc_broken(&self, host: &str, port: u16) {
        crate::util::lock_recover(&self.alt_svc).mark_broken(host, port);
    }

    pub(super) fn record_alt_svc(&self, host: &str, port: u16, headers: &[(String, String)]) {
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("alt-svc") {
                continue;
            }
            #[allow(clippy::significant_drop_tightening)]
            let mut cache = crate::util::lock_recover(&self.alt_svc);
            let key = (host.to_string(), port);
            if value.trim().eq_ignore_ascii_case("clear") {
                cache.entries.remove(&key);
                return;
            }
            for part in value.split(',') {
                let part = part.trim();
                let Some(rest) = part.strip_prefix("h3=\":") else {
                    continue;
                };
                let Some(end) = rest.find('"') else {
                    continue;
                };
                let Ok(h3_port) = rest[..end].parse::<u16>() else {
                    continue;
                };
                let max_age = parse_alt_svc_max_age(part).unwrap_or(86400);
                let expires = Instant::now()
                    .checked_add(Duration::from_secs(max_age))
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(86400));
                cache.insert(key, AltSvcEntry { h3_port, expires });
                return;
            }
        }
    }
}
