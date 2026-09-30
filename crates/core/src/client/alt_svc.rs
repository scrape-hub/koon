use std::collections::HashMap;
use std::time::{Duration, Instant};

use http::Uri;

use crate::error::Error;

/// How long an alternative service stays marked broken after its first failure; doubles with every
/// further failure (Chrome: 5 minutes, up to 48 hours).
const BROKEN_INITIAL: Duration = Duration::from_secs(300);
const BROKEN_MAX: Duration = Duration::from_secs(48 * 3600);

/// Most origins kept per map; above it, expired entries go first, then the ones that expire soonest
/// (Chrome keeps 1000 alternative services).
const MAX_ENTRIES: usize = 1000;

/// Cached Alt-Svc entry for HTTP/3 discovery.
pub(super) struct AltSvcEntry {
    pub(super) h3_port: u16,
    pub(super) expires: Instant,
}

struct Broken {
    until: Instant,
    failures: u32,
}

/// Known HTTP/3 alternatives per origin, and the ones that failed.
#[derive(Default)]
pub(super) struct AltSvcCache {
    entries: HashMap<(String, u16), AltSvcEntry>,
    broken: HashMap<(String, u16), Broken>,
}

/// Make room for one more entry in `map` up to `limit`: drop the expired ones, then the one
/// expiring first. Shared by every bounded, TTL-evicted map in the client (this cache's own two,
/// plus [`connection::HostCache`](super::connection::HostCache)) so the eviction algorithm exists
/// once instead of once per map.
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
    /// Mark the HTTP/3 alternative of an origin broken after a failure.
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

    /// The HTTP/3 alternative of an origin worked: forget its failures, as Chrome's
    /// `HttpServerProperties::ConfirmAlternativeService` does.
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

/// Check if a status code is a redirect.
pub(super) fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Resolve a redirect Location against the current URL (RFC 3986 §5 via the WHATWG URL parser):
/// relative paths, query-only and dot segments, protocol-relative URLs, and non-ASCII characters
/// are handled like in a browser. The fragment is dropped.
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

/// Parse `ma=SECONDS` from an Alt-Svc entry.
fn parse_alt_svc_max_age(entry: &str) -> Option<u64> {
    entry.split(';').find_map(|part| {
        part.trim()
            .strip_prefix("ma=")
            .and_then(|v| v.trim().parse().ok())
    })
}

impl super::Client {
    /// Whether the profile switches to HTTP/3 when a server advertises it with Alt-Svc.
    pub(super) fn follows_alt_svc(&self) -> bool {
        self.profile.quic.as_ref().is_some_and(|quic| quic.alt_svc)
    }

    /// Whether the profile discovers HTTP/3 from a host's DNS HTTPS record (see
    /// [`QuicConfig::https_rr`](crate::quic::QuicConfig::https_rr)).
    pub(super) fn follows_https_rr(&self) -> bool {
        self.profile
            .quic
            .as_ref()
            .is_some_and(|quic| quic.https_rr && (!quic.https_rr_doh_only || self.uses_doh()))
    }

    /// Whether a [`DohResolver`](crate::dns::DohResolver) is configured.
    fn uses_doh(&self) -> bool {
        #[cfg(feature = "doh")]
        return self.doh_resolver.is_some();
        #[cfg(not(feature = "doh"))]
        false
    }

    /// Whether the profile's QUIC stack is Apple's: it opens an HTTP/3 connection found through a
    /// DNS HTTPS record directly, without racing TCP like Chrome and Firefox do for an
    /// Alt-Svc-style alternative (`connect_direct_quic` in `execute.rs`), and it prefers the
    /// record's address hints over a normal lookup (`hinted_addresses` in `connection.rs`).
    pub(super) fn quic_stack_is_apple(&self) -> bool {
        matches!(
            self.profile.quic.as_ref().map(|q| q.stack),
            Some(crate::quic::QuicStack::Apple)
        )
    }

    /// The HTTP/3 port advertised for an origin, unless expired or broken.
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

    /// Whether the HTTP/3 alternative of an origin recently failed: checked before racing QUIC
    /// again, whether it was learned from Alt-Svc or from a DNS HTTPS record.
    pub(super) fn h3_broken(&self, host: &str, port: u16) -> bool {
        let cache = crate::util::lock_recover(&self.alt_svc);
        cache
            .broken
            .get(&(host.to_string(), port))
            .is_some_and(|b| b.until > Instant::now())
    }

    /// Mark the HTTP/3 alternative of an origin broken after a failure.
    pub(super) fn mark_alt_svc_broken(&self, host: &str, port: u16) {
        crate::util::lock_recover(&self.alt_svc).mark_broken(host, port);
    }

    /// Record an Alt-Svc header from a response (Chrome processes it on every response of a secure
    /// origin, whichever connection it came on). New connections to the origin will try HTTP/3; the
    /// current connection keeps serving requests, as in Chrome.
    pub(super) fn record_alt_svc(&self, host: &str, port: u16, headers: &[(String, String)]) {
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("alt-svc") {
                continue;
            }
            // Held for the rest of the loop body, which is exactly as long as it's needed.
            #[allow(clippy::significant_drop_tightening)]
            let mut cache = crate::util::lock_recover(&self.alt_svc);
            let key = (host.to_string(), port);
            if value.trim().eq_ignore_ascii_case("clear") {
                cache.entries.remove(&key);
                return;
            }
            for part in value.split(',') {
                let part = part.trim();
                // Only same-host alternatives: h3=":PORT"
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
                // `ma=` near u64::MAX would overflow Instant + Duration.
                let expires = Instant::now()
                    .checked_add(Duration::from_secs(max_age))
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(86400));
                cache.insert(key, AltSvcEntry { h3_port, expires });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(base: &str, location: &str) -> String {
        resolve_redirect(&base.parse().unwrap(), location)
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_resolve_redirect() {
        assert_eq!(resolve("https://a.com/x/y", "/z"), "https://a.com/z");
        assert_eq!(resolve("https://a.com/x/y", "z"), "https://a.com/x/z");
        assert_eq!(
            resolve("https://a.com/x/y", "?p=2"),
            "https://a.com/x/y?p=2"
        );
        assert_eq!(resolve("https://a.com/x/y/", "../z"), "https://a.com/x/z");
        assert_eq!(resolve("https://a.com/x", "//b.com/p"), "https://b.com/p");
        assert_eq!(
            resolve("https://a.com/x", "HTTPS://B.com/p"),
            "https://b.com/p"
        );
        assert_eq!(resolve("https://a.com/x", "/p#frag"), "https://a.com/p");
        assert_eq!(resolve("https://a.com/x", "/ü"), "https://a.com/%C3%BC");
        let err = resolve_redirect(&"https://a.com/".parse().unwrap(), "ftp://a.com/").unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme(_)));
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_cache_is_bounded() {
        let mut cache = AltSvcCache::default();
        for i in 0..MAX_ENTRIES + 5 {
            let key = (format!("h{i}.test"), 443);
            cache.insert(
                key.clone(),
                AltSvcEntry {
                    h3_port: 443,
                    expires: Instant::now() + Duration::from_secs(60 + i as u64),
                },
            );
            cache.mark_broken(&key.0, key.1);
        }
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        assert_eq!(cache.broken.len(), MAX_ENTRIES);
        // The newest survive.
        assert!(
            cache
                .entries
                .contains_key(&(format!("h{MAX_ENTRIES}.test"), 443))
        );
    }
}
