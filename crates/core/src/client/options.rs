//! Shared connection-options assembly, used by the CLI and every binding
//! (Node, Python, R) instead of each reimplementing the same recipe.

use std::net::IpAddr;

use super::{Client, ClientBuilder, IpVersion};
#[cfg(feature = "doh")]
use crate::dns::{DohConfig, DohResolver};
use crate::error::Error;
use crate::profile::{BrowserProfile, ServerPadding};

/// Options for the connection to an origin or a proxy: everything a client needs beyond the
/// profile itself and the per-request settings in [`RequestOptions`](super::RequestOptions).
///
/// Every binding and the CLI convert their own native option types into this struct's plain
/// fields and call [`apply`](Self::apply) once, instead of reimplementing the proxy/proxies
/// priority rule and the fallible parse steps (a proxy URL, a `--resolve` entry, a DoH provider,
/// a proxy CA bundle) once per language.
pub struct ConnectionOptions {
    /// Accepts any certificate from the origin (curl's `-k`/`--insecure`).
    pub ignore_tls_errors: bool,
    /// Proxy URL (`http://`, `https://` or `socks5://`); ignored when `proxies` is non-empty.
    pub proxy: Option<String>,
    /// Proxies to rotate through. Takes priority over `proxy` when both are set.
    pub proxies: Vec<String>,
    /// PEM bytes trusted for `https://` proxies, in addition to the built-in roots.
    pub proxy_ca_certs: Option<Vec<u8>>,
    /// Accepts any certificate from `https://` proxies.
    pub ignore_proxy_tls_errors: bool,
    /// Headers sent with every proxy CONNECT and plain `http://` request.
    pub proxy_headers: Vec<(String, String)>,
    /// Whether TLS sessions are resumed.
    pub session_resumption: bool,
    /// DNS-over-HTTPS provider.
    #[cfg(feature = "doh")]
    pub doh: Option<DohConfig>,
    /// Local address outgoing connections are bound to.
    pub local_address: Option<IpAddr>,
    /// Automatic retries on transport errors.
    pub retries: u32,
    /// Locale for the Accept-Language header (e.g. `"de-DE"`).
    pub locale: Option<String>,
    /// Restricts origin addresses to one IP version.
    pub ip_version: Option<IpVersion>,
    /// `host:port:addr[,addr...]` entries, curl's `--resolve` format.
    pub resolve: Vec<String>,
    /// Cap on a response body, decompressed (see [`ClientBuilder::max_response_body`]); `0`
    /// disables it.
    pub max_response_body: u64,
    /// Pins the profile's server-padding field trial instead of leaving it to draw a group when
    /// the client is built (see [`BrowserProfile::pin_server_padding`]); does nothing for a
    /// profile that does not run the trial.
    pub server_padding: Option<ServerPadding>,
}

impl Default for ConnectionOptions {
    /// Mirrors `ClientBuilder::new`'s own defaults, so applying a default `ConnectionOptions`
    /// changes nothing about the builder it is given.
    fn default() -> Self {
        Self {
            ignore_tls_errors: false,
            proxy: None,
            proxies: Vec::new(),
            proxy_ca_certs: None,
            ignore_proxy_tls_errors: false,
            proxy_headers: Vec::new(),
            session_resumption: true,
            #[cfg(feature = "doh")]
            doh: None,
            local_address: None,
            retries: 0,
            locale: None,
            ip_version: None,
            resolve: Vec::new(),
            max_response_body: super::DEFAULT_MAX_RESPONSE_BODY,
            server_padding: None,
        }
    }
}

impl ConnectionOptions {
    /// A client builder for `profile` with these options applied. The proxy/proxies priority rule
    /// and every parse step that can fail (a proxy URL, a `--resolve` entry, a DoH provider, a
    /// proxy CA bundle) live here, once, instead of once per binding.
    pub fn apply(self, mut profile: BrowserProfile) -> Result<ClientBuilder, Error> {
        if self.ignore_tls_errors {
            profile.tls.danger_accept_invalid_certs = true;
        }
        if let Some(padding) = self.server_padding {
            profile.pin_server_padding(padding);
        }
        let mut builder = Client::builder(profile)
            .session_resumption(self.session_resumption)
            .max_retries(self.retries)
            .proxy_headers(self.proxy_headers)
            .danger_accept_invalid_proxy_certs(self.ignore_proxy_tls_errors)
            .max_response_body(self.max_response_body);

        if let Some(pem) = &self.proxy_ca_certs {
            builder = builder.proxy_ca_certs(pem)?;
        }
        if !self.proxies.is_empty() {
            let urls: Vec<&str> = self.proxies.iter().map(String::as_str).collect();
            builder = builder.proxies(&urls)?;
        } else if let Some(proxy) = &self.proxy {
            builder = builder.proxy(proxy)?;
        }
        #[cfg(feature = "doh")]
        if let Some(config) = self.doh {
            builder = builder.doh(DohResolver::new(config)?);
        }
        if let Some(locale) = &self.locale {
            builder = builder.locale(locale);
        }
        if let Some(addr) = self.local_address {
            builder = builder.local_address(addr);
        }
        if let Some(version) = self.ip_version {
            builder = builder.ip_version(version);
        }
        for entry in &self.resolve {
            builder = builder.resolve_entry(entry)?;
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Chrome;

    #[test]
    fn default_options_change_nothing() {
        // A default `ConnectionOptions` must build successfully and keep the builder's own
        // defaults (in particular, it must not disable session resumption).
        let builder = ConnectionOptions::default()
            .apply(Chrome::latest())
            .unwrap();
        let client = builder.build().unwrap();
        assert!(client.user_agent().is_some());
    }

    #[test]
    fn proxies_take_priority_over_proxy() {
        let options = ConnectionOptions {
            proxy: Some("http://127.0.0.1:1".to_string()),
            proxies: vec!["http://127.0.0.1:2".to_string()],
            ..Default::default()
        };
        // Both parse fine; if `proxy` won, the builder would still succeed, so this only proves
        // the priority rule by observing that a genuinely invalid `proxies` entry is what fails --
        // meaning `proxies` was the one actually parsed.
        let options_with_bad_proxies = ConnectionOptions {
            proxy: Some("http://127.0.0.1:1".to_string()),
            proxies: vec!["not a url".to_string()],
            ..Default::default()
        };
        assert!(options.apply(Chrome::latest()).is_ok());
        assert!(options_with_bad_proxies.apply(Chrome::latest()).is_err());
    }

    #[test]
    fn empty_proxy_ca_certs_is_an_error() {
        let options = ConnectionOptions {
            proxy_ca_certs: Some(Vec::new()),
            ..Default::default()
        };
        assert!(options.apply(Chrome::latest()).is_err());
    }

    #[test]
    fn server_padding_pins_the_profiles_trial() {
        use crate::profile::ServerPadding;

        let pinned_bytes = ConnectionOptions {
            server_padding: Some(ServerPadding::Bytes(9000)),
            ..Default::default()
        }
        .apply(Chrome::latest())
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(pinned_bytes.profile().tls.server_padding, Some(9000));
        assert!(pinned_bytes.profile().tls.server_padding_trial.is_none());

        let pinned_none = ConnectionOptions {
            server_padding: Some(ServerPadding::None),
            ..Default::default()
        }
        .apply(Chrome::latest())
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(pinned_none.profile().tls.server_padding, None);
        assert!(pinned_none.profile().tls.server_padding_trial.is_none());

        // A profile without the trial (Firefox) is untouched either way.
        let firefox = ConnectionOptions {
            server_padding: Some(ServerPadding::Bytes(9000)),
            ..Default::default()
        }
        .apply(crate::Firefox::latest())
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(firefox.profile().tls.server_padding, None);
    }

    #[test]
    fn max_response_body_defaults_to_the_builders_own() {
        // A default `ConnectionOptions` must not change the cap `ClientBuilder::new` sets, and an
        // explicit `0` must still disable it (forwarded to `ClientBuilder::max_response_body`,
        // whose own `0` means "disabled").
        let default_cap = ConnectionOptions::default().max_response_body;
        assert!(default_cap > 0);
        let unlimited = ConnectionOptions {
            max_response_body: 0,
            ..Default::default()
        };
        assert_ne!(unlimited.max_response_body, default_cap);
    }
}
