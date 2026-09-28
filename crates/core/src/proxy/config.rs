use std::sync::atomic::{AtomicUsize, Ordering};
use url::Url;

/// Proxy configuration for outbound HTTP requests.
#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    /// The parsed proxy URL.
    pub url: Url,
    /// Proxy protocol type.
    pub kind: ProxyKind,
    /// Optional username/password authentication.
    pub auth: Option<ProxyAuth>,
}

/// Proxy protocol type.
#[derive(Debug, Clone)]
pub(crate) enum ProxyKind {
    /// HTTP CONNECT proxy.
    Http,
    /// HTTPS CONNECT proxy (TLS to proxy).
    Https,
    /// SOCKS5 proxy.
    Socks5,
}

/// Proxy authentication credentials.
#[derive(Debug, Clone)]
pub(crate) struct ProxyAuth {
    /// Proxy username.
    pub username: String,
    /// Proxy password.
    pub password: String,
}

impl ProxyConfig {
    /// Parse a proxy URL string (`http(s)://[user:pass@]host:port` or `socks5://host:port`) into a
    /// `ProxyConfig`.
    ///
    /// # Errors
    /// Returns [`Error::Proxy`](crate::Error::Proxy) if `proxy_url` is not a valid URL or its
    /// scheme is not `http`, `https` or `socks5`.
    pub fn parse(proxy_url: &str) -> Result<Self, crate::Error> {
        let url = Url::parse(proxy_url).map_err(|e| {
            let message = format!("Invalid proxy URL: {e}");
            crate::Error::Proxy(message, crate::error::boxed(e))
        })?;

        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "https" => ProxyKind::Https,
            "socks5" => ProxyKind::Socks5,
            other => {
                return Err(crate::Error::Proxy(
                    format!("Unsupported proxy scheme: {other}"),
                    None,
                ));
            }
        };

        let auth = (!url.username().is_empty()).then(|| ProxyAuth {
            username: url.username().to_string(),
            password: url.password().unwrap_or("").to_string(),
        });

        Ok(Self { url, kind, auth })
    }

    /// Host to connect to, or `127.0.0.1` if the proxy URL has none.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or("127.0.0.1")
    }

    /// Port to connect to, defaulting per `kind` if the proxy URL has none.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.url.port().unwrap_or(match self.kind {
            ProxyKind::Http => 80,
            ProxyKind::Https => 443,
            ProxyKind::Socks5 => 1080,
        })
    }
}

/// Round-robin proxy rotation over multiple proxy URLs, thread-safe via `AtomicUsize` (lock-free).
pub(crate) struct ProxyRotation {
    proxies: Vec<ProxyConfig>,
    index: AtomicUsize,
}

impl std::fmt::Debug for ProxyRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRotation")
            .field("proxies", &self.proxies)
            .field("index", &self.index.load(Ordering::Relaxed))
            .finish()
    }
}

impl ProxyRotation {
    /// Create a new proxy rotation from a slice of proxy URL strings.
    ///
    /// # Errors
    /// Returns [`Error::Proxy`](crate::Error::Proxy) if `proxy_urls` is empty or any URL is
    /// invalid.
    pub fn new(proxy_urls: &[&str]) -> Result<Self, crate::Error> {
        if proxy_urls.is_empty() {
            return Err(crate::Error::Proxy(
                "Proxy rotation requires at least one proxy URL".into(),
                None,
            ));
        }
        let proxies: Result<Vec<ProxyConfig>, _> = proxy_urls
            .iter()
            .map(|url| ProxyConfig::parse(url))
            .collect();
        Ok(Self {
            proxies: proxies?,
            index: AtomicUsize::new(0),
        })
    }

    /// Return the next proxy in round-robin order, with its index in the list.
    pub fn next(&self) -> (usize, &ProxyConfig) {
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        (idx, &self.proxies[idx])
    }
}
