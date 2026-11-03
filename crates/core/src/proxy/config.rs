use std::sync::atomic::{AtomicUsize, Ordering};
use url::Url;

#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    pub url: Url,
    pub kind: ProxyKind,
    pub auth: Option<ProxyAuth>,
}

#[derive(Debug, Clone)]
pub(crate) enum ProxyKind {
    Http,
    Https,
    Socks5,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyAuth {
    pub username: String,
    pub password: String,
}

impl ProxyConfig {
    pub fn parse(proxy_url: &str) -> Result<Self, crate::Error> {
        let url = Url::parse(proxy_url).map_err(|e| {
            let message = format!("Invalid proxy URL: {e}");
            crate::Error::Proxy(message, crate::error::boxed(e))
        })?;

        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "https" => ProxyKind::Https,
            "socks5" | "socks5h" => ProxyKind::Socks5,
            other => {
                return Err(crate::Error::Proxy(
                    format!("Unsupported proxy scheme: {other}"),
                    None,
                ));
            }
        };

        let decode = |part: &str| {
            percent_encoding::percent_decode_str(part)
                .decode_utf8()
                .map(std::borrow::Cow::into_owned)
                .map_err(|e| {
                    let message = format!("Invalid proxy URL: credentials are not UTF-8: {e}");
                    crate::Error::Proxy(message, crate::error::boxed(e))
                })
        };
        let auth = if url.username().is_empty() {
            None
        } else {
            Some(ProxyAuth {
                username: decode(url.username())?,
                password: decode(url.password().unwrap_or(""))?,
            })
        };

        Ok(Self { url, kind, auth })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or("127.0.0.1")
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.url.port().unwrap_or(match self.kind {
            ProxyKind::Http => 80,
            ProxyKind::Https => 443,
            ProxyKind::Socks5 => 1080,
        })
    }
}

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

    pub fn next(&self) -> (usize, &ProxyConfig) {
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        (idx, &self.proxies[idx])
    }
}
