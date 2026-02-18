use url::Url;

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub url: Url,
    pub kind: ProxyKind,
    pub auth: Option<ProxyAuth>,
}

#[derive(Debug, Clone)]
pub enum ProxyKind {
    Http,
    Https,
    Socks5,
}

#[derive(Debug, Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

impl ProxyConfig {
    /// Parse a proxy URL string into a ProxyConfig.
    ///
    /// Supported formats:
    /// - `http://host:port`
    /// - `https://host:port`
    /// - `socks5://host:port`
    /// - `http://user:pass@host:port`
    pub fn parse(proxy_url: &str) -> Result<Self, crate::Error> {
        let url = Url::parse(proxy_url)
            .map_err(|e| crate::Error::Proxy(format!("Invalid proxy URL: {e}")))?;

        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "https" => ProxyKind::Https,
            "socks5" => ProxyKind::Socks5,
            other => {
                return Err(crate::Error::Proxy(format!(
                    "Unsupported proxy scheme: {other}"
                )))
            }
        };

        let auth = if !url.username().is_empty() {
            Some(ProxyAuth {
                username: url.username().to_string(),
                password: url.password().unwrap_or("").to_string(),
            })
        } else {
            None
        };

        Ok(ProxyConfig { url, kind, auth })
    }

    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or("127.0.0.1")
    }

    pub fn port(&self) -> u16 {
        self.url.port().unwrap_or(match self.kind {
            ProxyKind::Http => 80,
            ProxyKind::Https => 443,
            ProxyKind::Socks5 => 1080,
        })
    }
}
