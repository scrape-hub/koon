mod alt_svc;
mod connection;
mod execute;
mod h1;
mod h2;
mod h3;
mod headers;
mod response;

pub use response::{HttpResponse, SessionExport};

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use boring2::ssl::SslConnector;
use h3_quinn::quinn;
use http::{Method, Uri};

use crate::cookie::CookieJar;
#[cfg(feature = "doh")]
use crate::dns::DohResolver;
use crate::error::Error;
use crate::multipart::Multipart;
use crate::pool::ConnectionPool;
use crate::profile::BrowserProfile;
use crate::proxy::ProxyConfig;
use crate::tls::{SessionCache, TlsConnector};
use crate::websocket::{self, WebSocket};

/// Builder for constructing a [`Client`] with custom settings.
pub struct ClientBuilder {
    profile: BrowserProfile,
    proxy: Option<ProxyConfig>,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
    follow_redirects: bool,
    max_redirects: u32,
    cookie_jar: bool,
    session_resumption: bool,
    #[cfg(feature = "doh")]
    doh_resolver: Option<DohResolver>,
}

impl ClientBuilder {
    fn new(profile: BrowserProfile) -> Self {
        ClientBuilder {
            profile,
            proxy: None,
            timeout: Duration::from_secs(30),
            custom_headers: Vec::new(),
            follow_redirects: true,
            max_redirects: 10,
            cookie_jar: true,
            session_resumption: true,
            #[cfg(feature = "doh")]
            doh_resolver: None,
        }
    }

    /// Set a proxy for all requests.
    pub fn proxy(mut self, proxy_url: &str) -> Result<Self, Error> {
        self.proxy = Some(ProxyConfig::parse(proxy_url)?);
        Ok(self)
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add custom headers that override profile defaults.
    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.custom_headers = headers;
        self
    }

    /// Enable or disable automatic redirect following. Default: true.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Set the maximum number of redirects to follow. Default: 10.
    pub fn max_redirects(mut self, max: u32) -> Self {
        self.max_redirects = max;
        self
    }

    /// Enable or disable the built-in cookie jar. Default: true.
    pub fn cookie_jar(mut self, enabled: bool) -> Self {
        self.cookie_jar = enabled;
        self
    }

    /// Enable or disable TLS session resumption. Default: true.
    pub fn session_resumption(mut self, enabled: bool) -> Self {
        self.session_resumption = enabled;
        self
    }

    /// Set a DNS-over-HTTPS resolver for encrypted DNS and ECH support.
    #[cfg(feature = "doh")]
    pub fn doh(mut self, resolver: DohResolver) -> Self {
        self.doh_resolver = Some(resolver);
        self
    }

    /// Build the [`Client`]. This creates the TLS connector (Phase 1).
    pub fn build(self) -> Result<Client, Error> {
        let session_cache = if self.session_resumption {
            Some(SessionCache::new())
        } else {
            None
        };

        let tls_connector =
            TlsConnector::build_connector(&self.profile.tls, session_cache.clone())?;

        let jar = if self.cookie_jar {
            Some(Mutex::new(CookieJar::new()))
        } else {
            None
        };

        Ok(Client {
            profile: self.profile,
            tls_connector,
            proxy: self.proxy,
            timeout: self.timeout,
            custom_headers: self.custom_headers,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            cookie_jar: jar,
            session_cache,
            #[cfg(feature = "doh")]
            doh_resolver: self.doh_resolver,
            pool: ConnectionPool::new(256, Duration::from_secs(90)),
            alt_svc_cache: Mutex::new(HashMap::new()),
            quic_endpoint: Mutex::new(None),
        })
    }
}

/// The main HTTP client with browser fingerprint impersonation.
///
/// The TLS connector is built once and cached for reuse across connections.
/// Supports automatic redirect following and cookie management.
pub struct Client {
    profile: BrowserProfile,
    tls_connector: SslConnector,
    proxy: Option<ProxyConfig>,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
    follow_redirects: bool,
    max_redirects: u32,
    cookie_jar: Option<Mutex<CookieJar>>,
    session_cache: Option<SessionCache>,
    #[cfg(feature = "doh")]
    doh_resolver: Option<DohResolver>,
    pool: ConnectionPool,
    /// Alt-Svc cache: maps (host, port) → H3 port + expiry.
    alt_svc_cache: Mutex<HashMap<(String, u16), alt_svc::AltSvcEntry>>,
    /// Lazily-initialized QUIC endpoint (shared across all H3 connections).
    quic_endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl Client {
    /// Create a builder for configuring the client.
    pub fn builder(profile: BrowserProfile) -> ClientBuilder {
        ClientBuilder::new(profile)
    }

    /// Get a reference to the browser profile.
    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    /// Create a new client with default settings (redirects on, cookies on).
    pub fn new(profile: BrowserProfile) -> Result<Self, Error> {
        Self::builder(profile).build()
    }

    /// Perform an HTTP GET request.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::GET, url, None).await
    }

    /// Perform an HTTP POST request.
    pub async fn post(&self, url: &str, body: Option<Vec<u8>>) -> Result<HttpResponse, Error> {
        self.request(Method::POST, url, body).await
    }

    /// Perform an HTTP PUT request.
    pub async fn put(&self, url: &str, body: Option<Vec<u8>>) -> Result<HttpResponse, Error> {
        self.request(Method::PUT, url, body).await
    }

    /// Perform an HTTP DELETE request.
    pub async fn delete(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::DELETE, url, None).await
    }

    /// Perform an HTTP PATCH request.
    pub async fn patch(&self, url: &str, body: Option<Vec<u8>>) -> Result<HttpResponse, Error> {
        self.request(Method::PATCH, url, body).await
    }

    /// Perform an HTTP HEAD request.
    pub async fn head(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::HEAD, url, None).await
    }

    /// Perform an HTTP request with the given method.
    /// Automatically follows redirects and manages cookies if enabled.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        self.request_with_headers(method, url, body, Vec::new()).await
    }

    /// Perform an HTTP POST request with a multipart/form-data body.
    pub async fn post_multipart(&self, url: &str, multipart: Multipart) -> Result<HttpResponse, Error> {
        let (body, content_type) = multipart.build();
        self.request_with_headers(
            Method::POST,
            url,
            Some(body),
            vec![("content-type".into(), content_type)],
        )
        .await
    }

    /// Save the current session (cookies + TLS sessions) as a JSON string.
    pub fn save_session(&self) -> Result<String, Error> {
        let cookies = self.cookie_jar.as_ref().map(|jar| {
            let jar = jar.lock().unwrap();
            serde_json::to_value(jar.cookies()).unwrap_or(serde_json::Value::Array(Vec::new()))
        });

        let tls_sessions = self.session_cache.as_ref().map(|cache| {
            cache.export().sessions
        });

        let export = SessionExport {
            cookies,
            tls_sessions,
        };

        serde_json::to_string_pretty(&export).map_err(Error::Json)
    }

    /// Load a session (cookies + TLS sessions) from a JSON string.
    pub fn load_session(&self, json: &str) -> Result<(), Error> {
        let export: SessionExport = serde_json::from_str(json).map_err(Error::Json)?;

        if let Some(cookies_val) = export.cookies {
            if let Some(jar_mutex) = &self.cookie_jar {
                let cookies_json = serde_json::to_string(&cookies_val).map_err(Error::Json)?;
                let loaded_jar = CookieJar::from_json(&cookies_json).map_err(Error::Json)?;
                let mut jar = jar_mutex.lock().unwrap();
                *jar = loaded_jar;
            }
        }

        if let Some(sessions) = export.tls_sessions {
            if let Some(cache) = &self.session_cache {
                let cache_export = crate::tls::SessionCacheExport { sessions };
                cache.import(&cache_export);
            }
        }

        Ok(())
    }

    /// Save the current session to a file.
    pub fn save_session_to_file(&self, path: &str) -> Result<(), Error> {
        let json = self.save_session()?;
        std::fs::write(path, json).map_err(Error::Io)
    }

    /// Load a session from a file.
    pub fn load_session_from_file(&self, path: &str) -> Result<(), Error> {
        let json = std::fs::read_to_string(path).map_err(Error::Io)?;
        self.load_session(&json)
    }

    /// Open a WebSocket connection to a `wss://` URL.
    ///
    /// Uses the same TLS fingerprint as HTTP requests but forces HTTP/1.1
    /// ALPN (no h2) for the Upgrade handshake. The connection does NOT use
    /// the connection pool — the stream is owned by the returned `WebSocket`.
    pub async fn websocket(&self, url: &str) -> Result<WebSocket, Error> {
        self.websocket_with_headers(url, Vec::new()).await
    }

    /// Open a WebSocket connection with extra headers.
    pub async fn websocket_with_headers(
        &self,
        url: &str,
        extra_headers: Vec<(String, String)>,
    ) -> Result<WebSocket, Error> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::Url(url::ParseError::EmptyHost))?;

        // Only wss:// is supported
        match uri.scheme_str() {
            Some("wss") => {}
            _ => {
                return Err(Error::ConnectionFailed(
                    "Only wss:// is supported (ws:// would leak fingerprint)".into(),
                ));
            }
        }

        let host = uri
            .host()
            .ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri.port_u16().unwrap_or(443);
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

        // 1. TCP connect
        let tcp = self.connect_tcp(host, port).await?;

        // 2. TLS handshake (HTTP/1.1 only ALPN)
        let tls_stream = self.tls_connect_ws(tcp, host, port).await?;

        // 3. Build headers using consolidated builder
        let ws_headers = headers::build_request_headers(
            &self.profile.headers,
            &self.custom_headers,
            &extra_headers,
            None,
            &["host", "cookie", "accept-encoding", "content-type", "content-length"],
            Some(authority),
            false,
            None, // WebSocket doesn't need sec-fetch-* correction
        );

        // 4. WebSocket handshake
        websocket::connect(tls_stream, &uri, &ws_headers, self.timeout).await
    }
}
