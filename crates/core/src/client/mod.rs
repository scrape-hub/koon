mod alt_svc;
mod connection;
mod execute;
mod h1;
mod h2;
mod h3;
mod headers;
mod response;

pub use response::{HttpResponse, SessionExport};
pub(crate) use response::estimate_headers_size;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Observe-only hook called before each HTTP request (including redirects).
pub type OnRequestHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Observe-only hook called after each HTTP response (including redirects).
pub type OnResponseHook = Arc<dyn Fn(u16, &str, &[(String, String)]) + Send + Sync>;

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
use crate::proxy::{ProxyConfig, ProxyRotation};
use crate::tls::{SessionCache, TlsConnector};
use crate::websocket::{self, WebSocket};

/// Builder for constructing a [`Client`] with custom settings.
pub struct ClientBuilder {
    profile: BrowserProfile,
    proxy: Option<ProxyConfig>,
    proxy_rotation: Option<ProxyRotation>,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
    follow_redirects: bool,
    max_redirects: u32,
    cookie_jar: bool,
    session_resumption: bool,
    local_address: Option<IpAddr>,
    on_request: Option<OnRequestHook>,
    on_response: Option<OnResponseHook>,
    #[cfg(feature = "doh")]
    doh_resolver: Option<DohResolver>,
}

impl ClientBuilder {
    fn new(profile: BrowserProfile) -> Self {
        ClientBuilder {
            profile,
            proxy: None,
            proxy_rotation: None,
            timeout: Duration::from_secs(30),
            custom_headers: Vec::new(),
            follow_redirects: true,
            max_redirects: 10,
            cookie_jar: true,
            session_resumption: true,
            local_address: None,
            on_request: None,
            on_response: None,
            #[cfg(feature = "doh")]
            doh_resolver: None,
        }
    }

    /// Set a single proxy for all requests.
    pub fn proxy(mut self, proxy_url: &str) -> Result<Self, Error> {
        self.proxy = Some(ProxyConfig::parse(proxy_url)?);
        Ok(self)
    }

    /// Set multiple proxies for round-robin rotation.
    ///
    /// Each request picks the next proxy in order, cycling back to the first.
    /// Takes priority over [`proxy()`](ClientBuilder::proxy) if both are set.
    pub fn proxies(mut self, proxy_urls: &[&str]) -> Result<Self, Error> {
        self.proxy_rotation = Some(ProxyRotation::new(proxy_urls)?);
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

    /// Bind outgoing connections to a specific local IP address.
    pub fn local_address(mut self, addr: IpAddr) -> Self {
        self.local_address = Some(addr);
        self
    }

    /// Register an observe-only hook called before each HTTP request.
    ///
    /// The hook receives `(method, url)` and fires for every request
    /// including intermediate redirects.
    pub fn on_request<F: Fn(&str, &str) + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.on_request = Some(Arc::new(f));
        self
    }

    /// Register an observe-only hook called after each HTTP response.
    ///
    /// The hook receives `(status, url, headers)` and fires for every
    /// response including intermediate redirects.
    pub fn on_response<F: Fn(u16, &str, &[(String, String)]) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_response = Some(Arc::new(f));
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
            proxy_rotation: self.proxy_rotation,
            timeout: self.timeout,
            custom_headers: self.custom_headers,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            cookie_jar: jar,
            session_cache,
            local_address: self.local_address,
            on_request: self.on_request,
            on_response: self.on_response,
            #[cfg(feature = "doh")]
            doh_resolver: self.doh_resolver,
            pool: ConnectionPool::new(256, Duration::from_secs(90)),
            alt_svc_cache: Mutex::new(HashMap::new()),
            quic_endpoint: Mutex::new(None),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
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
    proxy_rotation: Option<ProxyRotation>,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
    follow_redirects: bool,
    max_redirects: u32,
    cookie_jar: Option<Mutex<CookieJar>>,
    session_cache: Option<SessionCache>,
    local_address: Option<IpAddr>,
    on_request: Option<OnRequestHook>,
    on_response: Option<OnResponseHook>,
    #[cfg(feature = "doh")]
    doh_resolver: Option<DohResolver>,
    pool: ConnectionPool,
    /// Alt-Svc cache: maps (host, port) → H3 port + expiry.
    alt_svc_cache: Mutex<HashMap<(String, u16), alt_svc::AltSvcEntry>>,
    /// Lazily-initialized QUIC endpoint (shared across all H3 connections).
    quic_endpoint: Mutex<Option<quinn::Endpoint>>,
    /// Cumulative bytes sent across all requests.
    total_bytes_sent: Arc<AtomicU64>,
    /// Cumulative bytes received across all requests.
    total_bytes_received: Arc<AtomicU64>,
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

    /// Fire the on_request hook if registered.
    pub(super) fn fire_on_request(&self, method: &str, url: &str) {
        if let Some(hook) = &self.on_request {
            hook(method, url);
        }
    }

    /// Fire the on_response hook if registered.
    pub(super) fn fire_on_response(&self, status: u16, url: &str, headers: &[(String, String)]) {
        if let Some(hook) = &self.on_response {
            hook(status, url, headers);
        }
    }

    /// Get the total number of bytes sent across all requests.
    pub fn total_bytes_sent(&self) -> u64 {
        self.total_bytes_sent.load(Ordering::Relaxed)
    }

    /// Get the total number of bytes received across all requests.
    pub fn total_bytes_received(&self) -> u64 {
        self.total_bytes_received.load(Ordering::Relaxed)
    }

    /// Reset both cumulative byte counters to zero.
    pub fn reset_counters(&self) {
        self.total_bytes_sent.store(0, Ordering::Relaxed);
        self.total_bytes_received.store(0, Ordering::Relaxed);
    }

    /// Add bytes to the cumulative counters.
    pub(super) fn track_bytes(&self, sent: u64, received: u64) {
        self.total_bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.total_bytes_received.fetch_add(received, Ordering::Relaxed);
    }

    /// Get a clone of the shared bytes_received counter (for streaming responses).
    pub(super) fn bytes_received_counter(&self) -> Arc<AtomicU64> {
        self.total_bytes_received.clone()
    }

    /// Get a clone of the shared bytes_sent counter (for streaming responses).
    pub(super) fn bytes_sent_counter(&self) -> Arc<AtomicU64> {
        self.total_bytes_sent.clone()
    }

    /// Select proxy for this request: rotation > single > none.
    ///
    /// Returns `(proxy_index, proxy_config)`. The index is used as pool key
    /// discriminator so each proxy gets its own set of connections.
    pub(super) fn select_proxy(&self) -> (Option<usize>, Option<&ProxyConfig>) {
        if let Some(rotation) = &self.proxy_rotation {
            let (idx, proxy) = rotation.next();
            (Some(idx), Some(proxy))
        } else {
            (None, self.proxy.as_ref())
        }
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
