use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use boring2::ssl::SslConnector;
use h3_quinn::quinn;
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_boring2::SslStream;

use serde::{Deserialize, Serialize};

use crate::cookie::CookieJar;
#[cfg(feature = "doh")]
use crate::dns::DohResolver;
use crate::error::Error;
use crate::http1;
use crate::http2::config::{PseudoHeader, SettingId};
use crate::multipart::Multipart;
use crate::pool::ConnectionPool;
use crate::profile::BrowserProfile;
use crate::proxy::{ProxyConfig, ProxyKind};
use crate::streaming::StreamingResponse;
use crate::tls::{SessionCache, TlsConnector};
use crate::websocket::{self, WebSocket};
use crate::{http3, quic};

/// Cached Alt-Svc entry for HTTP/3 discovery.
struct AltSvcEntry {
    h3_port: u16,
    expires: Instant,
}

/// HTTP response with body.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub version: String,
    pub url: String,
}

/// Exported session data (cookies + TLS sessions) for save/load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_sessions: Option<HashMap<String, String>>,
}

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
    alt_svc_cache: Mutex<HashMap<(String, u16), AltSvcEntry>>,
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

    /// Perform a streaming HTTP request.
    ///
    /// Unlike [`request()`](Self::request), the response body is not buffered.
    /// Instead, chunks are delivered via [`StreamingResponse::next_chunk()`].
    ///
    /// Streaming responses do **not** follow redirects — the caller must handle
    /// 3xx responses manually (similar to `fetch(redirect: 'manual')`).
    ///
    /// Decompression is **not** applied to streaming responses.
    pub async fn request_streaming(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<StreamingResponse, Error> {
        let uri: Uri = url.parse().map_err(|_| Error::Url(url::ParseError::EmptyHost))?;

        let host = uri
            .host()
            .ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
        let is_https = uri.scheme_str() == Some("https");

        if !is_https {
            return Err(Error::ConnectionFailed(
                "Only HTTPS is supported (HTTP would leak fingerprint)".into(),
            ));
        }

        let cookie_header = self
            .cookie_jar
            .as_ref()
            .and_then(|jar| jar.lock().unwrap().cookie_header(&uri));

        // Try pooled H2 connection first
        if let Some(mut sender) = self.pool.try_get_h2(host, port) {
            match self
                .send_on_h2_streaming(&mut sender, method.clone(), &uri, body.clone(), cookie_header.as_deref())
                .await
            {
                Ok(resp) => {
                    // Keep H2 connection in pool (it's multiplexed)
                    self.pool.insert_h2(host, port, sender);
                    return Ok(resp);
                }
                Err(e) => {
                    self.pool.remove(host, port);
                    if !e.is_h2_goaway() {
                        return Err(e);
                    }
                    // GOAWAY: fall through to new connection
                }
            }
        }

        // New connection: TCP → TLS → H2/H1
        let tcp = self.connect_tcp(host, port).await?;
        let tls_stream = self.tls_connect(tcp, host, port).await?;

        let alpn = tls_stream.ssl().selected_alpn_protocol();
        let is_h2 = matches!(alpn, Some(b"h2"));

        if is_h2 {
            let mut sender = self.h2_handshake(tls_stream).await?;
            let resp = self
                .send_on_h2_streaming(&mut sender, method, &uri, body, cookie_header.as_deref())
                .await?;
            self.pool.insert_h2(host, port, sender);
            Ok(resp)
        } else {
            self.send_on_h1_streaming(tls_stream, method, &uri, body, cookie_header.as_deref())
                .await
        }
    }

    /// Send an H2 request and return a streaming response.
    async fn send_on_h2_streaming(
        &self,
        sender: &mut http2::client::SendRequest<bytes::Bytes>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
    ) -> Result<StreamingResponse, Error> {
        sender.clone().ready().await.map_err(Error::Http2)?;

        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let h2_uri: Uri = format!("{scheme}://{authority}{path}")
            .parse()
            .map_err(|_| Error::InvalidHeader("Failed to build H2 URI".into()))?;

        let req_builder = Request::builder()
            .method(method.clone())
            .uri(h2_uri)
            .version(Version::HTTP_2);

        let mut req = req_builder
            .body(())
            .map_err(|e| Error::InvalidHeader(format!("Failed to build request: {e}")))?;

        let headers = req.headers_mut();
        for (name, value) in &self.profile.headers {
            let lower = name.to_lowercase();
            if lower == "host" || lower == "cookie" {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }
        for (name, value) in &self.custom_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }
        if let Some(cookie_val) = cookie_header {
            if let Ok(hv) = HeaderValue::from_str(cookie_val) {
                headers.insert(http::header::COOKIE, hv);
            }
        }
        sort_headers_by_profile(headers, &self.profile.headers);

        let has_body = body.is_some();
        let (response_future, mut send_stream) = sender
            .send_request(req, !has_body)
            .map_err(Error::Http2)?;

        if let Some(body_bytes) = body {
            send_stream.send_data(body_bytes.into(), true).map_err(Error::Http2)?;
        }

        let response = tokio::time::timeout(self.timeout, response_future)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Http2)?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let mut recv_stream = response.into_body();
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            while let Some(chunk) = recv_stream.data().await {
                match chunk {
                    Ok(data) => {
                        let _ = recv_stream.flow_control().release_capacity(data.len());
                        if tx.send(Ok(data.to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Error::Http2(e))).await;
                        return;
                    }
                }
            }
        });

        Ok(StreamingResponse::new(
            status,
            resp_headers,
            "h2".to_string(),
            uri.to_string(),
            rx,
        ))
    }

    /// Send an H1 request and return a streaming response.
    /// The TLS stream is moved into a background task that streams body chunks.
    async fn send_on_h1_streaming(
        &self,
        mut stream: SslStream<TcpStream>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
    ) -> Result<StreamingResponse, Error> {
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

        let mut headers = http::HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(authority) {
            headers.insert(http::header::HOST, hv);
        }
        for (name, value) in &self.profile.headers {
            let lower = name.to_lowercase();
            if lower == "host" || lower == "cookie" {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }
        for (name, value) in &self.custom_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }
        if let Some(cookie_val) = cookie_header {
            if let Ok(hv) = HeaderValue::from_str(cookie_val) {
                headers.insert(http::header::COOKIE, hv);
            }
        }
        headers.insert(http::header::CONNECTION, HeaderValue::from_static("keep-alive"));
        sort_headers_by_profile(&mut headers, &self.profile.headers);

        let body_ref = body.as_deref();
        http1::write_request(&mut stream, &method, uri, &headers, body_ref).await?;

        // Read only headers
        let (status, resp_headers, remaining) =
            tokio::time::timeout(self.timeout, http1::read_response_for_streaming(&mut stream))
                .await
                .map_err(|_| Error::Timeout)??;

        let is_chunked = resp_headers
            .iter()
            .any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));
        let content_length: Option<usize> = resp_headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.trim().parse().ok());

        let (tx, rx) = mpsc::channel(16);

        // Spawn background task to stream body — connection is NOT returned to pool
        tokio::spawn(async move {
            if is_chunked {
                http1::stream_chunked_body(&mut stream, &remaining, tx).await;
            } else if let Some(len) = content_length {
                http1::stream_content_length_body(&mut stream, &remaining, len, tx).await;
            } else {
                http1::stream_until_close(&mut stream, &remaining, tx).await;
            }
        });

        Ok(StreamingResponse::new(
            status,
            resp_headers,
            "HTTP/1.1".to_string(),
            uri.to_string(),
            rx,
        ))
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

        // 3. Build headers: Host + profile headers + extra headers
        let mut headers = http::HeaderMap::new();

        // Host header
        if let Ok(hv) = HeaderValue::from_str(authority) {
            headers.insert(http::header::HOST, hv);
        }

        // Profile headers (User-Agent, Accept, etc.)
        for (name, value) in &self.profile.headers {
            let lower = name.to_lowercase();
            if lower == "host"
                || lower == "cookie"
                || lower == "accept-encoding"
                || lower == "content-type"
                || lower == "content-length"
            {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Custom client headers
        for (name, value) in &self.custom_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Extra headers for this WebSocket connection
        for (name, value) in &extra_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Sort headers to match profile order
        sort_headers_by_profile(&mut headers, &self.profile.headers);

        // 4. WebSocket handshake
        websocket::connect(tls_stream, &uri, &headers, self.timeout).await
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

    /// Perform an HTTP request with extra headers (e.g. multipart content-type).
    /// These headers are injected after custom_headers and override them.
    pub async fn request_with_headers(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpResponse, Error> {
        let mut current_url: Uri = url.parse().map_err(|_| Error::Url(url::ParseError::EmptyHost))?;
        let mut current_method = method;
        let mut current_body = body;
        let mut redirect_count: u32 = 0;

        loop {
            // Inject cookies into request headers
            let cookie_header = self
                .cookie_jar
                .as_ref()
                .and_then(|jar| jar.lock().unwrap().cookie_header(&current_url));

            let response = self
                .execute_single_request(
                    current_method.clone(),
                    &current_url,
                    current_body.clone(),
                    cookie_header.as_deref(),
                    &extra_headers,
                )
                .await?;

            // Store cookies from response
            if let Some(jar) = &self.cookie_jar {
                jar.lock()
                    .unwrap()
                    .store_from_response(&current_url, &response.headers);
            }

            // Check for redirect
            if !self.follow_redirects || !is_redirect(response.status) {
                return Ok(HttpResponse {
                    url: current_url.to_string(),
                    ..response
                });
            }

            redirect_count += 1;
            if redirect_count > self.max_redirects {
                return Err(Error::TooManyRedirects);
            }

            // Extract Location header
            let location = response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    Error::ConnectionFailed("Redirect without Location header".into())
                })?;

            // Resolve relative URL against current URL
            current_url = resolve_redirect(&current_url, &location)?;

            // 307/308: preserve method and body. Otherwise: POST -> GET, drop body.
            match response.status {
                307 | 308 => {}
                _ => {
                    if current_method != Method::GET && current_method != Method::HEAD {
                        current_method = Method::GET;
                        current_body = None;
                    }
                }
            }
        }
    }

    /// Execute a single HTTP request without redirect following.
    /// Uses the connection pool to reuse existing connections.
    /// Supports HTTP/3, HTTP/2, and HTTP/1.1.
    ///
    /// Protocol selection order:
    /// 1. Existing pooled H3 connection
    /// 2. Existing pooled H2 connection
    /// 3. Existing pooled H1.1 connection
    /// 4. New connection: if Alt-Svc cache says H3 is available and no proxy → try H3
    /// 5. Fallback: TCP → TLS → H2/H1 via ALPN
    async fn execute_single_request(
        &self,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse, Error> {
        let host = uri
            .host()
            .ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
        let is_https = uri.scheme_str() == Some("https");

        if !is_https {
            return Err(Error::ConnectionFailed(
                "Only HTTPS is supported (HTTP would leak fingerprint)".into(),
            ));
        }

        // 1. Try cached H3 connection from pool
        if let Some(mut sender) = self.pool.try_get_h3(host, port) {
            match http3::send_request(
                &mut sender,
                method.clone(),
                uri,
                &self.profile,
                &self.custom_headers,
                body.clone(),
                cookie_header,
            )
            .await
            {
                Ok(response) => {
                    let response = self.decompress_response(response)?;
                    return Ok(response);
                }
                Err(_) => {
                    self.pool.remove(host, port);
                }
            }
        }

        // 2. Try cached H2 connection from pool
        if let Some(mut sender) = self.pool.try_get_h2(host, port) {
            match self
                .send_on_h2(&mut sender, method.clone(), uri, body.clone(), cookie_header, extra_headers)
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => {
                    self.pool.remove(host, port);
                    // GOAWAY: retry on a fresh connection
                    if e.is_h2_goaway() {
                        return self
                            .new_connection_request(method, uri, body, cookie_header, host, port, extra_headers)
                            .await;
                    }
                }
            }
        }

        // 3. Try cached H1.1 connection from pool
        if let Some(mut stream) = self.pool.try_take_h1(host, port) {
            match self
                .send_on_h1(&mut stream, method.clone(), uri, body.clone(), cookie_header, extra_headers)
                .await
            {
                Ok((response, keep_alive)) => {
                    if keep_alive {
                        self.pool.insert_h1(host, port, stream);
                    }
                    return Ok(response);
                }
                Err(_) => {}
            }
        }

        self.new_connection_request(method, uri, body, cookie_header, host, port, extra_headers)
            .await
    }

    /// Open a new connection (H3 or TCP→TLS→H2/H1) and send a request.
    /// Extracted from `execute_single_request` steps 4+5 to allow GOAWAY retry.
    async fn new_connection_request(
        &self,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        host: &str,
        port: u16,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse, Error> {
        // 4. Try HTTP/3 if: no proxy, profile has QuicConfig, and Alt-Svc cache says H3 is available
        let has_proxy = self.proxy.is_some();
        let has_quic = self.profile.quic.is_some();
        let h3_port = if !has_proxy && has_quic {
            self.get_alt_svc_h3_port(host, port)
        } else {
            None
        };

        if let Some(h3_port) = h3_port {
            match self.try_h3_connection(host, h3_port, method.clone(), uri, body.clone(), cookie_header).await {
                Ok(response) => {
                    let response = self.decompress_response(response)?;
                    return Ok(response);
                }
                Err(_) => {
                    // H3 failed — remove Alt-Svc entry and fall through to H2/H1
                    self.remove_alt_svc(host, port);
                }
            }
        }

        // 5. New connection: TCP → TLS → H2/H1
        let tcp = self.connect_tcp(host, port).await?;
        let tls_stream = self.tls_connect(tcp, host, port).await?;

        let alpn = tls_stream.ssl().selected_alpn_protocol();
        let is_h2 = matches!(alpn, Some(b"h2"));

        let response = if is_h2 {
            let mut sender = self.h2_handshake(tls_stream).await?;
            let response = self
                .send_on_h2(&mut sender, method, uri, body, cookie_header, extra_headers)
                .await?;
            self.pool.insert_h2(host, port, sender);
            response
        } else {
            let mut stream = tls_stream;
            let (response, keep_alive) = self
                .send_on_h1(&mut stream, method, uri, body, cookie_header, extra_headers)
                .await?;
            if keep_alive {
                self.pool.insert_h1(host, port, stream);
            }
            response
        };

        // Parse Alt-Svc header for future H3 discovery
        if !has_proxy && has_quic {
            self.parse_alt_svc_from_response(host, port, &response.headers);
        }

        Ok(response)
    }

    /// Try to establish an HTTP/3 connection and send a request.
    async fn try_h3_connection(
        &self,
        host: &str,
        h3_port: u16,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
    ) -> Result<HttpResponse, Error> {
        let endpoint = self.get_or_create_quic_endpoint()?;

        let (mut send_request, mut driver) =
            http3::connect(&endpoint, host, h3_port, &self.profile).await?;

        // Spawn the H3 connection driver
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let response = http3::send_request(
            &mut send_request,
            method,
            uri,
            &self.profile,
            &self.custom_headers,
            body,
            cookie_header,
        )
        .await?;

        // Store H3 connection in pool
        self.pool.insert_h3(host, h3_port, send_request);

        Ok(response)
    }

    /// Get or lazily create the shared QUIC endpoint.
    fn get_or_create_quic_endpoint(&self) -> Result<quinn::Endpoint, Error> {
        let mut ep = self.quic_endpoint.lock().unwrap();
        if let Some(endpoint) = ep.as_ref() {
            return Ok(endpoint.clone());
        }
        let quic_config = self
            .profile
            .quic
            .as_ref()
            .ok_or_else(|| Error::Quic("No QuicConfig in profile".into()))?;
        let endpoint = quic::transport::build_endpoint(quic_config)?;
        *ep = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Check Alt-Svc cache for an H3 port for the given origin.
    fn get_alt_svc_h3_port(&self, host: &str, port: u16) -> Option<u16> {
        let cache = self.alt_svc_cache.lock().unwrap();
        if let Some(entry) = cache.get(&(host.to_string(), port)) {
            if entry.expires > Instant::now() {
                return Some(entry.h3_port);
            }
        }
        None
    }

    /// Remove an Alt-Svc entry.
    fn remove_alt_svc(&self, host: &str, port: u16) {
        self.alt_svc_cache
            .lock()
            .unwrap()
            .remove(&(host.to_string(), port));
    }

    /// Parse Alt-Svc header from H1/H2 response and cache H3 port.
    /// When a new Alt-Svc entry is discovered, evict the existing H2/H1 pool entry
    /// so the next request to this origin will attempt H3.
    fn parse_alt_svc_from_response(
        &self,
        host: &str,
        port: u16,
        headers: &[(String, String)],
    ) {
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("alt-svc") {
                continue;
            }
            // Look for h3=":PORT" or h3=":443"
            // Format: h3=":443"; ma=86400, h3-29=":443"; ma=86400
            for part in value.split(',') {
                let part = part.trim();
                if let Some(rest) = part.strip_prefix("h3=\":") {
                    if let Some(end) = rest.find('"') {
                        if let Ok(h3_port) = rest[..end].parse::<u16>() {
                            // Parse max-age
                            let max_age = parse_alt_svc_max_age(part).unwrap_or(86400);
                            let entry = AltSvcEntry {
                                h3_port,
                                expires: Instant::now() + Duration::from_secs(max_age),
                            };
                            self.alt_svc_cache
                                .lock()
                                .unwrap()
                                .insert((host.to_string(), port), entry);
                            // Evict existing H2/H1 pool entry so next request tries H3
                            self.pool.remove(host, port);
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Decompress an HTTP/3 response body.
    fn decompress_response(&self, response: HttpResponse) -> Result<HttpResponse, Error> {
        let content_encoding = response
            .headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(response.body, content_encoding)?;
        Ok(HttpResponse {
            body,
            ..response
        })
    }

    /// Establish TCP connection, optionally through a proxy.
    /// When DoH is enabled, resolves hostname via encrypted DNS first.
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        match &self.proxy {
            None => {
                #[cfg(feature = "doh")]
                if let Some(resolver) = &self.doh_resolver {
                    // Resolve via DoH, then connect to IP directly
                    let addrs = resolver.resolve(host).await?;
                    let addr = std::net::SocketAddr::new(addrs[0], port);
                    let stream =
                        tokio::time::timeout(self.timeout, TcpStream::connect(addr))
                            .await
                            .map_err(|_| Error::Timeout)?
                            .map_err(Error::Io)?;
                    stream.set_nodelay(true).ok();
                    return Ok(stream);
                }

                // Fallback: OS DNS resolution
                let addr = format!("{host}:{port}");
                let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(Error::Io)?;

                // Set TCP_NODELAY for lower latency
                stream.set_nodelay(true).ok();
                Ok(stream)
            }
            Some(proxy) => self.connect_via_proxy(proxy, host, port).await,
        }
    }

    /// Connect through a proxy.
    async fn connect_via_proxy(
        &self,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, Error> {
        match proxy.kind {
            #[cfg(feature = "socks")]
            ProxyKind::Socks5 => {
                let proxy_addr = format!("{}:{}", proxy.host(), proxy.port());
                let target = format!("{target_host}:{target_port}");

                let stream = if let Some(auth) = &proxy.auth {
                    tokio_socks::tcp::Socks5Stream::connect_with_password(
                        proxy_addr.as_str(),
                        target.as_str(),
                        &auth.username,
                        &auth.password,
                    )
                    .await
                    .map_err(|e| Error::Proxy(format!("SOCKS5 error: {e}")))?
                } else {
                    tokio_socks::tcp::Socks5Stream::connect(
                        proxy_addr.as_str(),
                        target.as_str(),
                    )
                    .await
                    .map_err(|e| Error::Proxy(format!("SOCKS5 error: {e}")))?
                };

                Ok(stream.into_inner())
            }
            ProxyKind::Http | ProxyKind::Https => {
                // HTTP CONNECT tunnel
                let proxy_addr = format!("{}:{}", proxy.host(), proxy.port());
                let stream = TcpStream::connect(&proxy_addr)
                    .await
                    .map_err(|e| Error::Proxy(format!("Failed to connect to proxy: {e}")))?;

                // Send CONNECT request
                let connect_req = format!(
                    "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
                     Host: {target_host}:{target_port}\r\n\
                     \r\n"
                );

                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = stream;
                stream
                    .write_all(connect_req.as_bytes())
                    .await
                    .map_err(Error::Io)?;

                // Read response (simple parsing, just check for 200)
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.map_err(Error::Io)?;
                let response = String::from_utf8_lossy(&buf[..n]);

                if !response.contains("200") {
                    return Err(Error::Proxy(format!(
                        "CONNECT tunnel failed: {response}"
                    )));
                }

                Ok(stream)
            }
            #[cfg(not(feature = "socks"))]
            ProxyKind::Socks5 => Err(Error::Proxy("SOCKS5 support not compiled in".into())),
        }
    }

    /// Perform TLS handshake with browser fingerprint (Phase 2).
    async fn tls_connect(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<SslStream<TcpStream>, Error> {
        self.tls_connect_inner(tcp, host, port, false).await
    }

    /// Perform TLS handshake for WebSocket (HTTP/1.1 only ALPN).
    async fn tls_connect_ws(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<SslStream<TcpStream>, Error> {
        self.tls_connect_inner(tcp, host, port, true).await
    }

    async fn tls_connect_inner(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        force_h1_only: bool,
    ) -> Result<SslStream<TcpStream>, Error> {
        // ECH config from DNS HTTPS record (when DoH is available)
        let ech_config = self.get_ech_config(host).await;

        let ssl = TlsConnector::configure_connection(
            &self.tls_connector,
            &self.profile.tls,
            host,
            force_h1_only,
            self.session_cache.as_ref(),
            ech_config.as_deref(),
        )?;

        let mut stream = tokio_boring2::SslStream::new(ssl, tcp)?;
        match Pin::new(&mut stream).connect().await {
            Ok(()) => Ok(stream),
            Err(e) => {
                // ECH retry: if ECH was used, check for retry configs from the server
                if ech_config.is_some() {
                    if let Some(retry_configs) = stream.ssl().get_ech_retry_configs() {
                        let retry_configs: Vec<u8> = retry_configs.to_vec();
                        return self
                            .tls_connect_ech_retry(host, port, force_h1_only, &retry_configs)
                            .await;
                    }
                }
                Err(Error::ConnectionFailed(format!(
                    "TLS handshake failed: {e}"
                )))
            }
        }
    }

    /// Retry TLS connection with ECH retry configs from the server.
    /// Called once after an ECH rejection — no loop to prevent infinite retries.
    async fn tls_connect_ech_retry(
        &self,
        host: &str,
        port: u16,
        force_h1_only: bool,
        retry_configs: &[u8],
    ) -> Result<SslStream<TcpStream>, Error> {
        let tcp = self.connect_tcp(host, port).await?;

        let ssl = TlsConnector::configure_connection(
            &self.tls_connector,
            &self.profile.tls,
            host,
            force_h1_only,
            self.session_cache.as_ref(),
            Some(retry_configs),
        )?;

        let mut stream = tokio_boring2::SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!("TLS ECH retry handshake failed: {e}"))
            })?;

        Ok(stream)
    }

    /// Get ECH config from DNS HTTPS record if DoH is available.
    async fn get_ech_config(&self, _host: &str) -> Option<Vec<u8>> {
        #[cfg(feature = "doh")]
        {
            if let Some(resolver) = &self.doh_resolver {
                if let Ok(Some(record)) = resolver.query_https_record(_host).await {
                    return record.ech_config_list;
                }
            }
        }
        None
    }

    /// Perform the HTTP/2 handshake over a TLS connection.
    /// Configures H2 settings from the browser profile and spawns the connection driver task.
    /// Returns a SendRequest handle that can be cloned and reused for multiple requests.
    async fn h2_handshake(
        &self,
        tls_stream: SslStream<TcpStream>,
    ) -> Result<http2::client::SendRequest<bytes::Bytes>, Error> {
        let h2_config = &self.profile.http2;

        // Build h2 client with fingerprinted settings
        let mut h2_builder = http2::client::Builder::new();

        if let Some(hts) = h2_config.header_table_size {
            h2_builder.header_table_size(hts);
        }
        if let Some(ep) = h2_config.enable_push {
            h2_builder.enable_push(ep);
        }
        if let Some(mcs) = h2_config.max_concurrent_streams {
            h2_builder.max_concurrent_streams(mcs);
        }
        h2_builder.initial_window_size(h2_config.initial_window_size);
        h2_builder.initial_connection_window_size(h2_config.initial_conn_window_size);
        if let Some(mfs) = h2_config.max_frame_size {
            h2_builder.max_frame_size(mfs);
        }
        if let Some(mhls) = h2_config.max_header_list_size {
            h2_builder.max_header_list_size(mhls);
        }

        // Settings order
        if !h2_config.settings_order.is_empty() {
            let mut order = http2::frame::SettingsOrder::builder();
            for setting_id in &h2_config.settings_order {
                let id = match setting_id {
                    SettingId::HeaderTableSize => http2::frame::SettingId::HeaderTableSize,
                    SettingId::EnablePush => http2::frame::SettingId::EnablePush,
                    SettingId::MaxConcurrentStreams => {
                        http2::frame::SettingId::MaxConcurrentStreams
                    }
                    SettingId::InitialWindowSize => http2::frame::SettingId::InitialWindowSize,
                    SettingId::MaxFrameSize => http2::frame::SettingId::MaxFrameSize,
                    SettingId::MaxHeaderListSize => http2::frame::SettingId::MaxHeaderListSize,
                    SettingId::EnableConnectProtocol => {
                        http2::frame::SettingId::EnableConnectProtocol
                    }
                    SettingId::NoRfc7540Priorities => {
                        http2::frame::SettingId::NoRfc7540Priorities
                    }
                };
                order = order.push(id);
            }
            h2_builder.settings_order(order.build());
        }

        // Pseudo-header order
        if !h2_config.pseudo_header_order.is_empty() {
            let mut pseudo = http2::frame::PseudoOrder::builder();
            for ph in &h2_config.pseudo_header_order {
                let id = match ph {
                    PseudoHeader::Method => http2::frame::PseudoId::Method,
                    PseudoHeader::Authority => http2::frame::PseudoId::Authority,
                    PseudoHeader::Scheme => http2::frame::PseudoId::Scheme,
                    PseudoHeader::Path => http2::frame::PseudoId::Path,
                    PseudoHeader::Status => http2::frame::PseudoId::Status,
                    PseudoHeader::Protocol => http2::frame::PseudoId::Protocol,
                };
                pseudo = pseudo.push(id);
            }
            h2_builder.headers_pseudo_order(pseudo.build());
        }

        // Stream dependency for HEADERS frame
        if let Some(dep) = &h2_config.headers_stream_dependency {
            h2_builder.headers_stream_dependency(http2::frame::StreamDependency::new(
                http2::frame::StreamId::from(dep.stream_id),
                dep.weight,
                dep.exclusive,
            ));
        }

        // PRIORITY frames (Firefox sends these, Chrome/Safari disable them)
        if !h2_config.priorities.is_empty() {
            let mut prio_builder = http2::frame::Priorities::builder();
            for pf in &h2_config.priorities {
                let dep = http2::frame::StreamDependency::new(
                    http2::frame::StreamId::from(pf.dependency),
                    pf.weight,
                    pf.exclusive,
                );
                let priority = http2::frame::Priority::new(
                    http2::frame::StreamId::from(pf.stream_id),
                    dep,
                );
                prio_builder = prio_builder.push(priority);
            }
            h2_builder.priorities(prio_builder.build());
        }

        // RFC 7540 Priorities deaktivieren (Chrome 131+, Safari 18.3)
        if let Some(val) = h2_config.no_rfc7540_priorities {
            h2_builder.no_rfc7540_priorities(val);
        }

        // CONNECT protocol (Safari 18.3)
        if let Some(val) = h2_config.enable_connect_protocol {
            h2_builder.enable_connect_protocol(val);
        }

        // Headers field order (for HTTP/2 fingerprinting)
        if !self.profile.headers.is_empty() {
            let mut order = http2::frame::HeadersOrder::builder();
            for (name, _) in &self.profile.headers {
                if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
                    order = order.push(hn);
                }
            }
            h2_builder.headers_order(order.build());
        }

        // Perform the HTTP/2 handshake
        let (client, h2_conn) = h2_builder
            .handshake::<_, bytes::Bytes>(tls_stream)
            .await
            .map_err(Error::Http2)?;

        // Spawn a task to drive the HTTP/2 connection
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        Ok(client)
    }

    /// Send an HTTP/2 request on an existing SendRequest handle.
    /// Waits for stream availability via `ready()`, builds headers, sends request+body, reads response.
    async fn send_on_h2(
        &self,
        sender: &mut http2::client::SendRequest<bytes::Bytes>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse, Error> {
        // Wait until the connection can accept a new stream.
        // Clone is cheap — clones share the same underlying H2 connection via Arc.
        sender.clone().ready().await.map_err(Error::Http2)?;

        // Build the request with headers in the correct order
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let h2_uri: Uri = format!("{scheme}://{authority}{path}")
            .parse()
            .map_err(|_| Error::InvalidHeader("Failed to build H2 URI".into()))?;

        let req_builder = Request::builder()
            .method(method.clone())
            .uri(h2_uri)
            .version(Version::HTTP_2);

        let mut req = req_builder
            .body(())
            .map_err(|e| Error::InvalidHeader(format!("Failed to build request: {e}")))?;

        // Add headers in profile order
        let headers = req.headers_mut();

        for (name, value) in &self.profile.headers {
            let lower = name.to_lowercase();
            if lower == "host" {
                continue;
            }
            // Skip cookie header from profile — we inject from jar
            if lower == "cookie" {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Apply custom headers (override profile defaults)
        for (name, value) in &self.custom_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Apply extra headers (override custom headers, e.g. multipart content-type)
        for (name, value) in extra_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Inject cookie header from jar
        if let Some(cookie_val) = cookie_header {
            if let Ok(hv) = HeaderValue::from_str(cookie_val) {
                headers.insert(http::header::COOKIE, hv);
            }
        }

        // Sort headers to match profile order (critical for fingerprinting)
        sort_headers_by_profile(headers, &self.profile.headers);

        // Send the request
        let has_body = body.is_some();
        let (response_future, mut send_stream) = sender
            .send_request(req, !has_body)
            .map_err(Error::Http2)?;

        // Send body if present
        if let Some(body_bytes) = body {
            send_stream
                .send_data(body_bytes.into(), true)
                .map_err(Error::Http2)?;
        }

        // Await the response
        let response = tokio::time::timeout(self.timeout, response_future)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Http2)?;

        let status = response.status().as_u16();

        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        // Read body
        let mut body_data = Vec::new();
        let mut recv_stream = response.into_body();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.map_err(Error::Http2)?;
            body_data.extend_from_slice(&chunk);
            // Acknowledge received data for flow control
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }

        // Decompress body based on Content-Encoding header
        let content_encoding = resp_headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(body_data, content_encoding)?;

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body,
            version: "h2".to_string(),
            url: uri.to_string(),
        })
    }
    /// Send an HTTP/1.1 request on an existing TLS stream.
    /// Returns the response and whether the connection supports keep-alive.
    async fn send_on_h1(
        &self,
        stream: &mut SslStream<TcpStream>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<(HttpResponse, bool), Error> {
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

        // Build headers in profile order
        let mut headers = http::HeaderMap::new();

        // Add Host header first (required for HTTP/1.1)
        if let Ok(hv) = HeaderValue::from_str(authority) {
            headers.insert(http::header::HOST, hv);
        }

        // Add profile headers
        for (name, value) in &self.profile.headers {
            let lower = name.to_lowercase();
            if lower == "host" || lower == "cookie" {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Apply custom headers
        for (name, value) in &self.custom_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Apply extra headers (override custom headers, e.g. multipart content-type)
        for (name, value) in extra_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Inject cookie header from jar
        if let Some(cookie_val) = cookie_header {
            if let Ok(hv) = HeaderValue::from_str(cookie_val) {
                headers.insert(http::header::COOKIE, hv);
            }
        }

        // Add Connection: keep-alive
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );

        // Sort headers to match profile order
        sort_headers_by_profile(&mut headers, &self.profile.headers);

        // Write request
        let body_ref = body.as_deref();
        http1::write_request(stream, &method, uri, &headers, body_ref).await?;

        // Read response (with timeout)
        let raw = tokio::time::timeout(self.timeout, http1::read_response(stream))
            .await
            .map_err(|_| Error::Timeout)??;

        // Check keep-alive from response
        let keep_alive = !raw
            .headers
            .iter()
            .any(|(k, v)| k == "connection" && v.eq_ignore_ascii_case("close"));

        // Decompress body
        let content_encoding = raw
            .headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(raw.body, content_encoding)?;

        let response = HttpResponse {
            status: raw.status,
            headers: raw.headers,
            body,
            version: "HTTP/1.1".to_string(),
            url: uri.to_string(),
        };

        Ok((response, keep_alive))
    }
}

/// Check if a status code is a redirect.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Resolve a redirect Location against the current URL.
fn resolve_redirect(base: &Uri, location: &str) -> Result<Uri, Error> {
    // If location is already absolute, use it directly
    if location.starts_with("http://") || location.starts_with("https://") {
        return location
            .parse()
            .map_err(|_| Error::Url(url::ParseError::EmptyHost));
    }

    // Relative URL — resolve against base
    let scheme = base.scheme_str().unwrap_or("https");
    let authority = base.authority().map(|a| a.as_str()).unwrap_or("");

    let absolute = if location.starts_with('/') {
        // Absolute path
        format!("{scheme}://{authority}{location}")
    } else {
        // Relative path — resolve against base path directory
        let base_path = base.path();
        let dir = match base_path.rfind('/') {
            Some(i) => &base_path[..=i],
            None => "/",
        };
        format!("{scheme}://{authority}{dir}{location}")
    };

    absolute
        .parse()
        .map_err(|_| Error::Url(url::ParseError::EmptyHost))
}

/// Sort headers to match the profile's header order.
/// Headers listed in the profile are inserted first in profile order,
/// then any remaining headers (custom, cookie) are appended.
fn sort_headers_by_profile(
    headers: &mut http::HeaderMap,
    profile_order: &[(String, String)],
) {
    let mut sorted = http::HeaderMap::with_capacity(headers.keys_len());

    // 1. Headers in profile order
    for (name, _) in profile_order {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            if let Some(val) = headers.remove(&hn) {
                sorted.insert(hn, val);
            }
        }
    }

    // 2. Remaining headers (custom, cookie, etc.)
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            sorted.insert(name, value);
        }
    }

    std::mem::swap(headers, &mut sorted);
}

/// Parse `ma=SECONDS` from an Alt-Svc entry.
fn parse_alt_svc_max_age(entry: &str) -> Option<u64> {
    for part in entry.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("ma=") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Decompress response body based on Content-Encoding header.
fn decompress_body(data: Vec<u8>, encoding: Option<&str>) -> Result<Vec<u8>, Error> {
    match encoding {
        Some("gzip") => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        Some("deflate") => {
            use std::io::Read;
            let mut decoder = flate2::read::DeflateDecoder::new(&data[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        Some("br") => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(&data), &mut out)
                .map_err(Error::Io)?;
            Ok(out)
        }
        Some("zstd") => {
            use std::io::Read;
            let mut decoder = zstd::Decoder::new(&data[..]).map_err(Error::Io)?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        _ => Ok(data),
    }
}
