mod alt_svc;
mod blink_header_map;
mod blocked;
pub(crate) mod body;
pub(crate) mod client_hints;
mod connection;
mod cookies;
mod execute;
mod h1;
mod h2;
mod h3;
pub(crate) mod headers;
mod options;
pub(crate) mod request_body;
mod response;
mod ws;

pub use blocked::blocked_by;
pub(crate) use connection::{BoxedIo, PrefixedStream};
pub(crate) use h2::H2Conn;
pub(crate) use h3::H3Conn;
pub use options::ConnectionOptions;
pub use request_body::Body;
pub use response::{ContentDecoder, HttpResponse, SessionExport, decode_body_text};

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Request hook called before each request is sent, redirects included, with `(method, url)`. An
/// error it returns fails the request unsent.
pub type OnRequestHook = Arc<dyn Fn(&str, &str) -> Result<(), Error> + Send + Sync>;

/// Request hook called after each response head, redirects included, with `(status, url, headers)`.
///
/// Called once cookies are stored. An error fails the request; the response is dropped unread.
pub type OnResponseHook =
    Arc<dyn Fn(u16, &str, &[(String, String)]) -> Result<(), Error> + Send + Sync>;

/// Request hook called before a redirect is followed, with `(status, redirect_url,
/// response_headers)`. `Ok(false)` stops and returns the 3xx response; an error fails the request.
pub type OnRedirectHook =
    Arc<dyn Fn(u16, &str, &[(String, String)]) -> Result<bool, Error> + Send + Sync>;

/// Per-request settings for [`Client::send`]; fields left unset fall back to the client's
/// configuration.
#[derive(Clone, Default)]
pub struct RequestOptions {
    /// Headers of this request, in order. They replace client and profile headers of the same name,
    /// which keep their browser position.
    pub headers: Vec<(String, String)>,
    /// Proxy URL for this request (`http://`, `https://` or `socks5://`), replacing the client's
    /// proxies.
    pub proxy: Option<String>,
    /// Timeout for the whole request: connecting, redirects and the body. `Some(Duration::ZERO)`
    /// disables it.
    pub timeout: Option<Duration>,
    /// Whether redirects are followed.
    pub follow_redirects: Option<bool>,
    /// Maximum number of redirects followed.
    pub max_redirects: Option<u32>,
    /// [`OnRequestHook`] for this request, replacing the client's.
    pub on_request: Option<OnRequestHook>,
    /// [`OnResponseHook`] for this request, replacing the client's.
    pub on_response: Option<OnResponseHook>,
    /// [`OnRedirectHook`] for this request, replacing the client's.
    pub on_redirect: Option<OnRedirectHook>,
}

use btls::ssl::SslConnector;
use btls::x509::X509;
use http::Method;

use crate::cookie::CookieJar;
#[cfg(feature = "doh")]
use crate::dns::DohResolver;
use crate::error::Error;
use crate::multipart::Multipart;
use crate::pool::ConnectionPool;
use crate::profile::{BrowserProfile, FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION};
use crate::proxy::{ProxyConfig, ProxyRotation};
use crate::quic::transport::QuicSetup;
use crate::tls::{SessionCache, TlsConnector};
use crate::websocket::WebSocket;

pub(crate) use execute::HeaderSource;

/// What a zero timeout ("no timeout") becomes: about ten years, short enough not to overflow
/// tokio's `Instant + Duration` deadline.
const NO_TIMEOUT: Duration = Duration::from_secs(315_360_000);

/// Builder for a [`Client`], created with [`Client::builder`].
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
    on_redirect: Option<OnRedirectHook>,
    max_retries: u32,
    locale: Option<String>,
    proxy_headers: Vec<(String, String)>,
    proxy_ca_certs: Vec<X509>,
    danger_accept_invalid_proxy_certs: bool,
    ip_version: Option<IpVersion>,
    resolve_overrides: ResolveOverrides,
    #[cfg(feature = "doh")]
    doh_resolver: Option<DohResolver>,
    #[cfg(feature = "doh")]
    native_https_resolver: Option<crate::dns::NativeHttpsResolver>,
    max_response_body: u64,
}

/// Default for [`ClientBuilder::max_response_body`]: generous for the HTML/JSON/API responses this
/// crate mostly fetches, while still bounding a single response's memory against an unbounded or
/// hostile server. A caller downloading larger files raises it explicitly.
const DEFAULT_MAX_RESPONSE_BODY: u64 = 100 * 1024 * 1024;

/// Addresses that replace DNS for a host and port (see [`ClientBuilder::resolve`]), keyed by
/// lowercase host and port.
pub(crate) type ResolveOverrides = HashMap<(String, u16), Vec<IpAddr>>;

/// IP version that origin addresses are restricted to (see [`ClientBuilder::ip_version`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}

impl TryFrom<u8> for IpVersion {
    type Error = Error;

    /// Accepts `4` or `6`; anything else is [`Error::InvalidArgument`].
    fn try_from(version: u8) -> Result<Self, Error> {
        match version {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            other => Err(Error::InvalidArgument(
                format!("Invalid IP version: {other}. Must be 4 or 6"),
                None,
            )),
        }
    }
}

impl std::str::FromStr for IpVersion {
    type Err = Error;

    /// Accepts `"4"`, `"6"`, `"v4"`, `"v6"`, `"ipv4"` or `"ipv6"`, ignoring case and surrounding
    /// whitespace; anything else is [`Error::InvalidArgument`].
    fn from_str(s: &str) -> Result<Self, Error> {
        let lower = s.trim().to_ascii_lowercase();
        let digits = lower
            .strip_prefix("ipv")
            .or_else(|| lower.strip_prefix('v'))
            .unwrap_or(&lower);
        digits
            .parse::<u8>()
            .map_err(|e| {
                let message = format!("Invalid IP version: '{s}'. Must be 4 or 6");
                Error::InvalidArgument(message, crate::error::boxed(e))
            })
            .and_then(Self::try_from)
    }
}

/// Parses an HTTP method name case-insensitively into its uppercase, wire form (`"get"` becomes
/// `GET`); [`Error::InvalidArgument`] if invalid.
pub fn parse_method(method: &str) -> Result<Method, Error> {
    Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|e| {
        let message = format!("Invalid HTTP method: '{method}'");
        Error::InvalidArgument(message, crate::error::boxed(e))
    })
}

impl ClientBuilder {
    fn new(profile: BrowserProfile) -> Self {
        Self {
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
            on_redirect: None,
            max_retries: 0,
            locale: None,
            proxy_headers: Vec::new(),
            proxy_ca_certs: Vec::new(),
            danger_accept_invalid_proxy_certs: false,
            ip_version: None,
            resolve_overrides: HashMap::new(),
            #[cfg(feature = "doh")]
            doh_resolver: None,
            #[cfg(feature = "doh")]
            native_https_resolver: None,
            max_response_body: DEFAULT_MAX_RESPONSE_BODY,
        }
    }

    /// Sets one proxy for all requests: `http://`, `https://` or `socks5://`, with optional
    /// `user:pass@` credentials. An `https://` proxy's certificate is verified like an origin's
    /// (see [`proxy_ca_certs`](Self::proxy_ca_certs)). [`Error::Proxy`] if the URL is invalid or
    /// has another scheme.
    pub fn proxy(mut self, proxy_url: &str) -> Result<Self, Error> {
        self.proxy = Some(ProxyConfig::parse(proxy_url)?);
        Ok(self)
    }

    /// Sets proxies to rotate through: each request, and each retry, takes the next one in turn.
    /// Takes precedence over [`proxy`](Self::proxy). [`Error::Proxy`] if the list is empty or a URL
    /// is invalid.
    pub fn proxies(mut self, proxy_urls: &[&str]) -> Result<Self, Error> {
        self.proxy_rotation = Some(ProxyRotation::new(proxy_urls)?);
        Ok(self)
    }

    /// Sets the timeout of each request: connecting, all redirects and reading the body.
    /// [`Duration::ZERO`] disables it. Default: 30 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        // Zero would fail every request at once via tokio's timeout, so it means NO_TIMEOUT
        // instead.
        self.timeout = if timeout.is_zero() {
            NO_TIMEOUT
        } else {
            timeout.min(NO_TIMEOUT)
        };
        self
    }

    /// Sets headers sent with every request. They replace profile headers of the same name, which
    /// keep their browser position; a later call replaces the headers of an earlier one.
    #[must_use]
    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.custom_headers = headers;
        self
    }

    /// Sets whether redirects are followed. Default: `true`.
    #[must_use]
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Sets the maximum number of redirects per request; one more fails with
    /// [`Error::TooManyRedirects`]. Default: 10.
    #[must_use]
    pub fn max_redirects(mut self, max: u32) -> Self {
        self.max_redirects = max;
        self
    }

    /// Caps a response body at `max` bytes, decompressed: past it, [`Client::send`]/[`get`](Client::get)/
    /// etc. and [`StreamingResponse::collect_body`](crate::StreamingResponse::collect_body)/
    /// [`decode_content`](crate::StreamingResponse::decode_content) fail with [`Error::Body`] instead
    /// of growing the buffer further, and a compressed body decoding past `max` fails the same way
    /// even if its compressed size is smaller: both protect against an unbounded or malicious server
    /// (a stalled close, or a decompression bomb), which this crate has no other bound against.
    /// Reading a streaming response chunk by chunk without decoding it is not capped: the caller
    /// already controls how much of it to read. `0` disables the cap. Default: 100 MiB.
    #[must_use]
    pub fn max_response_body(mut self, max: u64) -> Self {
        self.max_response_body = if max == 0 { u64::MAX } else { max };
        self
    }

    /// Sets whether the cookie jar stores and sends cookies. Default: `true`.
    #[must_use]
    pub fn cookie_jar(mut self, enabled: bool) -> Self {
        self.cookie_jar = enabled;
        self
    }

    /// Sets whether TLS sessions are resumed. Default: `true`.
    #[must_use]
    pub fn session_resumption(mut self, enabled: bool) -> Self {
        self.session_resumption = enabled;
        self
    }

    /// Binds outgoing connections to `addr`; only addresses of its IP version are then connected
    /// to.
    #[must_use]
    pub fn local_address(mut self, addr: IpAddr) -> Self {
        self.local_address = Some(addr);
        self
    }

    /// Sets the [`OnRequestHook`], called before every request is sent, redirects included. Wrap
    /// errors of your own in [`Error::Hook`].
    #[must_use]
    pub fn on_request<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), Error> + Send + Sync + 'static,
    {
        self.on_request = Some(Arc::new(f));
        self
    }

    /// Sets the [`OnResponseHook`], called after every response head, redirects included.
    #[must_use]
    pub fn on_response<F>(mut self, f: F) -> Self
    where
        F: Fn(u16, &str, &[(String, String)]) -> Result<(), Error> + Send + Sync + 'static,
    {
        self.on_response = Some(Arc::new(f));
        self
    }

    /// Sets the [`OnRedirectHook`], called before each redirect is followed.
    #[must_use]
    pub fn on_redirect<F>(mut self, f: F) -> Self
    where
        F: Fn(u16, &str, &[(String, String)]) -> Result<bool, Error> + Send + Sync + 'static,
    {
        self.on_redirect = Some(Arc::new(f));
        self
    }

    /// Sets how many retries a request gets, across all its redirects, after retryable transport
    /// errors (see [`Error::is_retryable`]); a failed hop is retried unless it's non-idempotent and
    /// already left, taking the rotation's next proxy. Default: 0. See [`Client::send`] for the
    /// exact rule.
    #[must_use]
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Sets the Accept-Language header from a locale such as `"fr-FR"` or `"de"`: the locale, its
    /// base language and English, weighted as the profile's browser does
    /// (`fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7` for Chromium).
    #[must_use]
    pub fn locale(mut self, locale: &str) -> Self {
        self.locale = Some(locale.to_string());
        self
    }

    /// Sets headers for HTTP and HTTPS proxies, sent with every CONNECT request and with plain
    /// `http://` requests, which go to the proxy in absolute form. A `Proxy-Authorization` header
    /// here replaces the one built from the proxy URL's credentials.
    #[must_use]
    pub fn proxy_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.proxy_headers = headers;
        self
    }

    /// Trusts the certificates of the PEM bundle `pem` for `https://` proxies, in addition to the
    /// built-in roots (like curl's `--proxy-cacert`). Origins are still verified against the
    /// built-in roots only. A later call replaces the certificates of an earlier one.
    /// [`Error::InvalidArgument`] if `pem` holds no certificate or an invalid one.
    pub fn proxy_ca_certs(mut self, pem: &[u8]) -> Result<Self, Error> {
        let certs = X509::stack_from_pem(pem).map_err(|e| {
            let message = format!("Invalid proxy CA certificate PEM: {e}");
            Error::InvalidArgument(message, crate::error::boxed(e))
        })?;
        if certs.is_empty() {
            return Err(Error::InvalidArgument(
                "No certificate found in the proxy CA PEM".into(),
                None,
            ));
        }
        self.proxy_ca_certs = certs;
        Ok(self)
    }

    /// Accepts any certificate from `https://` proxies (like curl's `--proxy-insecure`). Default:
    /// `false`.
    ///
    /// The connection stays encrypted, but anyone on the way to the proxy can pose as it and read
    /// the proxy credentials, the hosts requested and plain `http://` requests; prefer
    /// [`proxy_ca_certs`](Self::proxy_ca_certs). Origins are still verified: this affects proxies
    /// only, unlike
    /// [`TlsConfig::danger_accept_invalid_certs`](crate::tls::TlsConfig::danger_accept_invalid_certs).
    #[must_use]
    pub fn danger_accept_invalid_proxy_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_proxy_certs = accept;
        self
    }

    /// Restricts the addresses of origins to one IP version. Proxies are not affected.
    #[must_use]
    pub fn ip_version(mut self, version: IpVersion) -> Self {
        self.ip_version = Some(version);
        self
    }

    /// Connects to `addr` for requests to `host` on `addr.port()` instead of resolving `host` (like
    /// curl's `--resolve host:port:addr`); repeated calls for the same host and port add addresses,
    /// tried in order. Everything else (TLS server name, Host header, cookies, Alt-Svc) still
    /// uses `host` itself; through a proxy, connections go to the proxy, whose host name these
    /// entries resolve too.
    #[must_use]
    pub fn resolve(mut self, host: &str, addr: SocketAddr) -> Self {
        let host = connection::strip_brackets(host).to_ascii_lowercase();
        self.resolve_overrides
            .entry((host, addr.port()))
            .or_default()
            .push(addr.ip());
        self
    }

    /// Adds an entry in curl's `--resolve` format, `host:port:addr[,addr...]`, as
    /// [`resolve`](Self::resolve) does for each address. IPv6 hosts and addresses may be bracketed:
    /// `[::1]:443:[2001:db8::1]`. [`Error::InvalidArgument`] if not in this format.
    pub fn resolve_entry(mut self, entry: &str) -> Result<Self, Error> {
        let (host, port, addrs) = parse_resolve_entry(entry)?;
        for ip in addrs {
            self = self.resolve(host, SocketAddr::new(ip, port));
        }
        Ok(self)
    }

    /// Resolves origins through DNS-over-HTTPS, whose HTTPS records also supply ECH configurations.
    /// Proxies, and origins reached through one, are not resolved with it.
    #[must_use]
    #[cfg(feature = "doh")]
    pub fn doh(mut self, resolver: DohResolver) -> Self {
        self.doh_resolver = Some(resolver);
        self
    }

    /// Uses `resolver` for the plain (non-DoH) DNS HTTPS-record query a profile's default
    /// configuration makes on its own (see
    /// [`QuicConfig::https_rr`](crate::quic::QuicConfig::https_rr)), instead of discovering the
    /// system's nameserver: for a sandbox that can't read it, or to pin a test server. Ignored
    /// once [`doh`](Self::doh) is set.
    #[must_use]
    #[cfg(feature = "doh")]
    pub fn native_https_resolver(mut self, resolver: crate::dns::NativeHttpsResolver) -> Self {
        self.native_https_resolver = Some(resolver);
        self
    }

    /// Builds the [`Client`]. [`Error::InvalidHeader`] for an invalid header name or value (CR/LF
    /// etc.) in [`headers`](Self::headers), [`proxy_headers`](Self::proxy_headers),
    /// [`locale`](Self::locale) or the profile's own headers/hints; [`Error::Config`] or
    /// [`Error::TlsStack`] if `BoringSSL` rejects the profile's TLS settings.
    pub fn build(mut self) -> Result<Client, Error> {
        // Headers are written to the wire verbatim: reject CR/LF and other invalid bytes up front
        // instead of dropping them silently later.
        execute::validate_headers(&self.custom_headers)?;
        execute::validate_headers(&self.proxy_headers)?;

        if let Some(ref locale) = self.locale {
            let accept_lang = build_accept_language(locale, accept_language_style(&self.profile));
            if let Some(pos) = self
                .profile
                .headers
                .iter()
                .position(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
            {
                self.profile.headers[pos].1 = accept_lang;
            } else {
                self.profile
                    .headers
                    .push(("accept-language".to_string(), accept_lang));
            }
        }
        // The profile's own headers/hints go out verbatim too, so validate them here as well.
        execute::validate_headers(&self.profile.headers)?;
        if let Some(hints) = &self.profile.ua_client_hints {
            client_hints::validate(hints)?;
        }

        if self.profile.header_family.is_none() {
            self.profile.header_family = Some(crate::profile::HeaderFamily::detect(&self.profile));
        }

        // Chromium 152-153 vary this order per browser process; Chrome's PqcBandwidthExperiment
        // draws the server-padding size once, shared by TCP and QUIC.
        crate::tls::connector::shuffle_client_trust_anchors(&mut self.profile.tls);
        if let Some(tls) = self.profile.quic.as_mut().and_then(|q| q.tls.as_mut()) {
            crate::tls::connector::shuffle_client_trust_anchors(tls);
        }
        crate::tls::connector::draw_server_padding(&mut self.profile);

        let session_cache = if self.session_resumption {
            Some(SessionCache::new())
        } else {
            None
        };

        let tls_connector =
            TlsConnector::build_connector(&self.profile.tls, session_cache.clone())?;

        let h2_builder = h2::h2_builder(&self.profile.http2);

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
            on_redirect: self.on_redirect,
            max_retries: self.max_retries,
            max_response_body: self.max_response_body,
            proxy_headers: self.proxy_headers,
            proxy_ca_certs: self.proxy_ca_certs,
            danger_accept_invalid_proxy_certs: self.danger_accept_invalid_proxy_certs,
            proxy_tls: OnceLock::new(),
            ip_version: self.ip_version,
            resolve_overrides: self.resolve_overrides,
            #[cfg(feature = "doh")]
            doh_resolver: self.doh_resolver,
            #[cfg(feature = "doh")]
            native_https_resolver: self.native_https_resolver.unwrap_or_default(),
            h2_builder,
            pool: Arc::new(ConnectionPool::new(256, Duration::from_secs(90))),
            alt_svc: Arc::default(),
            host_cache: Mutex::default(),
            quic_setup: OnceLock::new(),
            h3_connections: Arc::default(),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            client_hints: client_hints::ClientHintsState::default(),
        })
    }
}

/// HTTP client that impersonates the browser of a [`BrowserProfile`]: its TLS, HTTP/2 and HTTP/3
/// fingerprints and its headers.
///
/// A client holds a connection pool, a cookie jar and a TLS session cache, as a browser does, so
/// reuse it across requests. Create one with [`Client::new`] or [`Client::builder`].
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
    on_redirect: Option<OnRedirectHook>,
    max_retries: u32,
    /// Cap on a response body, decompressed (see [`ClientBuilder::max_response_body`]).
    max_response_body: u64,
    proxy_headers: Vec<(String, String)>,
    /// Extra trust anchors for HTTPS proxies.
    proxy_ca_certs: Vec<X509>,
    danger_accept_invalid_proxy_certs: bool,
    /// The TLS setup for HTTPS proxies, built on first use: a client may get an HTTPS proxy only
    /// per request.
    proxy_tls: OnceLock<connection::ProxyTls>,
    pub(super) ip_version: Option<IpVersion>,
    resolve_overrides: ResolveOverrides,
    #[cfg(feature = "doh")]
    doh_resolver: Option<DohResolver>,
    /// Queries HTTPS DNS records over plain DNS when no [`DohResolver`] is configured: a profile's
    /// default (non-DoH) configuration, which still discovers HTTP/3 through them (see
    /// [`QuicConfig::https_rr`](crate::quic::QuicConfig::https_rr)).
    #[cfg(feature = "doh")]
    native_https_resolver: crate::dns::NativeHttpsResolver,
    /// The profile's HTTP/2 settings, applied to every HTTP/2 connection.
    h2_builder: http2::client::Builder,
    /// Shared with response bodies, which return HTTP/1.1 connections once they have been read, and
    /// with HTTP/3 connection attempts.
    pool: Arc<ConnectionPool>,
    /// HTTP/3 alternatives learned from Alt-Svc, and broken ones. Shared with HTTP/3 connection
    /// attempts, which mark failures.
    alt_svc: Arc<Mutex<alt_svc::AltSvcCache>>,
    /// Recently resolved host addresses.
    host_cache: Mutex<connection::HostCache>,
    /// What the QUIC connections share (transport and TLS configuration, TLS sessions, address
    /// validation tokens), built on first use.
    quic_setup: OnceLock<Arc<QuicSetup>>,
    /// The HTTP/3 connections that may still be open, shared with HTTP/3 connection attempts.
    h3_connections: Arc<h3::H3Connections>,
    /// Cumulative bytes sent across all requests.
    total_bytes_sent: AtomicU64,
    /// Cumulative bytes received across all requests. Shared with streaming response bodies, which
    /// count their bytes as they are read.
    total_bytes_received: Arc<AtomicU64>,
    /// The client hints origins asked for (Chromium profiles).
    client_hints: client_hints::ClientHintsState,
}

impl Client {
    /// Returns a [`ClientBuilder`] for `profile`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), koon_core::Error> {
    /// use std::time::Duration;
    /// use koon_core::{Chrome, Client};
    ///
    /// let client = Client::builder(Chrome::latest())
    ///     .timeout(Duration::from_secs(10))
    ///     .proxy("http://user:pass@127.0.0.1:8080")?
    ///     .build()?;
    /// let response = client.get("https://example.com/").await?;
    /// println!("{} {}", response.status, response.text());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn builder(profile: BrowserProfile) -> ClientBuilder {
        ClientBuilder::new(profile)
    }

    /// Returns the profile the client impersonates.
    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    /// Returns the profile's User-Agent, if it has one.
    pub fn user_agent(&self) -> Option<&str> {
        self.profile.user_agent()
    }

    /// Closes all pooled connections. The client stays usable and opens new ones as needed;
    /// cookies, TLS sessions and learned HTTP/3 alternatives are kept. Idle HTTP/3 connections
    /// close as the profile's browser closes them at shutdown; one whose response is still being
    /// read stays open until it's done. [`shutdown`](Self::shutdown) ends everything at once.
    pub fn close(&self) {
        // Out of the pool first, so that no request picks a connection that is being closed, but
        // released only after the HTTP/3 ones are closed: releasing the last hold on one ends it as
        // the pool drops it, which for Chrome's profile sends nothing.
        let pooled = self.pool.take_all();
        self.close_h3();
        drop(pooled);
    }

    /// Shuts the client down as a browser does before a program exits: every HTTP/3 connection
    /// closes at once and the pool is cleared, waiting up to 300 ms for the closes to be sent so
    /// they aren't lost if the process exits right after. HTTP/3 responses still being read fail,
    /// as in a browser; HTTP/1.1 and HTTP/2 are unaffected. Usable afterwards, as after
    /// [`close`](Self::close).
    pub async fn shutdown(&self) {
        let sent = self.shutdown_h3();
        self.pool.clear();
        sent.await;
    }

    /// Calls the request's `on_request` hook, else the client's.
    pub(super) fn fire_on_request(
        &self,
        options: &RequestOptions,
        method: &str,
        url: &http::Uri,
    ) -> Result<(), Error> {
        match options.on_request.as_ref().or(self.on_request.as_ref()) {
            Some(hook) => hook(method, &url.to_string()),
            None => Ok(()),
        }
    }

    /// Calls the request's `on_response` hook, else the client's.
    pub(super) fn fire_on_response(
        &self,
        options: &RequestOptions,
        status: u16,
        url: &http::Uri,
        headers: &[(String, String)],
    ) -> Result<(), Error> {
        match options.on_response.as_ref().or(self.on_response.as_ref()) {
            Some(hook) => hook(status, &url.to_string(), headers),
            None => Ok(()),
        }
    }

    /// Calls the request's `on_redirect` hook, else the client's; `true` follows the redirect.
    pub(super) fn fire_on_redirect(
        &self,
        options: &RequestOptions,
        status: u16,
        url: &http::Uri,
        headers: &[(String, String)],
    ) -> Result<bool, Error> {
        match options.on_redirect.as_ref().or(self.on_redirect.as_ref()) {
            Some(hook) => hook(status, &url.to_string(), headers),
            None => Ok(true),
        }
    }

    /// Removes all cookies from the cookie jar; TLS sessions, pooled connections and other state
    /// are kept.
    pub fn clear_cookies(&self) {
        if let Some(jar) = &self.cookie_jar {
            crate::util::lock_recover(jar).clear();
        }
    }

    /// Returns the approximate bytes sent by all requests (headers and bodies, before TLS) since
    /// creation or the last [`reset_counters`](Self::reset_counters).
    pub fn total_bytes_sent(&self) -> u64 {
        self.total_bytes_sent.load(Ordering::Relaxed)
    }

    /// Returns the approximate bytes received by all requests (headers and bodies, before
    /// decompression), counted like [`total_bytes_sent`](Self::total_bytes_sent).
    pub fn total_bytes_received(&self) -> u64 {
        self.total_bytes_received.load(Ordering::Relaxed)
    }

    /// Resets both byte counters to zero.
    pub fn reset_counters(&self) {
        self.total_bytes_sent.store(0, Ordering::Relaxed);
        self.total_bytes_received.store(0, Ordering::Relaxed);
    }

    /// Add bytes to the cumulative counters.
    pub(super) fn track_bytes(&self, sent: u64, received: u64) {
        self.total_bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.total_bytes_received
            .fetch_add(received, Ordering::Relaxed);
    }

    /// The proxy for a request: the next of the rotation, else the single proxy.
    pub(super) fn select_proxy(&self) -> Option<&ProxyConfig> {
        match &self.proxy_rotation {
            Some(rotation) => Some(rotation.next().1),
            None => self.proxy.as_ref(),
        }
    }

    /// Creates a client for `profile` with the default settings; fails as [`ClientBuilder::build`]
    /// does.
    pub fn new(profile: BrowserProfile) -> Result<Self, Error> {
        Self::builder(profile).build()
    }

    /// Sends a GET request; fails as [`request`](Self::request) does.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::GET, url, Body::empty()).await
    }

    /// Sends a POST request; `body` is anything that converts into a
    /// [`Body`]: bytes, a string, a stream, or `None`. Fails as
    /// [`request`](Self::request) does.
    pub async fn post(&self, url: &str, body: impl Into<Body>) -> Result<HttpResponse, Error> {
        self.request(Method::POST, url, body).await
    }

    /// Sends a PUT request; fails as [`request`](Self::request) does.
    pub async fn put(&self, url: &str, body: impl Into<Body>) -> Result<HttpResponse, Error> {
        self.request(Method::PUT, url, body).await
    }

    /// Sends a DELETE request; fails as [`request`](Self::request) does.
    pub async fn delete(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::DELETE, url, Body::empty()).await
    }

    /// Sends a PATCH request; fails as [`request`](Self::request) does.
    pub async fn patch(&self, url: &str, body: impl Into<Body>) -> Result<HttpResponse, Error> {
        self.request(Method::PATCH, url, body).await
    }

    /// Sends a HEAD request; fails as [`request`](Self::request) does.
    pub async fn head(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::HEAD, url, Body::empty()).await
    }

    /// Sends a request with the client's settings; [`send`](Self::send) also takes
    /// [`RequestOptions`].
    ///
    /// # Errors
    /// [`Error::Url`]/[`Error::UnsupportedScheme`] for an invalid URL or redirect target,
    /// [`Error::Timeout`], [`Error::TooManyRedirects`], a request hook's own error, [`Error::Body`]
    /// for a failed or unresendable stream body or a response past
    /// [`max_response_body`](ClientBuilder::max_response_body), or a connection/proxy/TLS/protocol
    /// error once [retries](ClientBuilder::max_retries) run out.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        body: impl Into<Body>,
    ) -> Result<HttpResponse, Error> {
        self.send(method, url, body, RequestOptions::default())
            .await
    }

    /// Sends a POST request with a `multipart/form-data` body, whose boundary follows the profile's
    /// browser. Its Content-Type replaces any in `options`. Fails as [`request`](Self::request)
    /// does.
    pub async fn post_multipart(
        &self,
        url: &str,
        multipart: Multipart,
        mut options: RequestOptions,
    ) -> Result<HttpResponse, Error> {
        let style = match headers::Family::of(&self.profile) {
            headers::Family::Firefox => crate::multipart::BoundaryStyle::Gecko,
            _ => crate::multipart::BoundaryStyle::WebKit,
        };
        let (body, content_type) = multipart.build_with(style);
        options
            .headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        options.headers.push(("content-type".into(), content_type));
        self.send(Method::POST, url, body, options).await
    }

    /// Serializes the session, cookies and TLS sessions, to JSON. [`Error::Json`] if serialization
    /// fails.
    pub fn save_session(&self) -> Result<String, Error> {
        let cookies = self
            .cookie_jar
            .as_ref()
            .map(|jar| crate::util::lock_recover(jar).cookies().to_vec());

        let tls_sessions = self
            .session_cache
            .as_ref()
            .map(|cache| cache.export().sessions);

        let export = SessionExport {
            cookies,
            tls_sessions,
        };

        serde_json::to_string_pretty(&export).map_err(Error::Json)
    }

    /// Loads a session saved with [`save_session`](Self::save_session): its cookies replace the
    /// jar's, its TLS sessions are added. Parts the client has disabled are skipped, and so are
    /// cookies whose name or value breaks the `Set-Cookie` rules (control characters, `;`).
    /// [`Error::Json`] if `json` is not a saved session.
    pub fn load_session(&self, json: &str) -> Result<(), Error> {
        let export: SessionExport = serde_json::from_str(json).map_err(Error::Json)?;

        if let (Some(mut cookies), Some(jar)) = (export.cookies, &self.cookie_jar) {
            // The Cookie header carries them verbatim.
            cookies.retain(|c| crate::cookie::validate_name_value(&c.name, &c.value).is_ok());
            *crate::util::lock_recover(jar) = CookieJar::from_cookies(cookies);
        }

        if let Some(sessions) = export.tls_sessions {
            if let Some(cache) = &self.session_cache {
                let cache_export = crate::tls::SessionCacheExport { sessions };
                cache.import(&cache_export);
            }
        }

        Ok(())
    }

    /// Writes the session, as [`save_session`](Self::save_session) returns it, to `path`.
    /// [`Error::Json`] or [`Error::Io`] if that fails.
    pub fn save_session_to_file(&self, path: &str) -> Result<(), Error> {
        let json = self.save_session()?;
        std::fs::write(path, json).map_err(Error::Io)
    }

    /// Loads a session from a file written by [`save_session_to_file`](Self::save_session_to_file).
    /// [`Error::Io`] if unreadable, [`Error::Json`] if it holds no saved session.
    pub fn load_session_from_file(&self, path: &str) -> Result<(), Error> {
        let json = std::fs::read_to_string(path).map_err(Error::Io)?;
        self.load_session(&json)
    }

    /// Opens a WebSocket connection to a `wss://` or `ws://` URL, over the transport the profile's
    /// browser picks (see [`crate::websocket`]): an RFC 8441 extended CONNECT on an existing HTTP/2
    /// connection where supported, else an HTTP/1.1 upgrade on a new connection. The handshake
    /// follows the browser's header order, Origin and cookies; the client's timeout covers it.
    /// [`Error::UnsupportedScheme`] for another scheme, [`Error::Url`] for an invalid URL,
    /// [`Error::Timeout`], [`Error::WebSocket`] if the upgrade fails, plus connection/proxy/TLS
    /// errors.
    pub async fn websocket(&self, url: &str) -> Result<WebSocket, Error> {
        self.websocket_with_headers(url, Vec::new()).await
    }

    /// Opens a WebSocket connection with extra headers, such as another `Origin`; they replace
    /// handshake headers of the same name. [`Error::InvalidHeader`] for an invalid header, else as
    /// [`websocket`](Self::websocket).
    pub async fn websocket_with_headers(
        &self,
        url: &str,
        extra_headers: Vec<(String, String)>,
    ) -> Result<WebSocket, Error> {
        execute::validate_headers(&extra_headers)?;
        let parsed = url::Url::parse(url.trim())?;
        let secure = match parsed.scheme() {
            "wss" => true,
            "ws" => false,
            other => {
                return Err(Error::UnsupportedScheme(format!(
                    "'{other}' in {url}: use ws:// or wss://"
                )));
            }
        };
        let uri: http::Uri = parsed
            .as_str()
            .parse()
            .map_err(|_| Error::Url(url::ParseError::InvalidDomainCharacter))?;
        let host = connection::strip_brackets(
            parsed
                .host_str()
                .ok_or(Error::Url(url::ParseError::EmptyHost))?,
        )
        .to_string();
        let port = parsed
            .port_or_known_default()
            .unwrap_or(if secure { 443 } else { 80 });
        let proxy = self.select_proxy();

        // Cookies and Origin are those of the http(s) origin of the socket.
        let mut http_url = parsed.clone();
        let _ = http_url.set_scheme(if secure { "https" } else { "http" });
        let http_uri: http::Uri = http_url
            .as_str()
            .parse()
            .map_err(|_| Error::Url(url::ParseError::InvalidDomainCharacter))?;
        let cookie = self
            .cookie_jar
            .as_ref()
            .and_then(|jar| crate::util::lock_recover(jar).cookie_header(&http_uri));

        let target = ws::WsTarget {
            uri: &uri,
            http_uri: &http_uri,
            host: &host,
            port,
            secure,
            proxy,
            cookie: cookie.as_deref(),
            extra_headers: &extra_headers,
        };
        let handshake = self.websocket_handshake(&target);
        let (ws, response_headers) = tokio::time::timeout(self.timeout, handshake)
            .await
            .map_err(|_| Error::Timeout)??;
        if let Some(jar) = &self.cookie_jar {
            crate::util::lock_recover(jar).store_from_response(&http_uri, &response_headers);
        }
        Ok(ws)
    }
}

/// How a browser weights the languages of its Accept-Language header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AcceptLanguageStyle {
    /// Chromium, Safari and Firefox 147+: 0.9, 0.8, … down to 0.1.
    Decrement,
    /// Firefox up to 146: the weights divide 1.0 evenly (`en-US,en;q=0.5`).
    EvenSplit,
    /// Brave: the locale and its base language only, without weights; the q value is added per
    /// request (`BrowserProfile::farble_accept_language`).
    Farbled,
}

fn accept_language_style(profile: &BrowserProfile) -> AcceptLanguageStyle {
    if profile.farble_accept_language {
        return AcceptLanguageStyle::Farbled;
    }
    let firefox_major = headers::header_value(&profile.headers, "user-agent")
        .and_then(|ua| ua.split("Firefox/").nth(1))
        .and_then(|v| v.split('.').next())
        .and_then(|v| v.parse::<u32>().ok());
    match firefox_major {
        Some(major) if major < FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION => {
            AcceptLanguageStyle::EvenSplit
        }
        _ => AcceptLanguageStyle::Decrement,
    }
}

/// The Accept-Language value for a locale: the locale, its base language, then English (`"de"` ->
/// de, en-US, en; `"en-US"` -> en-US, en), weighted as `"fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"`
/// (Chromium, Firefox 147+) or `"fr-FR,fr;q=0.8,en-US;q=0.5,en;q=0.3"` (Firefox ≤146).
fn build_accept_language(locale: &str, style: AcceptLanguageStyle) -> String {
    let lang = locale.split('-').next().unwrap_or(locale);
    let mut languages: Vec<&str> = vec![locale];
    if locale.contains('-') {
        languages.push(lang);
    }
    if style == AcceptLanguageStyle::Farbled {
        return languages.join(",");
    }
    if !lang.eq_ignore_ascii_case("en") {
        languages.extend(["en-US", "en"]);
    }

    let n = languages.len();
    languages
        .iter()
        .enumerate()
        .map(|(i, language)| {
            if i == 0 {
                return language.to_string();
            }
            let q = match style {
                AcceptLanguageStyle::Decrement => (10 - i.min(9)) as f64 / 10.0,
                // Firefox ≤146: q = 1 - i/n, rounded to one decimal.
                AcceptLanguageStyle::EvenSplit => {
                    ((1.0 - i as f64 / n as f64) * 10.0).round() / 10.0
                }
                AcceptLanguageStyle::Farbled => unreachable!("returned above"),
            };
            format!("{language};q={q:.1}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Split a curl `--resolve` entry, `host:port:addr[,addr...]`, into its host, port and addresses
/// (see [`ClientBuilder::resolve_entry`]).
fn parse_resolve_entry(entry: &str) -> Result<(&str, u16, Vec<IpAddr>), Error> {
    let invalid = || {
        Error::InvalidArgument(
            format!("Invalid resolve entry '{entry}': expected host:port:address[,address...]"),
            None,
        )
    };
    let (host, rest) = match entry.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed.split_once(']').ok_or_else(invalid)?;
            (host, rest.strip_prefix(':').ok_or_else(invalid)?)
        }
        None => entry.split_once(':').ok_or_else(invalid)?,
    };
    let (port, addrs) = rest.split_once(':').ok_or_else(invalid)?;
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if host.is_empty() {
        return Err(invalid());
    }
    let addrs = addrs
        .split(',')
        .map(|addr| {
            let addr = addr.trim();
            let addr = addr
                .strip_prefix('[')
                .and_then(|a| a.strip_suffix(']'))
                .unwrap_or(addr);
            addr.parse::<IpAddr>().map_err(|_| invalid())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((host, port, addrs))
}

/// Closes the client's HTTP/3 connections as [`Client::close`] does.
impl Drop for Client {
    fn drop(&mut self) {
        self.close_h3();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_language_decrement() {
        let s = AcceptLanguageStyle::Decrement;
        assert_eq!(build_accept_language("en-US", s), "en-US,en;q=0.9");
        assert_eq!(build_accept_language("en", s), "en");
        assert_eq!(build_accept_language("de", s), "de,en-US;q=0.9,en;q=0.8");
        assert_eq!(
            build_accept_language("fr-FR", s),
            "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
        );
    }

    #[test]
    fn test_accept_language_even_split_firefox_146() {
        let s = AcceptLanguageStyle::EvenSplit;
        assert_eq!(build_accept_language("en-US", s), "en-US,en;q=0.5");
        assert_eq!(build_accept_language("de", s), "de,en-US;q=0.7,en;q=0.3");
    }

    #[test]
    fn resolve_entries_parse_like_curl() {
        let v4: IpAddr = [127, 0, 0, 1].into();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            parse_resolve_entry("example.com:443:127.0.0.1").unwrap(),
            ("example.com", 443, vec![v4])
        );
        assert_eq!(
            parse_resolve_entry("[::1]:8443:[2001:db8::1],127.0.0.1").unwrap(),
            ("::1", 8443, vec![v6, v4])
        );
        assert_eq!(
            parse_resolve_entry("a.test:80:2001:db8::1").unwrap(),
            ("a.test", 80, vec![v6])
        );
        for bad in [
            "",
            "example.com",
            "example.com:443",
            "example.com:443:",
            "example.com:https:127.0.0.1",
            "example.com:70000:127.0.0.1",
            ":443:127.0.0.1",
            "example.com:443:localhost",
            "[::1:443:127.0.0.1",
        ] {
            let err = parse_resolve_entry(bad).unwrap_err();
            assert_eq!(err.code(), "INVALID_ARGUMENT", "{bad}");
        }

        let builder = Client::builder(crate::Chrome::latest())
            .resolve_entry("Example.COM:443:127.0.0.1,[::1]")
            .unwrap();
        assert_eq!(
            builder.resolve_overrides[&("example.com".to_string(), 443)],
            vec![v4, "::1".parse::<IpAddr>().unwrap()]
        );
    }

    fn build_error(builder: ClientBuilder) -> Error {
        builder.build().err().expect("the build must fail")
    }

    #[test]
    fn build_rejects_crlf_in_locale() {
        let err =
            build_error(Client::builder(crate::Chrome::latest()).locale("de\r\nX-Injected: 1"));
        assert_eq!(err.code(), "INVALID_HEADER", "{err}");
    }

    #[test]
    fn build_rejects_crlf_in_profile_json() {
        let chrome = crate::Chrome::latest();
        let json = chrome.to_json_pretty().unwrap();

        // A header value: the User-Agent.
        let ua = chrome.user_agent().unwrap();
        let tampered = json.replace(ua, r"Mozilla/5.0\r\nX-Injected: 1");
        assert_ne!(tampered, json);
        let profile = BrowserProfile::from_json(&tampered).unwrap();
        let err = build_error(Client::builder(profile));
        assert_eq!(err.code(), "INVALID_HEADER", "{err}");

        // A client hint value, sent only when an origin asks for it.
        let tampered = json.replace(r#""model": """#, r#""model": "Pixel\r\nX-Injected: 1""#);
        assert_ne!(tampered, json);
        let profile = BrowserProfile::from_json(&tampered).unwrap();
        let err = build_error(Client::builder(profile));
        assert_eq!(err.code(), "INVALID_HEADER", "{err}");
    }

    #[test]
    fn built_in_profiles_pass_header_validation() {
        for name in BrowserProfile::names() {
            let profile = BrowserProfile::resolve(&name.name).unwrap();
            execute::validate_headers(&profile.headers).unwrap();
            if let Some(hints) = &profile.ua_client_hints {
                client_hints::validate(hints).unwrap();
            }
        }
    }

    #[test]
    fn load_session_skips_cookies_that_would_inject_headers() {
        let url: http::Uri = "https://example.com/".parse().unwrap();
        let mut jar = CookieJar::new();
        jar.store_from_response(
            &url,
            &[
                ("set-cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
            ],
        );
        let mut cookies = jar.cookies().to_vec();
        cookies[1].value = "2\r\nX-Injected: 1".into();
        let json = serde_json::to_string(&SessionExport {
            cookies: Some(cookies),
            tls_sessions: None,
        })
        .unwrap();

        let client = Client::new(crate::Chrome::latest()).unwrap();
        client.load_session(&json).unwrap();
        let jar = crate::util::lock_recover(client.cookie_jar.as_ref().unwrap());
        assert_eq!(jar.cookie_header(&url).as_deref(), Some("a=1"));
    }
}
