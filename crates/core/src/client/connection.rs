use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use btls::ssl::SslConnector;
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio_btls::SslStream;

use super::IpVersion;
use crate::error::Error;
use crate::proxy::{ProxyConfig, ProxyKind};
use crate::tls::session_cache::session_key;
use crate::tls::{SessionCache, TlsConfig, TlsConnector};

/// A byte stream a connection runs on: TCP, possibly wrapped in TLS to the origin and/or an HTTPS
/// proxy, and/or tunnelled through a proxy.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) type BoxedIo = Box<dyn Io>;

/// Check that an idle pooled HTTP/1.1 connection is still usable before sending on it: the server
/// may have closed it while it sat in the pool. Any readable data on an idle connection also
/// disqualifies it.
pub(crate) fn is_idle_and_open(io: &mut BoxedIo) -> bool {
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    matches!(Pin::new(io).poll_read(&mut cx, &mut buf), Poll::Pending)
}

/// A freshly opened stream plus what the caller needs to know about it.
pub(crate) struct OpenedStream {
    pub io: BoxedIo,
    /// IP address of the TCP peer (the proxy when one is used).
    pub peer_addr: Option<String>,
}

/// Which protocols to offer in ALPN.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlpnMode {
    /// The profile's list (h2 + http/1.1 for browsers).
    Profile,
    /// http/1.1 only — WebSocket upgrades.
    Http11Only,
}

/// Delay before starting the next connection attempt while an earlier one is still pending (Happy
/// Eyeballs v2, RFC 8305 §5).
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// How long resolved addresses are reused. Chrome keeps system resolver results for a minute.
const HOST_CACHE_TTL: Duration = Duration::from_secs(60);

/// Most hosts kept in the host cache (Chrome: 1000).
const HOST_CACHE_SIZE: usize = 1000;

/// Recently resolved addresses per host, as the resolver returned them — before the IP version and
/// local address filtering, which depends on the request.
#[derive(Default)]
pub(super) struct HostCache {
    /// Keyed by host and whether DNS-over-HTTPS resolved it.
    entries: HashMap<(String, bool), (Vec<IpAddr>, Instant)>,
}

impl HostCache {
    fn get(&self, host: &str, doh: bool) -> Option<Vec<IpAddr>> {
        self.entries
            .get(&(host.to_string(), doh))
            .filter(|(_, expires)| *expires > Instant::now())
            .map(|(addrs, _)| addrs.clone())
    }

    fn insert(&mut self, host: &str, doh: bool, addrs: Vec<IpAddr>) {
        let key = (host.to_string(), doh);
        if !self.entries.contains_key(&key) {
            super::alt_svc::make_room(&mut self.entries, HOST_CACHE_SIZE, |(_, expires)| *expires);
        }
        self.entries
            .insert(key, (addrs, Instant::now() + HOST_CACHE_TTL));
    }
}

/// Strip the brackets around an IPv6 literal host (`"[::1]"` → `"::1"`); other hosts pass through
/// unchanged. Shared by every place that needs the bare host for a lookup, comparison or override
/// key — the URL and header forms keep the brackets, which SNI, DNS and socket addresses don't
/// want.
pub(super) fn strip_brackets(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// A stream that first yields bytes already read from it, then reads on: what followed a CONNECT
/// response or a WebSocket handshake response in the same read.
pub(crate) struct PrefixedStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub(crate) fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl super::Client {
    /// Look up the addresses of `host`, through DNS-over-HTTPS when it is configured and `use_doh`
    /// is set, else through the system resolver. Answers are reused for [`HOST_CACHE_TTL`].
    async fn lookup(&self, host: &str, use_doh: bool) -> Result<Vec<IpAddr>, Error> {
        #[cfg(feature = "doh")]
        let doh = self.doh_resolver.as_ref().filter(|_| use_doh);
        #[cfg(not(feature = "doh"))]
        let doh: Option<&()> = {
            let _ = use_doh;
            None
        };

        if let Some(addrs) = crate::util::lock_recover(&self.host_cache).get(host, doh.is_some()) {
            return Ok(addrs);
        }
        let addrs: Vec<IpAddr> = match doh {
            #[cfg(feature = "doh")]
            Some(resolver) => resolver.resolve(host).await?,
            _ => tokio::net::lookup_host((host, 0))
                .await
                .map_err(|e| {
                    Error::ConnectionFailed(
                        format!("DNS lookup for {host}: {e}"),
                        crate::error::boxed(e),
                    )
                })?
                .map(|addr| addr.ip())
                .collect(),
        };
        if !addrs.is_empty() {
            crate::util::lock_recover(&self.host_cache).insert(host, doh.is_some(), addrs.clone());
        }
        Ok(addrs)
    }

    /// The addresses [`ClientBuilder::resolve`](super::ClientBuilder::resolve) set for `host` and
    /// `port`.
    fn resolve_override(&self, host: &str, port: u16) -> Option<Vec<IpAddr>> {
        let bare = strip_brackets(host);
        self.resolve_overrides
            .get(&(bare.to_ascii_lowercase(), port))
            .cloned()
    }

    /// Resolve `host` to candidate addresses, applying the IP version and local address
    /// constraints. Addresses alternate between families in resolver order so a broken family can't
    /// stall every attempt.
    pub(super) async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
        // IP literals never go to a resolver.
        let bare = strip_brackets(host);
        let ips = match (self.resolve_override(host, port), bare.parse::<IpAddr>()) {
            (Some(ips), _) => ips,
            (None, Ok(ip)) => vec![ip],
            (None, Err(_)) => match self.hinted_addresses(host, port).await {
                Some(hints) => hints,
                None => self.lookup(host, true).await?,
            },
        };

        let wanted = |ip: &IpAddr| {
            let family_ok = match self.ip_version {
                Some(IpVersion::V4) => ip.is_ipv4(),
                Some(IpVersion::V6) => ip.is_ipv6(),
                None => true,
            };
            let local_ok = match self.local_address {
                Some(local) => local.is_ipv4() == ip.is_ipv4(),
                None => true,
            };
            family_ok && local_ok
        };
        let candidates: Vec<SocketAddr> = ips
            .into_iter()
            .filter(wanted)
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        if candidates.is_empty() {
            return Err(Error::ConnectionFailed(
                format!("no usable address for {host} (IP version / local address constraints)"),
                None,
            ));
        }
        Ok(interleave_families(candidates))
    }

    /// Connect to one address, binding the local address when configured.
    async fn connect_addr(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(local) = self.local_address {
            socket.bind(SocketAddr::new(local, 0))?;
        }
        let stream = socket.connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Connect to the first reachable address. A new attempt starts every 250 ms while earlier ones
    /// are pending; the first success wins.
    async fn connect_any(&self, addrs: &[SocketAddr]) -> Result<TcpStream, Error> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let mut pending = FuturesUnordered::new();
        let mut next = addrs.iter();
        let mut last_error: Option<io::Error> = None;

        if let Some(&addr) = next.next() {
            pending.push(Box::pin(self.connect_addr(addr)));
        }
        loop {
            if pending.is_empty() {
                let Some(&addr) = next.next() else { break };
                pending.push(Box::pin(self.connect_addr(addr)));
            }
            let delay = tokio::time::sleep(CONNECTION_ATTEMPT_DELAY);
            tokio::select! {
                Some(result) = pending.next() => match result {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_error = Some(e),
                },
                _ = delay, if next.len() > 0 => {
                    if let Some(&addr) = next.next() {
                        pending.push(Box::pin(self.connect_addr(addr)));
                    }
                }
            }
        }
        Err(match last_error {
            Some(e) => {
                let message = format!("connect failed: {e}");
                Error::ConnectionFailed(message, crate::error::boxed(e))
            }
            None => Error::ConnectionFailed("no address to connect to".into(), None),
        })
    }

    /// Open a byte stream to `host:port`, directly or through `proxy`. With an HTTP proxy and
    /// `tunnel == false` (plain http:// targets), no CONNECT is sent: the stream goes to the proxy,
    /// requests written in absolute form, as browsers do.
    pub(super) async fn open_stream(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&ProxyConfig>,
        tunnel: bool,
    ) -> Result<OpenedStream, Error> {
        let Some(proxy) = proxy else {
            let addrs = self.resolve(host, port).await?;
            let tcp = self.connect_any(&addrs).await?;
            let peer_addr = tcp.peer_addr().ok().map(|a| a.ip().to_string());
            return Ok(OpenedStream {
                io: Box::new(tcp),
                peer_addr,
            });
        };

        // The proxy host is resolved by the OS: DoH and the IP version preference apply to targets,
        // not to the proxy. An IPv6 literal comes in brackets, which glibc's resolver rejects.
        let bare_proxy_host = strip_brackets(proxy.host());
        let proxy_ips = match (
            self.resolve_override(proxy.host(), proxy.port()),
            bare_proxy_host.parse::<IpAddr>(),
        ) {
            (Some(ips), _) => ips,
            (None, Ok(ip)) => vec![ip],
            (None, Err(_)) => self
                .lookup(proxy.host(), false)
                .await
                .map_err(|e| match e {
                    Error::ConnectionFailed(msg, source) => {
                        Error::Proxy(format!("cannot resolve proxy: {msg}"), source)
                    }
                    e => e,
                })?,
        };
        let proxy_addrs: Vec<SocketAddr> = proxy_ips
            .into_iter()
            .filter(|ip| {
                self.local_address
                    .is_none_or(|local| local.is_ipv4() == ip.is_ipv4())
            })
            .map(|ip| SocketAddr::new(ip, proxy.port()))
            .collect();
        let tcp = self
            .connect_any(&interleave_families(proxy_addrs))
            .await
            .map_err(|e| {
                Error::Proxy(
                    format!("cannot connect to proxy: {e}"),
                    crate::error::boxed(e),
                )
            })?;
        let peer_addr = tcp.peer_addr().ok().map(|a| a.ip().to_string());

        let io: BoxedIo = match proxy.kind {
            ProxyKind::Socks5 => self.socks5_handshake(tcp, proxy, host, port).await?,
            ProxyKind::Http => {
                let io: BoxedIo = Box::new(tcp);
                if tunnel {
                    self.connect_tunnel(io, proxy, host, port).await?
                } else {
                    io
                }
            }
            ProxyKind::Https => {
                let io: BoxedIo = Box::new(self.proxy_tls_handshake(tcp, proxy).await?);
                if tunnel {
                    self.connect_tunnel(io, proxy, host, port).await?
                } else {
                    io
                }
            }
        };
        Ok(OpenedStream { io, peer_addr })
    }

    #[cfg(feature = "socks")]
    async fn socks5_handshake(
        &self,
        tcp: TcpStream,
        proxy: &ProxyConfig,
        host: &str,
        port: u16,
    ) -> Result<BoxedIo, Error> {
        let target = (host, port);
        let stream = match &proxy.auth {
            Some(auth) => {
                tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                    tcp,
                    target,
                    &auth.username,
                    &auth.password,
                )
                .await
            }
            None => tokio_socks::tcp::Socks5Stream::connect_with_socket(tcp, target).await,
        }
        .map_err(|e| Error::Proxy(format!("SOCKS5 error: {e}"), crate::error::boxed(e)))?;
        Ok(Box::new(stream.into_inner()))
    }

    #[cfg(not(feature = "socks"))]
    async fn socks5_handshake(
        &self,
        _tcp: TcpStream,
        _proxy: &ProxyConfig,
        _host: &str,
        _port: u16,
    ) -> Result<BoxedIo, Error> {
        Err(Error::Proxy("SOCKS5 support not compiled in".into(), None))
    }

    /// Establish an HTTP CONNECT tunnel through the proxy on `io`.
    async fn connect_tunnel(
        &self,
        mut io: BoxedIo,
        proxy: &ProxyConfig,
        host: &str,
        port: u16,
    ) -> Result<BoxedIo, Error> {
        let authority = authority_form(host, port);
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        for (name, value) in self.proxy_request_headers(proxy) {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        io.write_all(request.as_bytes()).await.map_err(Error::Io)?;

        let mut buf = BytesMut::with_capacity(1024);
        let head_end = loop {
            if let Some(end) = crate::http1::find_header_end(&buf) {
                break end;
            }
            if buf.len() > crate::http1::MAX_HEADER_SIZE {
                return Err(Error::Proxy("CONNECT response head too large".into(), None));
            }
            buf.reserve(1024);
            if io.read_buf(&mut buf).await.map_err(Error::Io)? == 0 {
                return Err(Error::Proxy(
                    "proxy closed the connection during CONNECT".into(),
                    None,
                ));
            }
        };

        let response = crate::http1::parse_head(&buf[..head_end]).map_err(|e| {
            Error::Proxy(
                format!("invalid CONNECT response: {e}"),
                crate::error::boxed(e),
            )
        })?;
        match response.status {
            200..300 => {
                // Anything after the head belongs to the tunnelled connection.
                let rest = buf.split_off(head_end).freeze();
                if rest.is_empty() {
                    Ok(io)
                } else {
                    Ok(Box::new(PrefixedStream::new(rest, io)))
                }
            }
            407 => Err(Error::Proxy(
                "proxy authentication required (407)".into(),
                None,
            )),
            0 => Err(Error::Proxy("invalid CONNECT response".into(), None)),
            code => Err(Error::Proxy(
                format!("CONNECT tunnel failed: {code} {}", response.reason),
                None,
            )),
        }
    }

    /// Headers sent to an HTTP proxy: Proxy-Authorization from the URL credentials (unless set
    /// explicitly), then the configured proxy headers.
    pub(super) fn proxy_request_headers(&self, proxy: &ProxyConfig) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        let has_manual_auth = self
            .proxy_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"));
        if !has_manual_auth {
            if let Some(auth) = &proxy.auth {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", auth.username, auth.password));
                headers.push(("Proxy-Authorization".into(), format!("Basic {encoded}")));
            }
        }
        headers.extend(self.proxy_headers.iter().cloned());
        headers
    }

    /// Open a TLS connection to `host:port` (through `proxy` if given), including the ECH retry
    /// when the server rejects our ECH config.
    pub(super) async fn connect_tls(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&ProxyConfig>,
        alpn: AlpnMode,
    ) -> Result<(SslStream<BoxedIo>, Option<String>), Error> {
        // Browsers only use ECH configs from DNS HTTPS records they resolved themselves; behind a
        // proxy there is no local lookup, so no ECH. The HTTPS record is looked up beside the
        // addresses and the TCP connection, as in Chrome; the handshake waits for both.
        let ech_lookup = async {
            match proxy {
                None if !self.skips_ech() => self.get_ech_config(host, port).await,
                _ => None,
            }
        };
        let (ech_config, opened) =
            tokio::join!(ech_lookup, self.open_stream(host, port, proxy, true));
        let opened = opened?;

        // Sessions are scoped to origin and proxy: a ticket must not link connections that leave
        // through different exits.
        let session_key = session_key(host, port, proxy.map(|p| &p.url));

        let first = self
            .tls_handshake(
                opened.io,
                host,
                alpn,
                ech_config.as_deref(),
                Some(&session_key),
            )
            .await;
        match first {
            Ok(stream) => Ok((stream, opened.peer_addr)),
            Err(TlsFailure {
                error,
                ech_retry_configs,
            }) => {
                let Some(retry_configs) = ech_retry_configs else {
                    return Err(error);
                };
                // One retry with the server's configs, over the same proxy.
                let opened = self.open_stream(host, port, proxy, true).await?;
                let stream = self
                    .tls_handshake(
                        opened.io,
                        host,
                        alpn,
                        Some(&retry_configs),
                        Some(&session_key),
                    )
                    .await
                    .map_err(|f| f.error)?;
                Ok((stream, opened.peer_addr))
            }
        }
    }

    /// Perform the fingerprinted TLS handshake with an origin on `io`.
    async fn tls_handshake(
        &self,
        io: BoxedIo,
        host: &str,
        alpn: AlpnMode,
        ech_config: Option<&[u8]>,
        session_key: Option<&str>,
    ) -> Result<SslStream<BoxedIo>, TlsFailure> {
        // Safari never offers a session again over TCP (captured on macOS 14 to 27 and iOS 17 to
        // 27): it neither offers nor stores one.
        let resumes = self.profile.header_family != Some(super::headers::Family::Safari);
        let session = match (self.session_cache.as_ref(), session_key) {
            (Some(cache), Some(key)) if resumes => Some((cache, key)),
            _ => None,
        };
        handshake(
            &self.tls_connector,
            &self.profile.tls,
            io,
            host,
            alpn,
            session,
            ech_config,
        )
        .await
    }

    /// TLS to an HTTPS proxy: the profile's `ClientHello`, verified against the proxy's own
    /// certificate, http/1.1 only (no CONNECT over HTTP/2). A plain-HTTP answer is reported as such
    /// and never retried in plain text, which would send the proxy credentials and target
    /// unencrypted.
    async fn proxy_tls_handshake(
        &self,
        tcp: TcpStream,
        proxy: &ProxyConfig,
    ) -> Result<SslStream<BoxedIo>, Error> {
        let proxy_tls = self.proxy_tls()?;
        // The URL keeps an IPv6 literal in brackets; SNI and the certificate check need the bare
        // address.
        let host = strip_brackets(proxy.host());
        let first_bytes = Arc::new(Mutex::new(Vec::new()));
        let io: BoxedIo = Box::new(FirstBytes {
            inner: tcp,
            seen: first_bytes.clone(),
            wanted: FIRST_BYTES,
        });
        handshake(
            &proxy_tls.connector,
            &proxy_tls.config,
            io,
            host,
            AlpnMode::Http11Only,
            None,
            None,
        )
        .await
        .map_err(|f| {
            if crate::util::lock_recover(&first_bytes).starts_with(b"HTTP/") {
                Error::Proxy(
                    format!(
                        "proxy {} answered in plain HTTP; use http:// instead of https:// for this proxy",
                        authority_form(host, proxy.port())
                    ),
                    None,
                )
            } else {
                let message = format!("TLS to proxy failed: {}", f.error);
                Error::Proxy(message, crate::error::boxed(f.error))
            }
        })
    }

    /// The TLS setup for HTTPS proxies, built on first use.
    fn proxy_tls(&self) -> Result<&ProxyTls, Error> {
        if let Some(proxy_tls) = self.proxy_tls.get() {
            return Ok(proxy_tls);
        }
        let mut config = self.profile.tls.clone();
        config.danger_accept_invalid_certs = self.danger_accept_invalid_proxy_certs;
        let connector = TlsConnector::build_proxy_connector(&config, &self.proxy_ca_certs)?;
        Ok(self
            .proxy_tls
            .get_or_init(|| ProxyTls { connector, config }))
    }

    /// Whether the profile's family sends neither real ECH nor GREASE at all, on TCP or QUIC:
    /// Safari and `OkHttp` (Conscrypt has no ECH). Shared by [`connect_tls`](Self::connect_tls) and
    /// [`start_h3`](Self::start_h3) so both skip the same lookup.
    pub(super) fn skips_ech(&self) -> bool {
        matches!(
            self.profile.header_family,
            Some(super::headers::Family::Safari | super::headers::Family::OkHttp)
        )
    }

    /// The ECH config from `host`'s DNS HTTPS record: via `DoH` when configured, else the plain
    /// system-resolver query — except Firefox up to 150 on macOS ([`https_rr_doh_only`]), which
    /// then gets none.
    ///
    /// [`https_rr_doh_only`]: crate::quic::QuicConfig::https_rr_doh_only
    #[cfg_attr(not(feature = "doh"), allow(unused_variables))]
    pub(super) async fn get_ech_config(&self, host: &str, port: u16) -> Option<Vec<u8>> {
        #[cfg(feature = "doh")]
        {
            if self.doh_resolver.is_none() && !self.follows_https_rr() {
                return None;
            }
            return self.https_record(host, port).await?.ech_config_list;
        }
        #[cfg(not(feature = "doh"))]
        None
    }

    /// `host`'s DNS HTTPS record for a request to `port` (via DoH when configured, else a plain
    /// query to the system's nameserver), bounded by [`HTTPS_RR_TIMEOUT`] so a slow resolver falls
    /// through to TCP instead of stalling; cached per resolver and host (Chromium skips a record on
    /// another port, see [`select_https_record`]).
    #[cfg(feature = "doh")]
    async fn https_record(&self, host: &str, port: u16) -> Option<crate::dns::HttpsRecord> {
        let lookup = async {
            match &self.doh_resolver {
                Some(resolver) => resolver.query_https_records(host).await,
                None => self.native_https_resolver.query_https_records(host).await,
            }
        };
        let records = tokio::time::timeout(HTTPS_RR_TIMEOUT, lookup)
            .await
            .ok()
            .and_then(|r| r.ok())?;
        let chromium = matches!(
            self.profile.header_family,
            Some(super::headers::Family::Chromium)
        );
        select_https_record(records, port, chromium)
    }

    /// The port to open the first connection to `host` as HTTP/3 on, when its DNS HTTPS record
    /// advertises `h3` — checked before Alt-Svc has anything cached, for a profile that follows
    /// HTTPS records (see [`QuicConfig::https_rr`](crate::quic::QuicConfig::https_rr)). The
    /// record's own `port` (RFC 9460 §7.2) overrides `port` for Safari and Firefox; Chromium skips
    /// such a record.
    #[cfg_attr(not(feature = "doh"), allow(unused_variables))]
    pub(super) async fn https_rr_h3_port(&self, host: &str, port: u16) -> Option<u16> {
        #[cfg(feature = "doh")]
        {
            let record = self.https_record(host, port).await?;
            record
                .alpn
                .iter()
                .any(|p| p == "h3")
                .then_some(record.port.unwrap_or(port))
        }
        #[cfg(not(feature = "doh"))]
        None
    }

    /// The DNS HTTPS record's address hints for `host`, when its profile prefers them over a normal
    /// A/AAAA lookup (Safari). `None` falls back to the ordinary lookup: the profile doesn't do
    /// this, no record was reachable, or it carried no hints.
    #[cfg_attr(not(feature = "doh"), allow(unused_variables))]
    pub(super) async fn hinted_addresses(&self, host: &str, port: u16) -> Option<Vec<IpAddr>> {
        #[cfg(feature = "doh")]
        {
            if !self.prefers_https_rr_hints() {
                return None;
            }
            let hints = self.https_record(host, port).await?.hint_addresses();
            (!hints.is_empty()).then(|| routable_first(hints))
        }
        #[cfg(not(feature = "doh"))]
        None
    }

    /// Whether the profile resolves a host's address from its DNS HTTPS record's
    /// `ipv4hint`/`ipv6hint` before falling back to A/AAAA, the way Safari does (see
    /// [`hinted_addresses`](Self::hinted_addresses)).
    #[cfg(feature = "doh")]
    fn prefers_https_rr_hints(&self) -> bool {
        self.follows_https_rr() && self.quic_stack_is_apple()
    }
}

/// The HTTPS record of `records` (lowest SvcPriority first) a request to `port` uses: the first
/// one, but for Chromium the first one without a `port` SvcParam or with the request's own
/// (`dns_response_result_extractor.cc` drops a mismatched port before looking at alpn/ECH);
/// Firefox/Safari follow the port.
#[cfg(feature = "doh")]
fn select_https_record(
    records: Vec<crate::dns::HttpsRecord>,
    port: u16,
    chromium: bool,
) -> Option<crate::dns::HttpsRecord> {
    records
        .into_iter()
        .find(|record| !chromium || record.port.is_none_or(|p| p == port))
}

/// `addrs` with those the host has a route to first, in their order, then the rest — the same probe
/// getaddrinfo's RFC 6724 rule 1 uses (a UDP `connect`, which sends nothing). The record's hints
/// aren't pre-sorted like a resolver's A/AAAA answers, so without this an unreachable IPv6 hint
/// (QUIC only tries the first address) would wrongly fall back to TCP.
#[cfg(feature = "doh")]
fn routable_first(addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    let routable = |ip: &IpAddr| {
        let bind = match ip {
            IpAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            IpAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        };
        std::net::UdpSocket::bind(bind)
            .and_then(|socket| socket.connect((*ip, 443)))
            .is_ok()
    };
    let (mut usable, unusable): (Vec<IpAddr>, Vec<IpAddr>) = addrs.into_iter().partition(routable);
    usable.extend(unusable);
    usable
}

/// Upper bound for querying a host's DNS HTTPS record before its first connection: generous for a
/// normal DNS round trip, bounded so a slow or unreachable resolver cannot stall a request that
/// would otherwise just go over TCP (see [`Client::https_record`](super::Client::https_record)).
#[cfg(feature = "doh")]
const HTTPS_RR_TIMEOUT: Duration = Duration::from_millis(300);

/// A failed TLS handshake, with the server's ECH retry configs if it rejected ours.
struct TlsFailure {
    error: Error,
    ech_retry_configs: Option<Vec<u8>>,
}

impl From<Error> for TlsFailure {
    fn from(error: Error) -> Self {
        Self {
            error,
            ech_retry_configs: None,
        }
    }
}

/// The fingerprinted TLS handshake on `io` with `connector` and `config`.
async fn handshake(
    connector: &SslConnector,
    config: &TlsConfig,
    io: BoxedIo,
    host: &str,
    alpn: AlpnMode,
    session: Option<(&SessionCache, &str)>,
    ech_config: Option<&[u8]>,
) -> Result<SslStream<BoxedIo>, TlsFailure> {
    let ssl = TlsConnector::configure_connection(
        connector,
        config,
        host,
        alpn == AlpnMode::Http11Only,
        session,
        ech_config,
    )
    .map_err(TlsFailure::from)?;

    let mut stream = SslStream::new(ssl, io).map_err(|e| TlsFailure::from(Error::from(e)))?;
    match Pin::new(&mut stream).connect().await {
        Ok(()) => Ok(stream),
        Err(e) => {
            let ech_retry_configs = if ech_config.is_some() {
                stream.ssl().get_ech_retry_configs().map(|c| c.to_vec())
            } else {
                None
            };
            Err(TlsFailure {
                error: Error::Tls(e),
                ech_retry_configs,
            })
        }
    }
}

/// The TLS setup for connections to HTTPS proxies: the profile's TLS configuration with the proxy's
/// certificate verification (see
/// [`ClientBuilder::proxy_ca_certs`](super::ClientBuilder::proxy_ca_certs)).
pub(super) struct ProxyTls {
    connector: SslConnector,
    config: TlsConfig,
}

/// How many of the first bytes from an HTTPS proxy are kept: enough to recognize a plain HTTP
/// response to the `ClientHello`.
const FIRST_BYTES: usize = 8;

/// A stream that keeps a copy of the first bytes read from it.
struct FirstBytes<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
    /// How many more bytes to copy.
    wanted: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstBytes<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if this.wanted > 0 {
            let read = &buf.filled()[before..];
            let n = read.len().min(this.wanted);
            crate::util::lock_recover(&this.seen).extend_from_slice(&read[..n]);
            this.wanted -= n;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstBytes<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// `host:port` for request targets, with IPv6 literals in brackets.
pub(crate) fn authority_form(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Reorder addresses to alternate between IPv6 and IPv4, starting with the family of the first
/// resolved address (RFC 8305 §4).
fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addrs.first().copied() else {
        return addrs;
    };
    let (mut primary, mut secondary): (Vec<_>, Vec<_>) = addrs
        .into_iter()
        .partition(|a| a.is_ipv6() == first.is_ipv6());
    let mut out = Vec::with_capacity(primary.len() + secondary.len());
    primary.reverse();
    secondary.reverse();
    loop {
        match (primary.pop(), secondary.pop()) {
            (None, None) => break,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interleave_families() {
        let v6a: SocketAddr = "[::1]:1".parse().unwrap();
        let v6b: SocketAddr = "[::2]:1".parse().unwrap();
        let v4a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let v4b: SocketAddr = "2.2.2.2:1".parse().unwrap();
        assert_eq!(
            interleave_families(vec![v6a, v6b, v4a, v4b]),
            vec![v6a, v4a, v6b, v4b]
        );
        assert_eq!(interleave_families(vec![v4a]), vec![v4a]);
    }

    /// Chromium skips a record on another port, for h3 and ECH alike, and takes the next one;
    /// Firefox and Safari take the first.
    #[cfg(feature = "doh")]
    #[test]
    fn test_chromium_skips_https_records_on_another_port() {
        let record = |port: Option<u16>, ech: u8| crate::dns::HttpsRecord {
            ech_config_list: Some(vec![ech]),
            alpn: vec!["h3".into()],
            port,
            ipv4hint: Vec::new(),
            ipv6hint: Vec::new(),
        };
        let ech = |records, port, chromium| {
            select_https_record(records, port, chromium).and_then(|r| r.ech_config_list)
        };
        let records = vec![record(Some(8443), 1), record(None, 2)];
        assert_eq!(ech(records.clone(), 443, true), Some(vec![2]));
        assert_eq!(ech(records.clone(), 443, false), Some(vec![1]));
        assert_eq!(ech(records, 8443, true), Some(vec![1]));
        // The request's own port, written out, is kept.
        assert_eq!(ech(vec![record(Some(443), 3)], 443, true), Some(vec![3]));
        assert_eq!(ech(vec![record(Some(8443), 4)], 443, true), None);
    }

    #[test]
    fn test_authority_form_brackets_ipv6() {
        assert_eq!(authority_form("example.com", 443), "example.com:443");
        assert_eq!(authority_form("::1", 8080), "[::1]:8080");
        assert_eq!(authority_form("[::1]", 8080), "[::1]:8080");
    }

    #[test]
    fn test_host_cache_is_bounded() {
        let mut cache = HostCache::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for i in 0..HOST_CACHE_SIZE + 10 {
            cache.insert(&format!("h{i}.test"), false, vec![ip]);
        }
        assert_eq!(cache.entries.len(), HOST_CACHE_SIZE);
        assert_eq!(cache.get("h1009.test", false), Some(vec![ip]));
        assert_eq!(cache.get("h1009.test", true), None);
    }

    #[tokio::test]
    async fn test_first_bytes_keeps_only_the_first_bytes() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut stream = FirstBytes {
            inner: &b"HTTP/1.1 400 Bad Request\r\n\r\n"[..],
            seen: seen.clone(),
            wanted: FIRST_BYTES,
        };
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"HTTP/1.1 400 Bad Request\r\n\r\n");
        assert_eq!(*seen.lock().unwrap(), b"HTTP/1.1");
    }

    #[tokio::test]
    async fn test_prefixed_stream_replays_prefix_first() {
        let inner = &b"inner"[..];
        let mut stream = PrefixedStream::new(Bytes::from_static(b"leftover "), inner);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"leftover inner");
    }
}
