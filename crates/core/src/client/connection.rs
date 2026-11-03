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

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) type BoxedIo = Box<dyn Io>;

pub(crate) fn is_idle_and_open(io: &mut BoxedIo) -> bool {
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    matches!(Pin::new(io).poll_read(&mut cx, &mut buf), Poll::Pending)
}

pub(crate) struct OpenedStream {
    pub io: BoxedIo,
    pub peer_addr: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlpnMode {
    Profile,
    Http11Only,
}

const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

const HOST_CACHE_TTL: Duration = Duration::from_secs(60);

const HOST_CACHE_SIZE: usize = 1000;

#[derive(Default)]
pub(super) struct HostCache {
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

pub(super) fn strip_brackets(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

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
                .map_err(|e| Error::Dns(format!("resolving {host}: {e}"), crate::error::boxed(e)))?
                .map(|addr| addr.ip())
                .collect(),
        };
        if !addrs.is_empty() {
            crate::util::lock_recover(&self.host_cache).insert(host, doh.is_some(), addrs.clone());
        }
        Ok(addrs)
    }

    pub(super) async fn prefetch_addresses(&self, host: &str, port: u16) {
        if self.resolve_override(host, port).is_none()
            && strip_brackets(host).parse::<IpAddr>().is_err()
        {
            let _ = self.lookup(host, true).await;
        }
    }

    fn resolve_override(&self, host: &str, port: u16) -> Option<Vec<IpAddr>> {
        let bare = strip_brackets(host);
        self.resolve_overrides
            .get(&(bare.to_ascii_lowercase(), port))
            .cloned()
    }

    pub(super) async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
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
                    Error::Dns(msg, source) => {
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
        let proxy_io = |e: std::io::Error| {
            Error::Proxy(format!("CONNECT failed: {e}"), crate::error::boxed(e))
        };
        io.write_all(request.as_bytes()).await.map_err(proxy_io)?;

        let mut buf = BytesMut::with_capacity(1024);
        let head_end = loop {
            if let Some(end) = crate::http1::find_header_end(&buf) {
                break end;
            }
            if buf.len() > crate::http1::MAX_HEADER_SIZE {
                return Err(Error::Proxy("CONNECT response head too large".into(), None));
            }
            buf.reserve(1024);
            if io.read_buf(&mut buf).await.map_err(proxy_io)? == 0 {
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

    pub(super) async fn connect_tls(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&ProxyConfig>,
        alpn: AlpnMode,
    ) -> Result<(SslStream<BoxedIo>, Option<String>), Error> {
        let ech_lookup = async {
            match proxy {
                None if !self.skips_ech() => self.get_ech_config(host, port).await,
                _ => None,
            }
        };
        let (ech_config, opened) =
            tokio::join!(ech_lookup, self.open_stream(host, port, proxy, true));
        let opened = opened?;

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

    async fn tls_handshake(
        &self,
        io: BoxedIo,
        host: &str,
        alpn: AlpnMode,
        ech_config: Option<&[u8]>,
        session_key: Option<&str>,
    ) -> Result<SslStream<BoxedIo>, TlsFailure> {
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

    async fn proxy_tls_handshake(
        &self,
        tcp: TcpStream,
        proxy: &ProxyConfig,
    ) -> Result<SslStream<BoxedIo>, Error> {
        let proxy_tls = self.proxy_tls()?;
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

    pub(super) fn skips_ech(&self) -> bool {
        matches!(
            self.profile.header_family,
            Some(super::headers::Family::Safari | super::headers::Family::OkHttp)
        )
    }

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

    #[cfg(feature = "doh")]
    async fn https_record(&self, host: &str, port: u16) -> Option<crate::dns::HttpsRecord> {
        let doh = self.doh_resolver.clone();
        let native = self.native_https_resolver.clone();
        let name = host.to_string();
        let lookup = tokio::spawn(async move {
            match doh {
                Some(resolver) => resolver.query_https_records(&name).await,
                None => native.query_https_records(&name).await,
            }
        });
        let records = tokio::time::timeout(HTTPS_RR_TIMEOUT, lookup)
            .await
            .ok()?
            .ok()?
            .ok()?;
        let chromium = matches!(
            self.profile.header_family,
            Some(super::headers::Family::Chromium)
        );
        select_https_record(records, port, chromium)
    }

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

    #[cfg(feature = "doh")]
    fn prefers_https_rr_hints(&self) -> bool {
        self.follows_https_rr() && self.quic_stack_is_apple()
    }
}

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

#[cfg(feature = "doh")]
const HTTPS_RR_TIMEOUT: Duration = Duration::from_millis(300);

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

pub(super) struct ProxyTls {
    connector: SslConnector,
    config: TlsConfig,
}

const FIRST_BYTES: usize = 8;

struct FirstBytes<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
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

pub(crate) fn authority_form(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

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
