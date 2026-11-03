use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use btls::ssl::{NameType, SniError, Ssl, SslAcceptor, SslAlert, SslMethod};
use bytes::{Bytes, BytesMut};
use http::Method;
use http::uri::Authority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::client::{Body, Client, ClientBuilder, HeaderSource, RequestOptions};
use crate::error::Error;
use crate::http1::{BodyFraming, BodyReader, BodyState};
use crate::profile::BrowserProfile;
use crate::streaming::StreamingResponse;

use super::ca::CertAuthority;

const BUFFERED_BODY_LIMIT: usize = 1024 * 1024;

const STREAMED_BODY_PIECES: usize = 8;

const MAX_HEAD_SIZE: usize = 64 * 1024;

const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);

const DEFAULT_MAX_CONNECTIONS: usize = 512;

const IDENTITY_HEADERS: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "upgrade-insecure-requests",
    "priority",
    "te",
    "dnt",
    "sec-gpc",
];

const CONNECTION_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "transfer-encoding",
    "upgrade",
    "trailer",
    "host",
    "content-length",
];

const HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

/// Header handling mode for the MITM proxy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HeaderMode {
    /// The request goes out with the profile's browser identity (TLS, HTTP/2 and headers
    /// fingerprinted), carrying the client's request.
    ///
    /// The profile's own headers (identity and connection-level ones; set the language via
    /// [`ClientBuilder::locale`] on [`ProxyServerConfig::client`]) replace the client's. A specific
    /// `Accept` without `text/html` (not `*/*`, and not a form post) survives instead, marking the
    /// request as an API call sent as a `fetch()`. Every other header (`Cookie`, `Content-Type`,
    /// `Authorization`, `Referer`, `Origin`, conditional and custom headers) is forwarded where the
    /// browser puts it. The response body reaches the client decoded.
    #[default]
    Impersonate,
    /// Pass through client headers as-is (order and case), only TLS and HTTP/2 are fingerprinted.
    /// The response body is passed through unchanged.
    Passthrough,
}

/// Configuration for the MITM proxy server.
pub struct ProxyServerConfig {
    /// Address to listen on. Default: `"127.0.0.1:0"` (random port). Must resolve to a loopback
    /// address unless [`allow_non_loopback`](Self::allow_non_loopback) is set: the proxy relays
    /// through koon's fingerprinted TLS/HTTP2 stack with no transport encryption of its own
    /// between it and its client, so on a reachable interface it is an open relay for anyone who
    /// can reach the port unless [`auth`](Self::auth) is also set.
    pub listen_addr: String,
    /// How to handle HTTP headers from the client.
    pub header_mode: HeaderMode,
    /// Directory for CA certificate storage. Default: `~/.koon/ca/`.
    pub ca_dir: Option<String>,
    /// The client that sends the intercepted requests on: its browser profile fingerprints them,
    /// and its other settings (upstream proxy, `locale`, DNS-over-HTTPS, retries, TLS options, ...)
    /// apply too. Its timeout covers only the response head and each body chunk, so a long download
    /// or event stream is not cut off. The proxy always turns redirect following and the cookie jar
    /// off, since the proxied client handles both itself.
    ///
    /// Default: `Client::builder(Chrome::latest())` (timeout 30 s).
    pub client: ClientBuilder,
    /// Whether [`listen_addr`](Self::listen_addr) may resolve to a non-loopback address. Default:
    /// `false`; `start` then refuses such an address before binding anything.
    pub allow_non_loopback: bool,
    /// `Proxy-Authorization: Basic` credentials required of every proxy-facing request (checked
    /// before a `CONNECT` tunnel is established or a request is forwarded; not re-checked for
    /// requests already inside an established tunnel, which a real client never re-sends proxy
    /// credentials into). Default: `None`.
    pub auth: Option<ProxyServerAuth>,
    /// Connections accepted at once; further ones wait for a slot to free up rather than being
    /// accepted and left unattended. Default: 512.
    pub max_connections: usize,
}

impl Default for ProxyServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".to_string(),
            header_mode: HeaderMode::default(),
            ca_dir: None,
            client: Client::builder(crate::profile::Chrome::latest()),
            allow_non_loopback: false,
            auth: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

/// `Proxy-Authorization: Basic` credentials the MITM proxy requires of its clients (see
/// [`ProxyServerConfig::auth`]).
#[derive(Debug, Clone)]
pub struct ProxyServerAuth {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

/// A local MITM proxy server that intercepts HTTPS traffic and re-sends it using koon's
/// fingerprinted TLS/HTTP2 stack.
pub struct ProxyServer {
    local_addr: SocketAddr,
    ca: Arc<CertAuthority>,
    shutdown_tx: watch::Sender<bool>,
}

impl ProxyServer {
    /// Start the proxy server.
    ///
    /// Binds to the configured address and spawns an accept loop. Returns immediately with the
    /// server handle.
    ///
    /// # Errors
    /// Returns an error if the CA cannot be loaded or generated, the client fails to build, the
    /// listen address cannot be bound, or it resolves to a non-loopback address and
    /// [`ProxyServerConfig::allow_non_loopback`] is not set.
    pub async fn start(config: ProxyServerConfig) -> Result<Self, Error> {
        let ca_dir = config.ca_dir.map_or_else(default_ca_dir, PathBuf::from);
        let ca = tokio::task::spawn_blocking(move || CertAuthority::load_or_generate(ca_dir))
            .await
            .map_err(|e| {
                let message = format!("CA setup task failed: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })??;
        let ca = Arc::new(ca);

        let client = config
            .client
            .follow_redirects(false)
            .cookie_jar(false)
            .build()?;
        let acceptor = build_acceptor(ca.clone())?;

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&config.listen_addr)
            .await
            .map_err(Error::Io)?
            .collect();
        check_listen_addrs(&addrs, config.allow_non_loopback)?;
        let listener = TcpListener::bind(addrs.as_slice())
            .await
            .map_err(Error::Io)?;
        let local_addr = listener.local_addr().map_err(Error::Io)?;

        let connections = Arc::new(Semaphore::new(config.max_connections.max(1)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            client,
            mode: config.header_mode,
            ca: ca.clone(),
            acceptor,
            auth: config.auth,
        });
        tokio::spawn(accept_loop(listener, shared, shutdown_rx, connections));

        Ok(Self {
            local_addr,
            ca,
            shutdown_tx,
        })
    }

    /// The port the proxy is listening on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// The proxy URL (e.g. `http://127.0.0.1:12345`).
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// The local address the proxy is bound to.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Path to the CA certificate PEM file.
    #[must_use]
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca.ca_cert_path()
    }

    /// CA certificate as PEM bytes.
    ///
    /// # Errors
    /// Returns [`Error::Proxy`] if the certificate cannot be PEM-encoded.
    pub fn ca_cert_pem(&self) -> Result<Vec<u8>, Error> {
        self.ca.ca_cert_pem()
    }

    /// Shut down the proxy server: stop accepting and close every open connection, including
    /// running tunnels. Dropping the server does the same.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

fn default_ca_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(
            || PathBuf::from(".koon/ca"),
            |home| PathBuf::from(home).join(".koon").join("ca"),
        )
}

struct Shared {
    client: Client,
    mode: HeaderMode,
    ca: Arc<CertAuthority>,
    acceptor: SslAcceptor,
    auth: Option<ProxyServerAuth>,
}

impl Shared {
    async fn server_tls(&self, host: &str) -> Result<Ssl, Error> {
        let ca = self.ca.clone();
        let host = host.to_string();
        let (cert, key) = tokio::task::spawn_blocking(move || ca.get_or_create_leaf(&host))
            .await
            .map_err(|e| {
                let message = format!("Certificate task failed: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })??;

        let tls_error = |e: btls::error::ErrorStack| {
            let message = format!("TLS setup failed: {e}");
            Error::Proxy(message, crate::error::boxed(e))
        };
        let mut ssl = Ssl::new(self.acceptor.context()).map_err(tls_error)?;
        ssl.set_certificate(&cert).map_err(tls_error)?;
        ssl.set_private_key(&key).map_err(tls_error)?;
        Ok(ssl)
    }
}

fn build_acceptor(ca: Arc<CertAuthority>) -> Result<SslAcceptor, Error> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(|e| {
        let message = format!("TLS acceptor setup failed: {e}");
        Error::Proxy(message, crate::error::boxed(e))
    })?;
    builder.set_servername_callback(move |ssl, alert| {
        let Some(name) = ssl.servername(NameType::HOST_NAME).map(str::to_string) else {
            return Ok(());
        };
        let Ok((cert, key)) = ca.get_or_create_leaf(&name) else {
            return Ok(());
        };
        ssl.set_certificate(&cert)
            .and_then(|()| ssl.set_private_key(&key))
            .map_err(|_| {
                *alert = SslAlert::INTERNAL_ERROR;
                SniError::ALERT_FATAL
            })
    });
    Ok(builder.build())
}

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut shutdown_rx: watch::Receiver<bool>,
    connections: Arc<Semaphore>,
) {
    const MIN_BACKOFF: Duration = Duration::from_millis(5);
    const MAX_BACKOFF: Duration = Duration::from_secs(1);
    let mut backoff = MIN_BACKOFF;
    let connection_rx = shutdown_rx.clone();

    loop {
        let permit = tokio::select! {
            permit = connections.clone().acquire_owned() => {
                permit.expect("the semaphore is never closed")
            }
            _ = shutdown_requested(&mut shutdown_rx) => return,
        };
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        backoff = MIN_BACKOFF;
                        let shared = shared.clone();
                        let mut shutdown_rx = connection_rx.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let handler = Box::pin(handle_connection(stream, &shared));
                            tokio::select! {
                                _ = handler => {}
                                _ = shutdown_requested(&mut shutdown_rx) => {}
                            }
                        });
                    }
                    Err(_) => {
                        drop(permit);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                }
            }
            _ = shutdown_requested(&mut shutdown_rx) => return,
        }
    }
}

async fn shutdown_requested(shutdown_rx: &mut watch::Receiver<bool>) {
    let _ = shutdown_rx.wait_for(|stop| *stop).await;
}

async fn handle_connection(mut stream: TcpStream, shared: &Shared) -> Result<(), Error> {
    let mut buf = Vec::new();
    let Some(first) = next_request(&mut stream, &mut buf).await else {
        return Ok(());
    };
    if !authorized(&first.headers, shared.auth.as_ref()) {
        return write_auth_required(&mut stream).await;
    }

    if first.method.eq_ignore_ascii_case("CONNECT") {
        return match connect_target(&first.target) {
            Some((authority, port)) if buf.is_empty() => {
                handle_connect(stream, authority.host(), port, shared).await
            }
            _ => write_error(&mut stream, 400, "Invalid CONNECT request").await,
        };
    }

    let mut request = first;
    loop {
        let target = request.target.clone();
        if !(target.starts_with("http://") || target.starts_with("https://")) {
            return write_error(&mut stream, 400, "Proxy requests need an absolute URL").await;
        }
        if !forward(&mut stream, &mut buf, shared, request, &target).await? {
            return Ok(());
        }
        match next_request(&mut stream, &mut buf).await {
            Some(next) if !authorized(&next.headers, shared.auth.as_ref()) => {
                return write_auth_required(&mut stream).await;
            }
            Some(next) => request = next,
            None => return Ok(()),
        }
    }
}

fn authorized(headers: &[(String, String)], auth: Option<&ProxyServerAuth>) -> bool {
    let Some(auth) = auth else {
        return true;
    };
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password))
    );
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .is_some_and(|(_, v)| v.trim() == expected)
}

async fn write_auth_required<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), Error> {
    let body = "Proxy authentication required";
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         proxy-authenticate: Basic realm=\"koon\"\r\n\
         content-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len(),
    );
    write_all_timeout(stream, response.as_bytes()).await?;
    flush_timeout(stream).await
}

fn connect_target(target: &str) -> Option<(Authority, u16)> {
    let authority = target.parse::<Authority>().ok()?;
    let has_port = authority
        .as_str()
        .rfind(':')
        .is_some_and(|i| !authority.as_str()[i..].contains(']'));
    match authority.port_u16() {
        Some(port) => Some((authority, port)),
        None if has_port => None,
        None => Some((authority, 443)),
    }
}

async fn handle_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    shared: &Shared,
) -> Result<(), Error> {
    write_all_timeout(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    let ssl = shared.server_tls(host).await?;
    let mut tls = tokio_btls::SslStream::new(ssl, stream).map_err(|e| {
        let message = format!("SslStream::new failed: {e}");
        Error::Proxy(message, crate::error::boxed(e))
    })?;
    tokio::time::timeout(CLIENT_IO_TIMEOUT, Pin::new(&mut tls).accept())
        .await
        .map_err(|_| {
            Error::Proxy(
                "Timed out waiting for TLS handshake from proxy client".into(),
                None,
            )
        })?
        .map_err(|e| {
            let message = format!("TLS accept failed: {e}");
            Error::Proxy(message, crate::error::boxed(e))
        })?;

    let origin = match port {
        443 => format!("https://{host}"),
        port => format!("https://{host}:{port}"),
    };
    let result = serve_tunnel(&mut tls, &origin, shared).await;
    let _ = tls.shutdown().await;
    result
}

async fn serve_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    origin: &str,
    shared: &Shared,
) -> Result<(), Error> {
    let mut buf = Vec::new();
    while let Some(request) = next_request(tls, &mut buf).await {
        if !request.target.starts_with('/') {
            return write_error(tls, 400, "Expected an origin-form request target").await;
        }
        let url = format!("{origin}{}", request.target);
        if !forward(tls, &mut buf, shared, request, &url).await? {
            break;
        }
    }
    Ok(())
}

async fn next_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> Option<ProxyRequest> {
    let (status, message) = match read_request(stream, buf, CLIENT_IO_TIMEOUT).await {
        Ok(request) => return request,
        Err(Error::Io(_)) => return None,
        Err(Error::Timeout) => (408, "Timed out reading the request".to_string()),
        Err(e) => (400, e.to_string()),
    };
    let _ = write_error(stream, status, &message).await;
    None
}

async fn forward<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    shared: &Shared,
    request: ProxyRequest,
    url: &str,
) -> Result<bool, Error> {
    let Ok(method) = Method::from_bytes(request.method.as_bytes()) else {
        write_error(stream, 400, "Invalid method").await?;
        return Ok(false);
    };
    let head_only = method == Method::HEAD;

    let (read_half, mut write_half) = tokio::io::split(&mut *stream);
    let mut body = ClientBody::new(read_half, buf, request.framing);
    let prefix = match body.buffer(BUFFERED_BODY_LIMIT).await {
        Ok(prefix) => prefix,
        Err(e) => {
            if let Some((status, message)) = client_error(&e) {
                write_error(&mut write_half, status, &message).await?;
            }
            return Ok(false);
        }
    };

    let (upstream_body, pump) = build_upstream_body(&body, prefix, request.framing);

    let exchange = async {
        let response = match shared.mode {
            HeaderMode::Impersonate => {
                let options = RequestOptions {
                    headers: impersonated_request_headers(
                        &method,
                        request.headers,
                        shared.client.profile(),
                    ),
                    ..RequestOptions::default()
                };
                shared
                    .client
                    .send_streaming(method, url, upstream_body, options)
                    .await
            }
            HeaderMode::Passthrough => {
                shared
                    .client
                    .send_streaming_with_source(
                        method,
                        url,
                        upstream_body,
                        RequestOptions::default(),
                        HeaderSource::Raw(request.headers),
                    )
                    .await
            }
        };
        match response {
            Ok(response) => {
                let decode = shared.mode == HeaderMode::Impersonate;
                write_response(&mut write_half, response, head_only, decode, request.http11).await
            }
            Err(e) => {
                write_error(&mut write_half, 502, &format!("Proxy error: {e}")).await?;
                Ok(false)
            }
        }
    };
    let pump = async {
        let Some(tx) = pump else {
            return true;
        };
        loop {
            let piece = match body.next().await {
                Ok(Some(piece)) => Ok(piece),
                Ok(None) => return true,
                Err(e) => Err(std::io::Error::other(e.to_string())),
            };
            let failed = piece.is_err();
            if tx.send(piece).await.is_err() || failed {
                return false;
            }
        }
    };
    let (framed, body_read) = tokio::join!(Box::pin(exchange), Box::pin(pump));

    body.finish(buf);
    Ok(framed? && body_read && !request.close)
}

fn build_upstream_body<R: AsyncRead + Unpin>(
    body: &ClientBody<R>,
    prefix: Bytes,
    framing: BodyFraming,
) -> (
    Body,
    Option<tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>>,
) {
    if body.is_done() {
        let upstream_body = match framing {
            BodyFraming::Empty => Body::empty(),
            _ => Body::from(prefix),
        };
        (upstream_body, None)
    } else {
        let (tx, mut rx) = tokio::sync::mpsc::channel(STREAMED_BODY_PIECES);
        if !prefix.is_empty() {
            let _ = tx.try_send(Ok(prefix));
        }
        let pieces = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));
        let upstream_body = match framing {
            BodyFraming::Length(length) => Body::sized_stream(pieces, length),
            _ => Body::stream(pieces),
        };
        (upstream_body, Some(tx))
    }
}

fn client_error(e: &Error) -> Option<(u16, String)> {
    match e {
        Error::Timeout => Some((408, "Timed out reading the request body".into())),
        Error::Io(_) => None,
        e => Some((400, e.to_string())),
    }
}

fn impersonated_request_headers(
    method: &Method,
    headers: Vec<(String, String)>,
    profile: &BrowserProfile,
) -> Vec<(String, String)> {
    let request_accept = |value: &str| {
        let value = value.trim();
        value != "*/*" && !value.to_ascii_lowercase().contains("text/html")
    };
    let keep_accept = crate::client::headers::header_value(&headers, "accept")
        .is_some_and(request_accept)
        && !crate::client::headers::is_navigation(method, &headers);
    headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            if lower == "accept" {
                return keep_accept;
            }
            !(IDENTITY_HEADERS.contains(&lower.as_str())
                || CONNECTION_HEADERS.contains(&lower.as_str())
                || lower.starts_with("sec-ch-")
                || lower.starts_with("sec-fetch-")
                || profile
                    .headers
                    .iter()
                    .any(|(profile_name, _)| profile_name.eq_ignore_ascii_case(name)))
        })
        .collect()
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    mut response: StreamingResponse,
    head_only: bool,
    decode: bool,
    http11: bool,
) -> Result<bool, Error> {
    let status = response.status;
    let has_body = !head_only && status >= 200 && status != 204 && status != 304;
    let decoded = decode && response.decode_content();
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let content_length = match (decoded, header("transfer-encoding")) {
        (false, None) => header("content-length").and_then(|v| v.trim().parse::<u64>().ok()),
        _ => None,
    };
    let chunked = has_body && content_length.is_none() && http11;

    use std::fmt::Write as _;

    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
    for (name, value) in &response.headers {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP_RESPONSE_HEADERS.contains(&lower.as_str())
            || lower == "content-length"
            || (decoded && lower == "content-encoding")
        {
            continue;
        }
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if let Some(len) = content_length {
        let _ = write!(head, "content-length: {len}\r\n");
    }
    if chunked {
        head.push_str("transfer-encoding: chunked\r\n");
    }
    head.push_str("\r\n");
    write_all_timeout(stream, head.as_bytes()).await?;

    if has_body {
        while let Some(chunk) = response.next_chunk().await {
            write_body(stream, &chunk?, chunked).await?;
            flush_timeout(stream).await?;
        }
        if chunked {
            write_all_timeout(stream, b"0\r\n\r\n").await?;
        }
    }
    flush_timeout(stream).await?;
    Ok(!has_body || content_length.is_some() || chunked)
}

async fn write_body<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
    chunked: bool,
) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }
    if chunked {
        let size = format!("{:x}\r\n", data.len());
        write_all_timeout(stream, size.as_bytes()).await?;
    }
    write_all_timeout(stream, data).await?;
    if chunked {
        write_all_timeout(stream, b"\r\n").await?;
    }
    Ok(())
}

async fn write_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    message: &str,
) -> Result<(), Error> {
    let response = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{message}",
        reason_phrase(status),
        message.len(),
    );
    write_all_timeout(stream, response.as_bytes()).await?;
    flush_timeout(stream).await
}

async fn write_all_timeout<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<(), Error> {
    tokio::time::timeout(CLIENT_IO_TIMEOUT, stream.write_all(data))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)
}

async fn flush_timeout<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), Error> {
    tokio::time::timeout(CLIENT_IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)
}

fn reason_phrase(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("")
}

struct ProxyRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    framing: BodyFraming,
    http11: bool,
    close: bool,
}

async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    head_timeout: Duration,
) -> Result<Option<ProxyRequest>, Error> {
    let deadline = tokio::time::Instant::now() + head_timeout;
    let head_len = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEAD_SIZE {
            return Err(Error::Proxy("Request headers too large".into(), None));
        }
        buf.reserve(8192);
        let n = match tokio::time::timeout_at(deadline, stream.read_buf(buf)).await {
            Ok(read) => read.map_err(Error::Io)?,
            Err(_) if buf.is_empty() => return Ok(None),
            Err(_) => return Err(Error::Timeout),
        };
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(Error::Proxy(
                    "Connection closed inside a request".into(),
                    None,
                ))
            };
        }
    };

    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut slots);
    match parsed.parse(&buf[..head_len]) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(Error::Proxy("Incomplete request head".into(), None));
        }
        Err(e) => {
            let message = format!("Malformed request: {e}");
            return Err(Error::Proxy(message, crate::error::boxed(e)));
        }
    }
    let method = parsed.method.unwrap_or_default().to_string();
    let target = parsed.path.unwrap_or_default().to_string();
    let http11 = parsed.version == Some(1);
    let headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    buf.drain(..head_len);

    let connection_has = |token: &str| {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    };
    let close = connection_has("close") || (!http11 && !connection_has("keep-alive"));
    let framing = request_framing(&headers)?;

    Ok(Some(ProxyRequest {
        method,
        target,
        headers,
        framing,
        http11,
        close,
    }))
}

fn request_framing(headers: &[(String, String)]) -> Result<BodyFraming, Error> {
    fn values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
    let transfer_encoding = values(headers, "transfer-encoding");
    let content_lengths = values(headers, "content-length");

    if !transfer_encoding.is_empty() {
        if !content_lengths.is_empty() {
            return Err(Error::Proxy(
                "Request has both Content-Length and Transfer-Encoding headers".into(),
                None,
            ));
        }
        let last_coding = transfer_encoding
            .iter()
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .rfind(|c| !c.is_empty());
        if !last_coding.is_some_and(|c| c.eq_ignore_ascii_case("chunked")) {
            return Err(Error::Proxy(
                "Request Transfer-Encoding does not end in chunked".into(),
                None,
            ));
        }
        return Ok(BodyFraming::Chunked);
    }

    let mut length: Option<u64> = None;
    for value in content_lengths.iter().flat_map(|v| v.split(',')) {
        let value = value.trim();
        let parsed = (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.parse::<u64>().ok())
            .flatten()
            .ok_or_else(|| Error::Proxy(format!("Invalid Content-Length: {value:?}"), None))?;
        if length.is_some_and(|l| l != parsed) {
            return Err(Error::Proxy(
                "Conflicting Content-Length headers".into(),
                None,
            ));
        }
        length = Some(parsed);
    }
    Ok(match length {
        Some(length) if length > 0 => BodyFraming::Length(length),
        _ => BodyFraming::Empty,
    })
}

struct ClientBody<R> {
    reader: BodyReader<R>,
    state: BodyState,
}

impl<R: AsyncRead + Unpin> ClientBody<R> {
    fn new(stream: R, buffered: &mut Vec<u8>, framing: BodyFraming) -> Self {
        let buffered = BytesMut::from(&std::mem::take(buffered)[..]);
        Self {
            reader: BodyReader::with_buffer(stream, buffered),
            state: BodyState::new(framing),
        }
    }

    const fn is_done(&self) -> bool {
        matches!(self.state, BodyState::Done)
    }

    async fn next(&mut self) -> Result<Option<Bytes>, Error> {
        tokio::time::timeout(
            CLIENT_IO_TIMEOUT,
            self.reader.next_body_chunk(&mut self.state),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    async fn buffer(&mut self, limit: usize) -> Result<Bytes, Error> {
        let mut prefix = BytesMut::new();
        if matches!(self.state, BodyState::Length(n) if n > limit as u64) {
            return Ok(prefix.freeze());
        }
        while prefix.len() <= limit {
            match self.next().await? {
                Some(piece) => prefix.extend_from_slice(&piece),
                None => break,
            }
        }
        Ok(prefix.freeze())
    }

    fn finish(self, buf: &mut Vec<u8>) {
        let (_, rest) = self.reader.into_parts();
        buf.extend_from_slice(&rest);
    }
}

fn check_listen_addrs(addrs: &[SocketAddr], allow_non_loopback: bool) -> Result<(), Error> {
    match addrs.iter().find(|addr| !addr.ip().is_loopback()) {
        Some(addr) if !allow_non_loopback => Err(Error::Proxy(
            format!(
                "refusing to listen on non-loopback address {addr}: an unauthenticated MITM proxy \n                 on a reachable interface is an open relay. Set `allow_non_loopback` (and \n                 consider `auth`) to opt in."
            ),
            None,
        )),
        _ => Ok(()),
    }
}
