use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use h3::error::{Code, StreamError};
use h3::fingerprint::ConnectionClose;
use h3_quinn::quinn;
use http::{Method, Request, Uri, Version};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::Error;
use crate::http2::config::PseudoHeader;
use crate::pool::{ConnInfo, H3Sender, Mux, PoolKey};
use crate::quic::transport::QuicSetup;

use super::body::{
    BodyStream, ExchangeError, Http3Body, MuxFailure, ResponseParts, Upload, UploadOr, with_upload,
};
use super::h2::{header_map, response_headers, with_pseudo_headers};
use super::request_body::{Body, ByteStream, LengthCheck, already_sent, stream_error};
use super::response::estimate_headers_size;

/// Upper bound for establishing a QUIC connection (also for a 0-RTT handshake to complete); a
/// timeout marks the HTTP/3 alternative broken.
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest time [`Client::shutdown`](super::Client::shutdown) waits for the closes of its HTTP/3
/// connections to go out.
const SHUTDOWN_WAIT: Duration = Duration::from_millis(300);

/// How often [`Client::shutdown`](super::Client::shutdown) yields to the connection drivers before
/// it waits on the timer.
const SHUTDOWN_YIELDS: u32 = 64;

/// How long the first request on a new connection gives the server packets that arrived with the
/// handshake to be processed (see `server_settings`).
const SETTINGS_WAIT: Duration = Duration::from_millis(1);

/// A new HTTP/3 connection. `id` is its pool ID, unless the pool already had a multiplexed
/// connection for its origin.
pub(super) struct NewH3 {
    pub conn: H3Conn,
    pub info: ConnInfo,
    pub id: Option<u64>,
}

/// Whether an HTTP/3 error ends the connection rather than one stream.
fn h3_connection_failed(e: &StreamError) -> bool {
    !matches!(
        e,
        StreamError::StreamError { .. }
            | StreamError::RemoteTerminate { .. }
            | StreamError::HeaderTooBig { .. }
    )
}

/// A stream failure once the request was sent: `H3_REQUEST_REJECTED` means the server did not
/// process it (RFC 9114 §8.1), everything else means it may have.
fn stream_failed(what: &str, e: StreamError) -> MuxFailure {
    let connection_failed = h3_connection_failed(&e);
    let rejected = matches!(&e, StreamError::RemoteTerminate { code, .. } if *code == Code::H3_REQUEST_REJECTED);
    let message = format!("{what}: {e}");
    let error = Error::Http3(message, crate::error::boxed(e));
    MuxFailure {
        connection_failed,
        error: if rejected {
            ExchangeError::NotSent(error)
        } else {
            ExchangeError::Sent(error)
        },
    }
}

/// Whether a request may go out as 0-RTT data: only safe methods (Chrome `enable_early_data_`,
/// Firefox `Do0RTT`), and never a streamed body, which could not be sent again if the server
/// rejects the early data.
fn may_send_early(method: &Method, body: &Body) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) && !body.is_stream()
}

/// Where a connection's 0-RTT data stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Early {
    /// The handshake of a resumed connection is running; safe requests go out as 0-RTT data.
    Pending,
    /// The handshake is complete. `accepted` tells whether the server took the 0-RTT data (always
    /// `false` without any).
    Done { accepted: bool },
    /// The handshake failed or timed out.
    Failed,
}

/// An HTTP/3 connection as the pool keeps it.
///
/// A resumed connection sends its SETTINGS and safe requests as 0-RTT data. If the server rejects
/// that data, QUIC discards every stream opened so far, and the HTTP/3 session is set up again on
/// the same connection with those requests resent (the server processed none of them).
#[derive(Clone)]
pub(crate) struct H3Conn(Arc<H3Shared>);

struct H3Shared {
    /// The handle requests go out on; replaced once when the server rejects 0-RTT data.
    sender: Mutex<H3Sender>,
    early: watch::Receiver<Early>,
    connection: quinn::Connection,
    setup: Arc<QuicSetup>,
    /// Server name, under which the server's settings are remembered.
    host: String,
    /// Port of the origin, under which the connection's RTT is remembered.
    port: u16,
    /// The server's settings are remembered for this connection.
    settings_remembered: AtomicBool,
    /// Requests in progress (see [`H3Lease`]).
    open_requests: AtomicUsize,
}

impl Drop for H3Shared {
    /// Nothing holds the connection any more. Chrome's `close_on_drop` is `IdleTimeout`: abandon it
    /// and let the server notice at its own idle timeout; other fingerprints close it properly when
    /// `sender` drops next.
    fn drop(&mut self) {
        // The session goes away: Chromium keeps its RTT for the next connection to the origin if
        // its handshake was confirmed.
        let confirmed = matches!(*self.early.borrow(), Early::Done { .. });
        self.setup.remember_rtt(
            &self.host,
            self.port,
            confirmed.then(|| self.connection.rtt()),
        );
        if self.setup.http3().close_on_drop == ConnectionClose::IdleTimeout
            && self.connection.close_reason().is_none()
        {
            self.connection.abandon();
        }
    }
}

impl H3Conn {
    fn new(
        sender: H3Sender,
        early: watch::Receiver<Early>,
        connection: quinn::Connection,
        setup: Arc<QuicSetup>,
        target: &Target<'_>,
    ) -> Self {
        Self(Arc::new(H3Shared {
            sender: Mutex::new(sender),
            early,
            connection,
            setup,
            host: target.host.to_string(),
            port: target.port,
            settings_remembered: AtomicBool::new(false),
            open_requests: AtomicUsize::new(0),
        }))
    }

    fn current(&self) -> H3Sender {
        crate::util::lock_recover(&self.0.sender).clone()
    }

    /// The handle for a request, and whether the request goes out as 0-RTT data. Requests that may
    /// not be sent early wait for the handshake.
    async fn sender(&self, early_ok: bool) -> Result<(H3Sender, bool), Error> {
        // Ended by its idle timeout or by the server.
        if let Some(reason) = self.0.connection.close_reason() {
            let message = format!("QUIC connection closed: {reason}");
            return Err(Error::Quic(message, crate::error::boxed(reason)));
        }
        let mut early = self.0.early.clone();
        if *early.borrow() == Early::Pending {
            if early_ok {
                return Ok((self.current(), true));
            }
            let _ = early.wait_for(|s| *s != Early::Pending).await;
        }
        let state = *early.borrow();
        match state {
            Early::Done { .. } => Ok((self.current(), false)),
            Early::Pending | Early::Failed => {
                Err(Error::Quic("QUIC handshake failed".into(), None))
            }
        }
    }

    /// After a request that went out as 0-RTT data failed: the handle to send it again on if the
    /// server rejected the early data, else `None` (the failure has another cause).
    async fn resend_after_rejection(&self) -> Option<H3Sender> {
        let mut early = self.0.early.clone();
        let _ = early.wait_for(|s| *s != Early::Pending).await;
        let state = *early.borrow();
        (state == Early::Done { accepted: false }).then(|| self.current())
    }

    /// The `ACCEPT_CH` entries of the server's ALPS data. Chromium takes them once the handshake is
    /// complete (`TlsClientHandshaker:: FinishHandshake`), so requests sent as 0-RTT data go
    /// without.
    pub(crate) fn accept_ch(&self) -> Option<Arc<[(String, String)]>> {
        if *self.0.early.borrow() == Early::Pending {
            return None;
        }
        let data = self
            .0
            .connection
            .handshake_data()?
            .downcast::<quinn_btls::HandshakeData>()
            .ok()?;
        let alps = data.peer_application_settings.as_deref()?;
        Some(super::client_hints::alps_accept_ch(alps, true).into())
    }

    /// Whether the TLS handshake resumed a session.
    fn resumed(&self) -> bool {
        self.0
            .connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn_btls::HandshakeData>().ok())
            .is_some_and(|data| data.session_reused)
    }

    /// Keep the server's settings for requests sent as 0-RTT data on the next connection, as the
    /// browsers keep them with the session ticket. Once per connection: the server sends SETTINGS
    /// once.
    fn remember_peer_settings(&self) {
        if self.0.settings_remembered.load(Ordering::Relaxed) {
            return;
        }
        if let Some(settings) = self.current().peer_settings() {
            self.0.setup.remember_peer_settings(&self.0.host, settings);
            self.0.settings_remembered.store(true, Ordering::Relaxed);
        }
    }

    /// The order h3 writes the pseudo-headers in.
    fn pseudo_header_order(&self) -> &[PseudoHeader] {
        self.0.setup.pseudo_header_order()
    }

    /// The fields as the QPACK encoder sends them: Chrome's encoder sends each cookie as a field of
    /// its own (RFC 9114 §4.2.1).
    fn fields_on_the_wire(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        if !self.0.setup.splits_cookies() {
            return headers.to_vec();
        }
        let mut fields = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            if name != "cookie" {
                fields.push((name.clone(), value.clone()));
                continue;
            }
            // Cut at every `;`, dropping one space after it (quiche).
            for (i, crumb) in value.split(';').enumerate() {
                let crumb = if i > 0 {
                    crumb.strip_prefix(' ').unwrap_or(crumb)
                } else {
                    crumb
                };
                fields.push(("cookie".to_string(), crumb.to_string()));
            }
        }
        fields
    }
}

/// A request's hold on its HTTP/3 connection until its response body is read or dropped: the
/// connection stays open whatever the pool does with it meanwhile, and counts as busy (see
/// [`H3Connections::close_all`]).
pub(crate) struct H3Lease(H3Conn);

impl H3Lease {
    fn new(conn: &H3Conn) -> Self {
        conn.0.open_requests.fetch_add(1, Ordering::SeqCst);
        Self(conn.clone())
    }
}

impl Drop for H3Lease {
    fn drop(&mut self) {
        self.0.0.open_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The HTTP/3 connections of a client, so that the client can end them as the browser does when it
/// shuts down. A connection is open as long as the pool or a request holds it (see `Drop for
/// H3Shared`).
#[derive(Default)]
pub(crate) struct H3Connections(Mutex<Vec<Weak<H3Shared>>>);

impl H3Connections {
    fn add(&self, conn: &H3Conn) {
        let mut live = crate::util::lock_recover(&self.0);
        live.retain(|conn| conn.strong_count() > 0);
        live.push(Arc::downgrade(&conn.0));
    }

    /// End the idle connections with `close` (the profile's `close_on_shutdown`); one with a
    /// request in progress is left to end as the pool drops it once that request is done.
    pub(crate) fn close_all(&self, close: &ConnectionClose) {
        crate::util::lock_recover(&self.0).retain(|conn| {
            let Some(conn) = conn.upgrade() else {
                return false;
            };
            if conn.connection.close_reason().is_some() {
                return false;
            }
            if conn.open_requests.load(Ordering::SeqCst) > 0 {
                return true;
            }
            // Closed right here, before this may be the last hold on the connection (see `Drop for
            // H3Shared`).
            close_quic(&conn.connection, close);
            false
        });
    }

    /// End every open connection with `close` at once, requests in progress included (they fail, as
    /// in a browser that shuts down), returning each connection whose close is to be sent with its
    /// datagrams sent so far.
    fn close_all_now(&self, close: &ConnectionClose) -> Vec<(quinn::Connection, u64)> {
        let live = std::mem::take(&mut *crate::util::lock_recover(&self.0));
        let mut closing = Vec::new();
        for conn in live.iter().filter_map(Weak::upgrade) {
            let connection = conn.connection.clone();
            if connection.close_reason().is_some() || *close == ConnectionClose::IdleTimeout {
                continue;
            }
            // Nothing goes out between counting and closing, so the next datagram is the close.
            let hold = connection.hold_transmit();
            let sent = connection.stats().udp_tx.datagrams;
            close_quic(&connection, close);
            drop(hold);
            closing.push((connection, sent));
        }
        closing
    }
}

/// Close a QUIC connection directly, as h3 would through h3-quinn's `close_transport`.
fn close_quic(connection: &quinn::Connection, close: &ConnectionClose) {
    let varint = |v: u64| quinn::VarInt::from_u64(v).unwrap_or(quinn::VarInt::MAX);
    match close {
        ConnectionClose::IdleTimeout => {}
        ConnectionClose::Application { code, reason } => {
            connection.close(varint(u64::from(*code)), reason.as_bytes());
        }
        ConnectionClose::Transport {
            code,
            frame_type,
            reason,
        } => match transport_error_code(*code) {
            Some(code) => {
                connection.close_transport(code, frame_type.map(varint), reason.as_bytes())
            }
            // quinn only sends the codes it knows; h3-quinn falls back so.
            None => connection.close(varint(u64::from(Code::H3_NO_ERROR)), reason.as_bytes()),
        },
        // An unrecognized reason (from a newer h3) behaves like IdleTimeout: nothing is sent, the
        // connection closes on its own.
        _ => {}
    }
}

/// The transport error code quinn can send for `code`, or `None` if `code` doesn't fit a QUIC
/// varint (h3's own codes always do, so this is not reachable in practice).
fn transport_error_code(code: u64) -> Option<quinn::TransportErrorCode> {
    quinn::VarInt::from_u64(code)
        .ok()
        .map(quinn::TransportErrorCode::from)
}

impl super::Client {
    /// End the client's HTTP/3 connections as the browser does when it shuts down (see
    /// [`H3Connections::close_all`]).
    pub(super) fn close_h3(&self) {
        if let Some(setup) = self.quic_setup.get() {
            self.h3_connections
                .close_all(&setup.http3().close_on_shutdown);
        }
    }

    /// End the client's HTTP/3 connections at once as the browser does when it shuts down, and
    /// return a wait until their closes have gone out (handed to the socket), at most
    /// [`SHUTDOWN_WAIT`].
    pub(super) fn shutdown_h3(&self) -> impl Future<Output = ()> + use<> {
        let closing = match self.quic_setup.get() {
            Some(setup) => self
                .h3_connections
                .close_all_now(&setup.http3().close_on_shutdown),
            None => Vec::new(),
        };
        async move {
            let deadline = tokio::time::Instant::now() + SHUTDOWN_WAIT;
            let mut yields = 0;
            for (connection, sent) in closing {
                while connection.stats().udp_tx.datagrams <= sent {
                    if tokio::time::Instant::now() >= deadline {
                        return;
                    }
                    // A close goes out as soon as its connection's driver runs. quinn has no event
                    // for it: yield to the driver first, and only then fall back to the timer,
                    // whose ticks are about 15.6 ms apart on Windows.
                    if yields < SHUTDOWN_YIELDS {
                        yields += 1;
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        }
    }

    /// What the QUIC connections of the client share, built on first use.
    fn quic_setup(&self) -> Result<Arc<QuicSetup>, Error> {
        if let Some(setup) = self.quic_setup.get() {
            return Ok(setup.clone());
        }
        let quic = self
            .profile
            .quic
            .as_ref()
            .ok_or_else(|| Error::Quic("no QUIC config in profile".into(), None))?;
        let setup = Arc::new(QuicSetup::new(
            quic,
            &self.profile.tls,
            self.session_cache.is_some(),
        )?);
        // Another request may have built one meanwhile; all use the first.
        let _ = self.quic_setup.set(setup);
        Ok(self
            .quic_setup
            .get()
            .expect("QUIC setup was just set")
            .clone())
    }

    /// Start an HTTP/3 connection to the origin of `key` on `h3_port`. The handshake runs in a task
    /// of its own and completes even after the request that started it has moved on (TCP won, or it
    /// was cancelled): a failure marks the alternative broken, else offers the pool a connection.
    pub(super) async fn start_h3(
        &self,
        key: &PoolKey,
        h3_port: u16,
    ) -> JoinHandle<Result<NewH3, Error>> {
        let setup = async {
            let setup = self.quic_setup()?;
            // Concurrent with resolving the address, as `connect_tls` does for TCP: same lookup,
            // same profile's ECH config, same Safari/OkHttp skip (`skips_ech`) — neither sends ECH
            // at all, real or GREASE.
            let (addrs, ech_config_list) = tokio::join!(self.resolve(&key.host, h3_port), async {
                if self.skips_ech() {
                    None
                } else {
                    // The request's port, not the HTTP/3 one.
                    self.get_ech_config(&key.host, key.port).await
                }
            });
            let addr = *addrs
                .map_err(|e| {
                    let message = format!("resolving {}: {e}", key.host);
                    Error::Quic(message, crate::error::boxed(e))
                })?
                .first()
                .ok_or_else(|| Error::Quic(format!("no address for {}", key.host), None))?;
            // Each connection has a UDP socket of its own, as in browsers (see `quic::transport`).
            let bind = match self.local_address {
                Some(local) => SocketAddr::new(local, 0),
                None if addr.is_ipv6() => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                None => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            };
            let endpoint = setup.endpoint(bind)?;
            Ok::<_, Error>((setup, endpoint, addr, ech_config_list))
        }
        .await;

        let (pool, alt_svc, key) = (self.pool.clone(), self.alt_svc.clone(), key.clone());
        let connections = self.h3_connections.clone();
        tokio::spawn(async move {
            let broken = {
                let (alt_svc, key) = (alt_svc.clone(), key.clone());
                move || crate::util::lock_recover(&alt_svc).mark_broken(&key.host, key.port)
            };
            let connected = match setup {
                Ok((setup, endpoint, addr, ech_config_list)) => {
                    let target = Target {
                        addr,
                        host: &key.host,
                        port: key.port,
                        alt_used: alt_used(&key.host, h3_port),
                        ech_config_list,
                    };
                    connect_h3(setup, endpoint, target, broken.clone()).await
                }
                Err(e) => Err(e),
            };
            match connected {
                Ok((conn, info)) => {
                    crate::util::lock_recover(&alt_svc).confirm(&key.host, key.port);
                    connections.add(&conn);
                    let id = pool.put_mux(key, Mux::H3(conn.clone()), info.clone());
                    Ok(NewH3 { conn, info, id })
                }
                Err(e) => {
                    broken();
                    Err(e)
                }
            }
        })
    }

    /// Send one request on an HTTP/3 connection and read the response head.
    pub(super) async fn send_h3(
        &self,
        conn: H3Conn,
        ctx: SendContext<'_>,
        body: &Body,
    ) -> Result<ResponseParts, MuxFailure> {
        let SendContext {
            info,
            reused,
            method,
            uri,
            headers,
        } = ctx;
        let (sender, early) = conn
            .sender(may_send_early(method, body) && conn.0.setup.sends_early_requests())
            .await
            .map_err(|e| MuxFailure {
                error: ExchangeError::NotSent(e),
                connection_failed: true,
            })?;
        let request = Exchange {
            conn: &conn,
            info: &info,
            reused,
            method,
            uri,
            headers: &headers,
            body,
        };
        let mut result = request.run(sender).await;
        if early && result.is_err() {
            if let Some(sender) = conn.resend_after_rejection().await {
                // The server discarded the early data unprocessed.
                result = request.run(sender).await;
            }
        }
        let mut parts = result?;
        parts.info.tls_resumed = conn.resumed();
        conn.remember_peer_settings();
        Ok(parts)
    }
}

/// The Alt-Used value for an alternative on the origin's host (Firefox
/// `nsHttpChannel::BeginConnect`): the host, and the port unless it is 443.
fn alt_used(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// What [`Client::send_h2`](super::Client::send_h2) and [`Client::send_h3`](super::Client::send_h3)
/// need beyond the connection and the body.
pub(super) struct SendContext<'a> {
    pub info: ConnInfo,
    pub reused: bool,
    pub method: &'a Method,
    pub uri: &'a Uri,
    /// The regular headers, in wire order.
    pub headers: Vec<(String, String)>,
}

/// One request/response exchange on an HTTP/3 connection.
struct Exchange<'a> {
    conn: &'a H3Conn,
    info: &'a ConnInfo,
    reused: bool,
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a [(String, String)],
    body: &'a Body,
}

/// A request sent on an HTTP/3 connection, and what reading its response needs (see
/// [`Exchange::send`]/[`Exchange::read_response`]).
struct SentRequest {
    lease: H3Lease,
    recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    upload: Option<Upload>,
    request_headers: Vec<(String, String)>,
    bytes_sent: u64,
}

impl Exchange<'_> {
    async fn run(&self, sender: H3Sender) -> Result<ResponseParts, MuxFailure> {
        self.send(sender).await?.read_response(self).await
    }

    /// Build the request, send its headers, then its body (if any).
    async fn send(&self, mut sender: H3Sender) -> Result<SentRequest, MuxFailure> {
        let Exchange {
            conn,
            method,
            uri,
            headers,
            body,
            ..
        } = *self;
        let request_failed = |e: Error| MuxFailure {
            error: ExchangeError::Invalid(e),
            connection_failed: false,
        };
        let lease = H3Lease::new(conn);
        let mut request = Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .version(Version::HTTP_3)
            .body(())
            .map_err(|e| {
                let message = e.to_string();
                request_failed(Error::InvalidHeader(message, crate::error::boxed(e)))
            })?;
        // h3 writes the fields in the map's order, which is the browser's.
        *request.headers_mut() = header_map(headers).map_err(request_failed)?;

        let request_headers = with_pseudo_headers(
            conn.pseudo_header_order(),
            method,
            uri,
            conn.fields_on_the_wire(headers),
        );
        let bytes_sent =
            estimate_headers_size(&request_headers) + body.content_length().unwrap_or(0);

        // A request without a body goes out as one STREAM frame with the HEADERS frame and the FIN,
        // as in the browsers.
        let bodyless = !body.is_stream() && body.bytes().is_none_or(|bytes| bytes.is_empty());
        let stream = if bodyless {
            sender.send_request_and_finish(request).await
        } else {
            sender.send_request(request).await
        };
        // Failing to open a stream means nothing was sent; a field section above the server's limit
        // cannot be sent on any connection.
        let stream = stream.map_err(|e| {
            let connection_failed = h3_connection_failed(&e);
            let header_too_big = matches!(e, StreamError::HeaderTooBig { .. });
            let message = format!("sending request: {e}");
            let error = Error::Http3(message, crate::error::boxed(e));
            MuxFailure {
                connection_failed,
                error: if header_too_big {
                    ExchangeError::Invalid(error)
                } else {
                    ExchangeError::NotSent(error)
                },
            }
        })?;
        let (send, recv) = stream.split();
        let mut send = H3Send {
            stream: send,
            finished: bodyless,
        };
        let mut upload = None;
        if bodyless {
            // Finished together with the HEADERS frame.
        } else if body.is_stream() {
            let stream = body.take_stream().ok_or_else(|| MuxFailure {
                error: ExchangeError::Sent(already_sent()),
                connection_failed: false,
            })?;
            upload = Some(Upload::spawn(pipe_h3(send, stream, body.content_length())));
        } else {
            if let Some(bytes) = body.bytes() {
                send.stream
                    .send_data(bytes.clone())
                    .await
                    .map_err(|e| stream_failed("sending body", e))?;
            }
            send.finish()
                .await
                .map_err(|e| stream_failed("finishing request", e))?;
        }

        Ok(SentRequest {
            lease,
            recv,
            upload,
            request_headers,
            bytes_sent,
        })
    }
}

impl SentRequest {
    /// Read the response head, following any interim (103 Early Hints, 100 Continue) responses,
    /// which come as HEADERS frames of their own before the final one.
    async fn read_response(self, exchange: &Exchange<'_>) -> Result<ResponseParts, MuxFailure> {
        let Self {
            lease,
            mut recv,
            mut upload,
            request_headers,
            bytes_sent,
        } = self;
        let response = loop {
            let response = with_upload(recv.recv_response(), &mut upload)
                .await
                .map_err(|e| match e {
                    UploadOr::Upload(e) => MuxFailure {
                        error: ExchangeError::Sent(e),
                        connection_failed: false,
                    },
                    UploadOr::Response(e) => stream_failed("receiving response", e),
                })?;
            if !response.status().is_informational() {
                break response;
            }
        };
        let status = response.status().as_u16();
        let resp_headers = response_headers(response.headers());
        let head_bytes = estimate_headers_size(&resp_headers);
        let body = if *exchange.method == Method::HEAD {
            BodyStream::Empty
        } else {
            BodyStream::Http3(Box::new(Http3Body {
                stream: recv,
                _upload: upload,
                _conn: lease,
            }))
        };

        Ok(ResponseParts {
            status,
            headers: resp_headers,
            version: "h3",
            request_headers,
            info: exchange.info.clone(),
            connection_reused: exchange.reused,
            bytes_sent,
            head_bytes,
            body,
        })
    }
}

/// The sending half of an HTTP/3 request stream. Dropped before the request is finished, it resets
/// the stream: quinn would finish it, and a cut-off body would look complete.
struct H3Send {
    stream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    finished: bool,
}

impl H3Send {
    async fn finish(&mut self) -> Result<(), StreamError> {
        self.stream.finish().await?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for H3Send {
    fn drop(&mut self) {
        if !self.finished {
            self.stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Send a stream body, reading the next chunk only once QUIC flow control took the previous one.
async fn pipe_h3(mut send: H3Send, mut body: ByteStream, length: Option<u64>) -> Result<(), Error> {
    let mut check = LengthCheck::new(length);
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(stream_error)?;
        if chunk.is_empty() {
            continue;
        }
        check.chunk(chunk.len())?;
        send.stream.send_data(chunk).await.map_err(|e| {
            let message = format!("sending body: {e}");
            Error::Http3(message, crate::error::boxed(e))
        })?;
    }
    check.end()?;
    send.finish().await.map_err(|e| {
        let message = format!("finishing request: {e}");
        Error::Http3(message, crate::error::boxed(e))
    })
}

/// Where a QUIC connection goes.
struct Target<'a> {
    addr: SocketAddr,
    /// Server name of the TLS handshake.
    host: &'a str,
    /// Port of the origin.
    port: u16,
    /// Authority of the Alt-Svc alternative.
    alt_used: String,
    /// ECH config from the host's DNS HTTPS record, if `DoH` made one reachable; `None` GREASEs,
    /// like a browser without one.
    ech_config_list: Option<Vec<u8>>,
}

type H3Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;

/// Set up the HTTP/3 session on a QUIC connection with the profile's fingerprint: open the control
/// and QPACK streams and send SETTINGS. `remembered` are the server's settings from an earlier
/// connection, for a session that starts in 0-RTT.
async fn h3_session(
    setup: &QuicSetup,
    quic: h3_quinn::Connection,
    remembered: Option<h3::fingerprint::PeerSettings>,
) -> Result<(H3Driver, H3Sender), Error> {
    let mut builder = h3::client::builder();
    builder.fingerprint(setup.http3().clone());
    if let Some(settings) = remembered {
        builder.zero_rtt_settings(settings);
    }
    builder.build(quic).await.map_err(|e| {
        let message = format!("H3 handshake failed: {e}");
        Error::Http3(message, crate::error::boxed(e))
    })
}

/// Drive an HTTP/3 session until its connection ends. The driver reads the server's control and
/// QPACK streams, which dynamic-table references in responses need.
fn drive(mut driver: H3Driver) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    })
}

/// Establish a QUIC connection and the HTTP/3 session on it. `broken` marks the alternative broken
/// when a handshake that carries 0-RTT data fails after this returned.
async fn connect_h3(
    setup: Arc<QuicSetup>,
    endpoint: quinn::Endpoint,
    target: Target<'_>,
    broken: impl FnOnce() + Send + 'static,
) -> Result<(H3Conn, ConnInfo), Error> {
    let connecting = endpoint
        .connect_with(
            setup.client_config(target.host, target.port, target.ech_config_list.as_deref())?,
            target.addr,
            target.host,
        )
        .map_err(|e| {
            let message = format!("QUIC connect error: {e}");
            Error::Quic(message, crate::error::boxed(e))
        })?;
    let info = ConnInfo {
        peer_addr: Some(target.addr.ip().to_string()),
        alt_used: Some(target.alt_used.clone()),
        ..ConnInfo::default()
    };

    match connecting.into_0rtt() {
        // A session to resume: SETTINGS and safe requests go out as 0-RTT data right away.
        Ok((connection, accepted)) => {
            // The browsers write their control and QPACK streams before the first flight leaves, so
            // the last Initial goes out with them (Firefox coalesces it with that 0-RTT packet,
            // which also carries its first NEW_CONNECTION_ID).
            let hold = connection.hold_transmit();
            let (quic, zero_rtt) = h3_quinn::Connection::new_0rtt(connection.clone(), accepted);
            let remembered = setup.peer_settings(target.host);
            let (driver, sender) =
                tokio::time::timeout(QUIC_CONNECT_TIMEOUT, h3_session(&setup, quic, remembered))
                    .await
                    .map_err(|_| Error::Quic("QUIC handshake timed out".into(), None))??;
            drop(hold);
            let (state, early) = watch::channel(Early::Pending);
            let conn = H3Conn::new(sender, early, connection.clone(), setup.clone(), &target);
            tokio::spawn(settle_early_data(
                Arc::downgrade(&conn.0),
                connection,
                zero_rtt,
                drive(driver),
                setup,
                state,
                broken,
            ));
            Ok((conn, info))
        }
        Err(connecting) => {
            let connection = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| Error::Quic("QUIC handshake timed out".into(), None))?
                .map_err(|e| {
                    let message = format!("QUIC connection failed: {e}");
                    Error::Quic(message, crate::error::boxed(e))
                })?;
            let quic = h3_quinn::Connection::new(connection.clone());
            let (driver, sender) = h3_session(&setup, quic, None).await?;
            drive(driver);
            server_settings(&sender).await;
            let (_, early) = watch::channel(Early::Done { accepted: false });
            Ok((H3Conn::new(sender, early, connection, setup, &target), info))
        }
    }
}

/// Let server packets that arrived with the handshake be processed before the first request on a
/// new connection: whether the server's SETTINGS come with the handshake (Google) or a round trip
/// later (Cloudflare) decides if that request can use the QPACK dynamic table. Yields to the
/// QUIC/HTTP-3 drivers for at most [`SETTINGS_WAIT`] instead of sleeping (Windows timer ticks are
/// ~15.6 ms).
async fn server_settings(sender: &H3Sender) {
    let deadline = Instant::now() + SETTINGS_WAIT;
    std::future::poll_fn(|cx| match sender.poll_peer_settings(cx) {
        Poll::Ready(_) => Poll::Ready(()),
        Poll::Pending if Instant::now() >= deadline => Poll::Ready(()),
        Poll::Pending => {
            // Come back once the other tasks had their turn.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

/// Follow the handshake of a connection that sent 0-RTT data. When the server rejects the early
/// data, the session's driver ends without closing the QUIC connection, and a new session replaces
/// it.
async fn settle_early_data(
    conn: Weak<H3Shared>,
    connection: quinn::Connection,
    zero_rtt: h3_quinn::ZeroRtt,
    driver: JoinHandle<()>,
    setup: Arc<QuicSetup>,
    state: watch::Sender<Early>,
    broken: impl FnOnce(),
) {
    let fail = |connection: &quinn::Connection| {
        connection.close(quinn::VarInt::from_u32(0), b"");
        broken();
        let _ = state.send(Early::Failed);
    };
    let accepted = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, zero_rtt.accepted()).await;
    // `accepted` is also `false` when the connection is lost.
    let accepted = match (accepted, connection.close_reason()) {
        (Ok(accepted), None) => accepted,
        // Closed or abandoned by the client itself, which is no failure of the alternative.
        (Ok(_), Some(quinn::ConnectionError::LocallyClosed)) => {
            let _ = state.send(Early::Failed);
            return;
        }
        _ => return fail(&connection),
    };
    if !accepted {
        // The old session must end before its last handle goes: a driver that sees that happen
        // first closes the QUIC connection.
        let _ = driver.await;
        let quic = h3_quinn::Connection::new(connection.clone());
        let Ok((driver, sender)) = h3_session(&setup, quic, None).await else {
            return fail(&connection);
        };
        match conn.upgrade() {
            Some(conn) => *crate::util::lock_recover(&conn.sender) = sender,
            // Nobody holds the connection any more.
            None => return,
        }
        drive(driver);
    }
    let _ = state.send(Early::Done { accepted });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_used_names_the_port_unless_443() {
        assert_eq!(alt_used("www.google.com", 443), "www.google.com");
        assert_eq!(alt_used("example.com", 8443), "example.com:8443");
        assert_eq!(alt_used("::1", 4433), "[::1]:4433");
    }

    #[test]
    fn only_safe_requests_go_out_early() {
        let empty = Body::empty();
        assert!(may_send_early(&Method::GET, &empty));
        assert!(may_send_early(&Method::HEAD, &empty));
        assert!(may_send_early(&Method::OPTIONS, &empty));
        // Idempotent but not safe: browsers wait for the handshake.
        assert!(!may_send_early(&Method::PUT, &empty));
        assert!(!may_send_early(&Method::DELETE, &empty));
        assert!(!may_send_early(&Method::POST, &Body::from("x")));
        let stream = Body::stream(futures_util::stream::iter(Vec::<
            Result<Bytes, std::io::Error>,
        >::new()));
        assert!(!may_send_early(&Method::GET, &stream));
    }
}
