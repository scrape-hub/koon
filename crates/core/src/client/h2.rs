use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::AbortHandle;
use tokio_btls::SslStream;

use crate::error::Error;
use crate::http2::config::{
    ConnectionPing, HeaderCompression, HeadersPriority, Http2Config, PseudoHeader, SettingId,
    WindowUpdateRule,
};

use super::body::{
    BodyStream, ExchangeError, Http2Body, MuxFailure, ResponseParts, Upload, UploadOr, with_upload,
};
use super::connection::BoxedIo;
use super::headers::header_value;
use super::request_body::{Body, ByteStream, Length, LengthCheck, already_sent, stream_error};
use super::response::estimate_headers_size;

/// Pseudo-header order when a profile sets none. The h3 crate always writes this order.
pub(super) const DEFAULT_PSEUDO_ORDER: [PseudoHeader; 4] = [
    PseudoHeader::Method,
    PseudoHeader::Scheme,
    PseudoHeader::Authority,
    PseudoHeader::Path,
];

/// The HTTP/2 client configuration of a profile: SETTINGS and their order, pseudo-header order,
/// stream dependency and PRIORITY frames. Built once per client.
pub(super) fn h2_builder(h2_config: &Http2Config) -> http2::client::Builder {
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

    if !h2_config.settings_order.is_empty() {
        let mut order = http2::frame::SettingsOrder::builder();
        for setting_id in &h2_config.settings_order {
            let id = match setting_id {
                SettingId::HeaderTableSize => http2::frame::SettingId::HeaderTableSize,
                SettingId::EnablePush => http2::frame::SettingId::EnablePush,
                SettingId::MaxConcurrentStreams => http2::frame::SettingId::MaxConcurrentStreams,
                SettingId::InitialWindowSize => http2::frame::SettingId::InitialWindowSize,
                SettingId::MaxFrameSize => http2::frame::SettingId::MaxFrameSize,
                SettingId::MaxHeaderListSize => http2::frame::SettingId::MaxHeaderListSize,
                SettingId::EnableConnectProtocol => http2::frame::SettingId::EnableConnectProtocol,
                SettingId::NoRfc7540Priorities => http2::frame::SettingId::NoRfc7540Priorities,
            };
            order = order.push(id);
        }
        h2_builder.settings_order(order.build());
    }

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
            let priority =
                http2::frame::Priority::new(http2::frame::StreamId::from(pf.stream_id), dep);
            prio_builder = prio_builder.push(priority);
        }
        h2_builder.priorities(prio_builder.build());
    }

    // Disable RFC 7540 priorities (Chrome 131+, Safari 18.3)
    if let Some(val) = h2_config.no_rfc7540_priorities {
        h2_builder.no_rfc7540_priorities(val);
    }

    // CONNECT protocol (Safari 18.3)
    if let Some(val) = h2_config.enable_connect_protocol {
        h2_builder.enable_connect_protocol(val);
    }

    // Client stream IDs are odd.
    if let Some(id) = h2_config.initial_stream_id.filter(|id| id % 2 == 1) {
        h2_builder.initial_stream_id(id);
    }
    if h2_config.headers_priority == Some(HeadersPriority::Chromium) {
        h2_builder.stream_dependency_chain(true);
    }
    if let Some(size) = h2_config.initial_stream_window_size {
        h2_builder.initial_stream_window_size(size.min(MAX_WINDOW_SIZE));
    }
    if let Some(rule) = h2_config.stream_window_update {
        h2_builder.stream_window_update(window_update_policy(rule));
    }
    if let Some(rule) = h2_config.connection_window_update {
        h2_builder.connection_window_update(window_update_policy(rule));
    }
    if let Some(compression) = h2_config.header_compression {
        h2_builder.header_compression(match compression {
            HeaderCompression::Firefox => http2::client::HeaderCompression::Firefox,
            HeaderCompression::Chromium => http2::client::HeaderCompression::Chromium,
            HeaderCompression::Safari => http2::client::HeaderCompression::Safari,
        });
    }
    h2_builder.write_frames_individually(h2_config.write_frames_individually);
    h2_builder.write_preface_alone(h2_config.write_preface_alone);
    h2_builder.write_data_with_headers(h2_config.write_data_with_headers);
    if let Some(size) = h2_config.max_header_frame_size {
        h2_builder.max_header_frame_size(size);
    }
    h2_builder.go_away_on_close(h2_config.goaway_on_close);

    // No h2_builder.headers_order(): it is per connection and would force the navigation order onto
    // fetch requests. Each request's HeaderMap is built in wire order by the header builder
    // instead.
    h2_builder
}

/// Largest flow-control window (RFC 9113 §6.9.1).
const MAX_WINDOW_SIZE: u32 = (1 << 31) - 1;

fn window_update_policy(rule: WindowUpdateRule) -> http2::client::WindowUpdatePolicy {
    let mut policy = http2::client::WindowUpdatePolicy::threshold(rule.threshold);
    if let Some(low) = rule.low_window {
        policy = policy.low_window(low);
    }
    if let Some(ms) = rule.interval_ms {
        policy = policy.interval(Duration::from_millis(ms));
    }
    policy
}

/// Whether an HTTP/2 error ends the connection rather than one stream.
fn h2_connection_failed(e: &http2::Error) -> bool {
    e.is_io() || e.is_go_away()
}

/// The priority block of a request's HEADERS frame (see [`HeadersPriority`]), `None` for none.
/// `headers` are the request's regular headers.
// `weight` is always 1-256 here, so `weight - 1` always fits a `u8`.
#[allow(clippy::cast_possible_truncation)]
fn request_priority(
    scheme: HeadersPriority,
    headers: &[(String, String)],
) -> Option<http2::frame::StreamDependency> {
    // Safari's weights per destination, as captured: (document, style and script, image).
    let safari = |(document, style, image): (u16, u16, u16)| {
        let weight = match header_value(headers, "sec-fetch-dest")? {
            "document" => document,
            "style" | "script" => style,
            "image" => image,
            _ => return None,
        };
        Some((weight, false))
    };
    // The wire weight is 1-256, the frame field one less.
    let (weight, exclusive): (u16, bool) = match scheme {
        HeadersPriority::SafariSonoma => safari((255, 24, 8))?,
        HeadersPriority::SafariSequoia => safari((256, 64, 4))?,
        HeadersPriority::Firefox => {
            // Http2StreamBase::SetPriority: 22 minus nsISupportsPriority.
            let weight = match header_value(headers, "sec-fetch-dest") {
                // A top-level document: urgent start, PRIORITY_HIGHEST.
                Some("document") => 42,
                // imgLoader: PRIORITY_LOW.
                Some("image") => 12,
                // @font-face loads: PRIORITY_HIGH.
                Some("font") => 32,
                // Necko's default, PRIORITY_NORMAL.
                _ => 22,
            };
            (weight, false)
        }
        HeadersPriority::Chromium => {
            let urgency = header_value(headers, "priority")
                .and_then(priority_urgency)
                .unwrap_or(DEFAULT_URGENCY);
            (chromium_weight(urgency), true)
        }
    };
    Some(http2::frame::StreamDependency::new(
        http2::frame::StreamId::zero(),
        (weight - 1) as u8,
        exclusive,
    ))
}

/// Urgency of a request without a `priority` header or without `u` (RFC 9218 §4.1).
const DEFAULT_URGENCY: u8 = 3;

/// The urgency (`u`) of a `priority` header value, if it has a valid one.
fn priority_urgency(value: &str) -> Option<u8> {
    value.split(',').find_map(|member| {
        let (key, value) = member.trim().split_once('=')?;
        (key.trim() == "u")
            .then(|| value.trim().parse::<u8>().ok())
            .flatten()
            .filter(|u| *u <= 7)
    })
}

/// Chromium's HTTP/2 weight of a request priority: the urgency Chromium sends is its SPDY priority
/// (`ConvertRequestPriorityToQuicPriority`), and `Spdy3PriorityToHttp2Weight` spreads SPDY
/// priorities 0-7 over 256-1.
// Matches Chromium's own float-to-int cast; the result is always in 1-256.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn chromium_weight(urgency: u8) -> u16 {
    const STEPS: f32 = 255.9 / 7.0;
    (STEPS * (7.0 - f32::from(urgency.min(7)))) as u16 + 1
}

/// An accepted extended CONNECT: the response head and the stream's halves.
pub(super) type WebSocketStream = (
    http::response::Parts,
    http2::SendStream<Bytes>,
    http2::RecvStream,
);

/// A multiplexed HTTP/2 connection as the pool keeps it: the handle requests go out on, and what
/// its PING rules need.
#[derive(Clone)]
pub(crate) struct H2Conn {
    sender: http2::client::SendRequest<Bytes>,
    shared: Arc<H2Shared>,
}

/// State of a connection that its requests and its driver task share.
struct H2Shared {
    /// When the connection was set up; the times below count from it.
    start: Instant,
    /// Microseconds to the last read from the connection.
    last_read_us: AtomicU64,
    /// Microseconds to the PING sent last, `NO_PING` before the first.
    ping_sent_us: AtomicU64,
    /// Payload of the next PING of a [`ConnectionPing::BeforeRequest`] connection: Chromium counts
    /// from 1 (`next_ping_id_`).
    next_ping_id: AtomicU64,
    /// The connection's PING rule.
    ping: Option<ConnectionPing>,
    /// The task that drives the connection: aborted when a PING goes unanswered.
    driver: OnceLock<AbortHandle>,
}

const NO_PING: u64 = u64::MAX;

impl H2Shared {
    // A connection's age in microseconds never approaches u64::MAX (over 584,000 years).
    #[allow(clippy::cast_possible_truncation)]
    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn touch(&self) {
        self.last_read_us.store(self.now_us(), Ordering::Relaxed);
    }

    /// Time since the last read.
    fn idle(&self) -> Duration {
        let last = self.last_read_us.load(Ordering::Relaxed);
        Duration::from_micros(self.now_us().saturating_sub(last))
    }

    /// Whether something was read after the PING sent at `sent_us`.
    fn read_since(&self, sent_us: u64) -> bool {
        self.last_read_us.load(Ordering::Relaxed) > sent_us
    }

    /// `SpdySession::MaybeSendPrefacePing`: the payload of a PING to send right after the HEADERS
    /// of a request going out now, when nothing was read for longer than `idle` and no PING is
    /// waiting for its answer.
    // `idle`'s microseconds never approach u64::MAX either.
    #[allow(clippy::cast_possible_truncation)]
    fn preface_ping(&self, idle: Duration) -> Option<(u64, [u8; 8])> {
        let sent = self.ping_sent_us.load(Ordering::Relaxed);
        if sent != NO_PING && !self.read_since(sent) {
            return None;
        }
        let now = self.now_us();
        let last_read = self.last_read_us.load(Ordering::Relaxed);
        if now <= last_read + idle.as_micros() as u64 {
            return None;
        }
        // Concurrent requests: one of them sends the PING.
        self.ping_sent_us
            .compare_exchange(sent, now, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;
        let id = self.next_ping_id.fetch_add(1, Ordering::Relaxed);
        Some((now, id.to_be_bytes()))
    }

    /// Close the connection: stop its driver, which drops the transport.
    fn abort(&self) {
        if let Some(driver) = self.driver.get() {
            driver.abort();
        }
    }
}

/// Firefox's idle PING (`Http2Session::ReadTimeoutTick`): after `idle` without reads a PING with
/// eight zero bytes, and the connection closes when it is not answered within `timeout`. Runs as
/// long as the connection.
async fn idle_pings(
    shared: Arc<H2Shared>,
    mut ping_pong: http2::PingPong,
    idle: Duration,
    timeout: Duration,
) {
    loop {
        let since = shared.idle();
        if since < idle {
            tokio::time::sleep(idle - since).await;
            continue;
        }
        let ping = ping_pong.ping(http2::Ping::with_payload([0; 8]));
        match tokio::time::timeout(timeout, ping).await {
            Ok(Ok(_)) => {}
            // Unanswered, or the connection is gone.
            _ => return,
        }
    }
}

/// The TLS stream of an HTTP/2 connection. Notes when data arrives, for the PING rules, and closes
/// with or without a TLS `close_notify`.
struct H2Io {
    tls: SslStream<BoxedIo>,
    shared: Arc<H2Shared>,
    close_notify: bool,
}

impl AsyncRead for H2Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.tls).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.shared.touch();
        }
        polled
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().tls).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_flush(cx)
    }

    /// Without `close_notify`, the TCP connection (or tunnel) under TLS is shut down directly: a
    /// plain FIN, as Chromium closes.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.close_notify {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        } else {
            Pin::new(this.tls.get_mut()).poll_shutdown(cx)
        }
    }
}

impl super::Client {
    /// Perform the HTTP/2 handshake with the profile's settings and spawn the connection driver
    /// task. Returns a handle that can be cloned and reused for multiple requests.
    pub(super) async fn h2_handshake(&self, tls: SslStream<BoxedIo>) -> Result<H2Conn, Error> {
        let config = &self.profile.http2;
        let shared = Arc::new(H2Shared {
            start: Instant::now(),
            last_read_us: AtomicU64::new(0),
            ping_sent_us: AtomicU64::new(NO_PING),
            next_ping_id: AtomicU64::new(1),
            ping: config.ping,
            driver: OnceLock::new(),
        });
        let io = H2Io {
            tls,
            shared: shared.clone(),
            close_notify: config.close_notify,
        };
        let (client, mut h2_conn) = self
            .h2_builder
            .handshake::<_, Bytes>(io)
            .await
            .map_err(Error::Http2)?;

        let idle = match config.ping {
            Some(ConnectionPing::Idle {
                idle_ms,
                timeout_ms,
            }) => h2_conn.ping_pong().map(|ping_pong| {
                idle_pings(
                    shared.clone(),
                    ping_pong,
                    Duration::from_millis(idle_ms),
                    Duration::from_millis(timeout_ms),
                )
            }),
            _ => None,
        };

        // Drive the connection. Errors surface on the streams that use it; the pool drops the
        // connection once it stops accepting requests.
        let driver = tokio::spawn(async move {
            match idle {
                Some(idle) => {
                    tokio::select! {
                        _ = h2_conn => {}
                        // An unanswered PING ends the connection.
                        _ = idle => {}
                    }
                }
                None => {
                    let _ = h2_conn.await;
                }
            }
        });
        let _ = shared.driver.set(driver.abort_handle());

        Ok(H2Conn {
            sender: client,
            shared,
        })
    }

    /// Send one request on a multiplexed HTTP/2 connection and read the response head.
    pub(super) async fn send_h2(
        &self,
        conn: H2Conn,
        ctx: super::h3::SendContext<'_>,
        body: &Body,
    ) -> Result<ResponseParts, MuxFailure> {
        let super::h3::SendContext {
            info,
            reused,
            method,
            uri,
            headers,
        } = ctx;
        let failed = |e: http2::Error, sent: bool| {
            let connection_failed = h2_connection_failed(&e);
            let e = Error::Http2(e);
            MuxFailure {
                error: if sent {
                    ExchangeError::Sent(e)
                } else {
                    ExchangeError::NotSent(e)
                },
                connection_failed,
            }
        };
        let request_failed = |e: Error| MuxFailure {
            error: ExchangeError::Invalid(e),
            connection_failed: false,
        };

        // A dead connection fails here, before anything was sent.
        let H2Conn { sender, shared } = conn;
        let mut sender = sender.ready().await.map_err(|e| MuxFailure {
            error: ExchangeError::NotSent(Error::Http2(e)),
            connection_failed: true,
        })?;

        let mut request = Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| {
                let message = e.to_string();
                request_failed(Error::InvalidHeader(message, crate::error::boxed(e)))
            })?;
        *request.headers_mut() = header_map(&headers).map_err(request_failed)?;
        self.stream_extensions(&shared, &mut request, &headers);

        let request_headers = with_pseudo_headers(
            &self.profile.http2.pseudo_header_order,
            method,
            uri,
            headers,
        );
        let bytes_sent =
            estimate_headers_size(&request_headers) + body.content_length().unwrap_or(0);

        let no_body = body.length() == Length::None;
        let (response, mut send_stream) = sender
            .send_request(request, no_body)
            .map_err(|e| failed(e, false))?;
        let mut upload = None;
        if let Some(bytes) = body.bytes() {
            send_stream
                .send_data(bytes.clone(), true)
                .map_err(|e| failed(e, true))?;
        } else if !no_body {
            let stream = body.take_stream().ok_or_else(|| MuxFailure {
                error: ExchangeError::Sent(already_sent()),
                connection_failed: false,
            })?;
            let length = body.content_length();
            upload = Some(Upload::spawn(pipe_h2(send_stream, stream, length)));
        }

        let response = with_upload(response, &mut upload)
            .await
            .map_err(|e| match e {
                UploadOr::Upload(e) => MuxFailure {
                    error: ExchangeError::Sent(e),
                    connection_failed: false,
                },
                UploadOr::Response(e) => {
                    let connection_failed = h2_connection_failed(&e);
                    MuxFailure {
                        error: classify_h2_error(e),
                        connection_failed,
                    }
                }
            })?;
        let status = response.status().as_u16();
        let resp_headers = response_headers(response.headers());
        let head_bytes = estimate_headers_size(&resp_headers);
        let body = if *method == Method::HEAD {
            BodyStream::Empty
        } else {
            BodyStream::Http2(Box::new(Http2Body {
                recv: response.into_body(),
                _upload: upload,
            }))
        };

        Ok(ResponseParts {
            status,
            headers: resp_headers,
            version: "h2",
            request_headers,
            info,
            connection_reused: reused,
            bytes_sent,
            head_bytes,
            body,
        })
    }

    /// What a new stream's HEADERS carry besides the header fields: the profile's priority block,
    /// and Chromium's PING after a while without reads (the connection ends when nothing arrives
    /// within its timeout).
    fn stream_extensions(
        &self,
        shared: &Arc<H2Shared>,
        request: &mut Request<()>,
        headers: &[(String, String)],
    ) {
        if let Some(dependency) = self
            .profile
            .http2
            .headers_priority
            .and_then(|scheme| request_priority(scheme, headers))
        {
            request.extensions_mut().insert(dependency);
        }
        if let Some(ConnectionPing::BeforeRequest {
            idle_ms,
            timeout_ms,
        }) = shared.ping
        {
            if let Some((sent, payload)) = shared.preface_ping(Duration::from_millis(idle_ms)) {
                request
                    .extensions_mut()
                    .insert(http2::frame::Ping::new(payload));
                let shared = shared.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
                    if !shared.read_since(sent) {
                        shared.abort();
                    }
                });
            }
        }
    }

    /// Open a WebSocket stream on `conn` with an extended CONNECT (RFC 8441 §4): `:method CONNECT`
    /// and `:protocol websocket`, the profile's other pseudo-headers with `:protocol` last, then
    /// `headers`; `uri` is the socket's `https` URL. Returns the response head and stream halves.
    pub(super) async fn open_h2_websocket(
        &self,
        conn: H2Conn,
        uri: &Uri,
        headers: &[(String, String)],
    ) -> Result<WebSocketStream, MuxFailure> {
        let H2Conn { sender, shared } = conn;
        let mut sender = sender.ready().await.map_err(|e| MuxFailure {
            error: ExchangeError::NotSent(Error::Http2(e)),
            connection_failed: true,
        })?;
        let invalid = |e: Error| MuxFailure {
            error: ExchangeError::Invalid(e),
            connection_failed: false,
        };
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri.clone())
            .version(Version::HTTP_2)
            .extension(http2::ext::Protocol::from_static("websocket"))
            .body(())
            .map_err(|e| {
                let message = e.to_string();
                invalid(Error::InvalidHeader(message, crate::error::boxed(e)))
            })?;
        *request.headers_mut() = header_map(headers).map_err(invalid)?;
        self.stream_extensions(&shared, &mut request, headers);

        let (response, send) = sender.send_request(request, false).map_err(|e| {
            let connection_failed = h2_connection_failed(&e);
            MuxFailure {
                error: ExchangeError::NotSent(Error::Http2(e)),
                connection_failed,
            }
        })?;
        let response = response.await.map_err(|e| {
            let connection_failed = h2_connection_failed(&e);
            MuxFailure {
                error: classify_h2_error(e),
                connection_failed,
            }
        })?;
        let (parts, recv) = response.into_parts();
        Ok((parts, send, recv))
    }
}

impl H2Conn {
    /// Whether the server's SETTINGS so far enable the extended CONNECT of RFC 8441
    /// (`SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`); `false` until its first SETTINGS frame arrived.
    pub(crate) fn extended_connect(&self) -> bool {
        self.sender.is_extended_connect_protocol_enabled()
    }

    /// Wait for the server's first SETTINGS frame.
    pub(crate) async fn remote_settings(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.sender.poll_remote_settings(cx))
            .await
            .map_err(Error::Http2)
    }
}

/// Send a stream body as the peer's flow control allows, reading the next chunk only once the
/// previous one is on its way. A failing body stream resets the request stream.
async fn pipe_h2(
    mut send: http2::SendStream<Bytes>,
    mut body: ByteStream,
    length: Option<u64>,
) -> Result<(), Error> {
    let result = async {
        let mut check = LengthCheck::new(length);
        while let Some(chunk) = body.next().await {
            let mut chunk = chunk.map_err(stream_error)?;
            check.chunk(chunk.len())?;
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                let mut granted = send.capacity();
                while granted == 0 {
                    granted = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                        Some(Ok(n)) => n,
                        Some(Err(e)) => return Err(Error::Http2(e)),
                        None => return Err(stream_closed()),
                    };
                }
                let part = chunk.split_to(granted.min(chunk.len()));
                send.send_data(part, false).map_err(Error::Http2)?;
            }
        }
        check.end()?;
        send.send_data(Bytes::new(), true).map_err(Error::Http2)
    }
    .await;
    if matches!(result, Err(Error::Body(..))) {
        send.send_reset(http2::Reason::CANCEL);
    }
    result
}

fn stream_closed() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "stream closed while sending the request body",
    ))
}

/// A stream the server refused, or one above the GOAWAY's last stream ID, was not processed (RFC
/// 9113 §8.7): safe to replay.
fn classify_h2_error(e: http2::Error) -> ExchangeError {
    let unprocessed =
        e.reason() == Some(http2::Reason::REFUSED_STREAM) || (e.is_go_away() && e.is_remote());
    if unprocessed {
        ExchangeError::NotSent(Error::Http2(e))
    } else {
        ExchangeError::Sent(Error::Http2(e))
    }
}

/// Build a `HeaderMap` in the given order. Invalid names or values are an error rather than
/// silently dropped; values may contain UTF-8, which goes out as its bytes (see
/// [`validate_headers`](super::execute::validate_headers)).
pub(super) fn header_map(headers: &[(String, String)]) -> Result<HeaderMap, Error> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
            let message = format!("invalid header name: {name:?}");
            Error::InvalidHeader(message, crate::error::boxed(e))
        })?;
        let value = HeaderValue::from_bytes(value.as_bytes()).map_err(|e| {
            let message = format!("invalid value for header {name}");
            Error::InvalidHeader(message, crate::error::boxed(e))
        })?;
        map.append(name, value);
    }
    Ok(map)
}

/// Response headers as pairs. Values that are not valid UTF-8 (raw Latin-1 in a Location or
/// Set-Cookie) are decoded lossily instead of dropped.
pub(super) fn response_headers(map: &HeaderMap) -> Vec<(String, String)> {
    map.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Prepend the pseudo-headers in the order they go on the wire; [`DEFAULT_PSEUDO_ORDER`] if `order`
/// is empty.
pub(super) fn with_pseudo_headers(
    order: &[PseudoHeader],
    method: &Method,
    uri: &Uri,
    headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let order = if order.is_empty() {
        &DEFAULT_PSEUDO_ORDER[..]
    } else {
        order
    };
    let mut out = Vec::with_capacity(headers.len() + 4);
    for pseudo in order {
        let entry = match pseudo {
            PseudoHeader::Method => (":method", method.as_str().to_string()),
            PseudoHeader::Scheme => (":scheme", uri.scheme_str().unwrap_or("https").to_string()),
            PseudoHeader::Authority => (":authority", super::headers::host_header(uri)),
            PseudoHeader::Path => (
                ":path",
                uri.path_and_query()
                    .map_or("/", |pq| pq.as_str())
                    .to_string(),
            ),
            PseudoHeader::Status | PseudoHeader::Protocol => continue,
        };
        out.push((entry.0.to_string(), entry.1));
    }
    out.extend(headers);
    out
}
