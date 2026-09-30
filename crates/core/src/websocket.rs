//! WebSocket connections (RFC 6455), over HTTP/1.1 or, as browsers do, over an HTTP/2 stream (RFC
//! 8441 extended CONNECT) where the profile's browser would use one: see `OverH2` for which, and
//! `ClosingBehavior` for how it ends that stream. None of them runs WebSockets over HTTP/3 (RFC
//! 9220) by default.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use http::{Method, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tungstenite::protocol::Role;

use crate::client::headers::header_value;
use crate::client::{BoxedIo, PrefixedStream};
use crate::error::Error;
use crate::http1;
use crate::profile::{BrowserProfile, HeaderFamily, SafariLayout, SafariStack};

/// A WebSocket message (text or binary).
#[derive(Debug, Clone)]
pub enum Message {
    /// UTF-8 text message.
    Text(String),
    /// Binary message.
    Binary(Vec<u8>),
}

type WsStream = tokio_tungstenite::WebSocketStream<BoxedIo>;

/// A WebSocket connection with browser-fingerprinted TLS. The TLS handshake uses the same BoringSSL
/// fingerprint as HTTP requests, and the opening handshake follows the browser's: an HTTP/1.1
/// upgrade, or an extended CONNECT on an HTTP/2 connection where the browser would use one (see
/// [the module documentation](self)). Reading and writing are independent: a pending
/// [`receive`](WebSocket::receive) does not block [`send_text`](WebSocket::send_text) or
/// [`close`](WebSocket::close). Once [`receive`](WebSocket::receive) sees the server's Close frame
/// (the reply to [`close`](WebSocket::close), or its own) or the end of the connection, the
/// connection is closed, as browsers close it, rather than left half-open until the `WebSocket` is
/// dropped. Over HTTP/2 its stream ends as the browser ends it; the HTTP/2 connection stays open.
pub struct WebSocket {
    /// `None` once the connection is closed.
    sink: Mutex<Option<SplitSink<WsStream, tungstenite::Message>>>,
    stream: Mutex<Option<SplitStream<WsStream>>>,
}

impl WebSocket {
    fn new(ws: WsStream) -> Self {
        let (sink, stream) = ws.split();
        Self {
            sink: Mutex::new(Some(sink)),
            stream: Mutex::new(Some(stream)),
        }
    }

    /// Send a text message. Errors if the connection is closed or the send fails.
    pub async fn send_text(&self, text: &str) -> Result<(), Error> {
        self.send(tungstenite::Message::Text(text.into())).await
    }

    /// Send a binary message. Errors if the connection is closed or the send fails.
    pub async fn send_binary(&self, data: &[u8]) -> Result<(), Error> {
        self.send(tungstenite::Message::Binary(data.into())).await
    }

    async fn send(&self, message: tungstenite::Message) -> Result<(), Error> {
        let mut sink = self.sink.lock().await;
        let sink = sink.as_mut().ok_or(tungstenite::Error::AlreadyClosed)?;
        sink.send(message).await?;
        Ok(())
    }

    /// Receive the next message. Returns `None` if the connection is closed; pings are answered
    /// automatically. Errors on a protocol violation or a transport failure.
    pub async fn receive(&self) -> Result<Option<Message>, Error> {
        let mut guard = self.stream.lock().await;
        let Some(stream) = guard.as_mut() else {
            return Ok(None);
        };
        loop {
            match stream.next().await {
                Some(Ok(tungstenite::Message::Text(t))) => return Ok(Some(Message::Text(t))),
                Some(Ok(tungstenite::Message::Binary(b))) => return Ok(Some(Message::Binary(b))),
                Some(Ok(tungstenite::Message::Close(_))) | None => {
                    // Send what is still queued (the reply to a Close frame of the server), then
                    // drop both halves, which closes the connection.
                    *guard = None;
                    if let Some(mut sink) = self.sink.lock().await.take() {
                        let _ = sink.close().await;
                    }
                    return Ok(None);
                }
                Some(Ok(_)) => continue, // ping, pong, raw frame
                Some(Err(e)) => return Err(e.into()),
            }
        }
    }

    /// Close the WebSocket connection with an optional close code and reason. Ends once
    /// [`receive`](Self::receive) got the server's reply; does nothing if already closed. Errors if
    /// sending the Close frame fails.
    pub async fn close(&self, code: Option<u16>, reason: Option<String>) -> Result<(), Error> {
        let close_frame = code.map(|c| tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::from(c),
            reason: reason.unwrap_or_default().into(),
        });
        let mut sink = self.sink.lock().await;
        let Some(sink) = sink.as_mut() else {
            return Ok(());
        };
        sink.send(tungstenite::Message::Close(close_frame)).await?;
        Ok(())
    }
}

/// How a profile's browser carries WebSockets over HTTP/2 (see [the module documentation](self)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverH2 {
    /// Never: each socket gets an HTTP/1.1 connection (Safari up to macOS 15 and iOS 18, OkHttp,
    /// other clients).
    Never,
    /// Chromium, Safari from macOS 26 and iOS 26 on: on an HTTP/2 connection the client already has
    /// to the origin, if its server enabled extended CONNECT.
    ExistingConnection,
    /// Firefox: on HTTP/2 connections of the client's WebSockets, which a new connection offering
    /// `h2` may become.
    OwnConnections,
}

/// How a browser ends the HTTP/2 stream of a WebSocket, once the closing handshake completes or the
/// server ends the stream. RFC 8441 §5 maps a TCP FIN to END_STREAM and a TCP reset to RST_STREAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosingBehavior {
    /// Forget the stream without a frame once the server ends it, leaving its half open (Chromium
    /// up to 153, Firefox, Safari before macOS/iOS 26, OkHttp).
    Wait,
    /// Answer the server's END_STREAM with an empty DATA frame
    /// (`WebSocketSpdyStreamAdapter::MaybeSendEndStream`; Chromium 154).
    AnswerEndStream,
    /// End the client's half with the Close frame itself, the orderly close of RFC 8441 §5
    /// (`WebSocketSpdyStreamAdapter::Write` with `is_final_write`, commit 6f0b004b43; Chromium from
    /// 155 on). The server's END_STREAM then gets no frame of its own, the Close reply carries it,
    /// and a stream dropped before both ends are closed is reset.
    EndStreamWithClose,
    /// Reset with RST_STREAM(NO_ERROR) as soon as the closing handshake is complete or the server
    /// ended the stream, instead of waiting or answering; the Close frame that answers the server's
    /// also goes out as three DATA frames (frame header, masking key, payload) rather than one
    /// (Safari from macOS/iOS 26 on).
    ResetAfterClose,
}

/// How a browser ends the HTTP/2 stream of a WebSocket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H2Close {
    /// How long the server gets, once the closing handshake is complete, to end the stream before
    /// the client resets it with RST_STREAM(CANCEL): Chromium's
    /// `kUnderlyingConnectionCloseTimeoutSeconds` (2 s), Firefox's `kLingeringCloseTimeout` (1 s).
    /// Unused by [`ClosingBehavior::ResetAfterClose`].
    pub linger: Duration,
    pub behavior: ClosingBehavior,
}

/// The WebSocket behaviour of a profile's browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    pub over_h2: OverH2,
    pub close: H2Close,
}

/// First Chromium version that answers the server's END_STREAM on a WebSocket stream with its own.
const CHROMIUM_END_STREAM_REPLY_VERSION: u32 = 154;

/// First Chromium version that ends its half of a WebSocket stream with the Close frame.
const CHROMIUM_END_STREAM_WITH_CLOSE_VERSION: u32 = 155;

/// The WebSocket policy of `profile`'s browser. Chromium profiles take their version from the
/// `Chrome/` token of their User-Agent (Edge and Opera carry their Chromium version there); without
/// one, the newest behaviour.
pub(crate) fn policy(profile: &BrowserProfile) -> Policy {
    match HeaderFamily::of(profile) {
        HeaderFamily::Chromium => {
            let chromium = header_value(&profile.headers, "user-agent")
                .and_then(|ua| ua.split("Chrome/").nth(1))
                .and_then(|v| v.split('.').next())
                .and_then(|v| v.parse::<u32>().ok());
            let since = |version: u32| chromium.is_none_or(|major| major >= version);
            let behavior = if since(CHROMIUM_END_STREAM_WITH_CLOSE_VERSION) {
                ClosingBehavior::EndStreamWithClose
            } else if since(CHROMIUM_END_STREAM_REPLY_VERSION) {
                ClosingBehavior::AnswerEndStream
            } else {
                ClosingBehavior::Wait
            };
            Policy {
                over_h2: OverH2::ExistingConnection,
                close: H2Close {
                    linger: Duration::from_secs(2),
                    behavior,
                },
            }
        }
        HeaderFamily::Firefox => Policy {
            over_h2: OverH2::OwnConnections,
            close: H2Close {
                linger: Duration::from_secs(1),
                behavior: ClosingBehavior::Wait,
            },
        },
        HeaderFamily::Safari if SafariLayout::of(profile).stack == SafariStack::Tahoe => Policy {
            over_h2: OverH2::ExistingConnection,
            close: H2Close {
                linger: Duration::ZERO,
                behavior: ClosingBehavior::ResetAfterClose,
            },
        },
        _ => Policy {
            over_h2: OverH2::Never,
            close: H2Close {
                linger: Duration::from_secs(2),
                behavior: ClosingBehavior::Wait,
            },
        },
    }
}

fn handshake_failed(reason: String) -> Error {
    Error::ConnectionFailed(format!("WebSocket handshake failed: {reason}"), None)
}

/// Fail if the response selects an extension or subprotocol the request did not offer. `value`
/// looks up a response header by lowercase name.
fn check_selected<'a>(
    offered: &[(String, String)],
    value: impl Fn(&str) -> Option<&'a str>,
) -> Result<(), Error> {
    let was_offered = |name: &str| offered.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    for (name, what) in [
        ("sec-websocket-extensions", "Sec-WebSocket-Extensions"),
        ("sec-websocket-protocol", "Sec-WebSocket-Protocol"),
    ] {
        if value(name).is_some_and(|v| !v.trim().is_empty()) && !was_offered(name) {
            return Err(handshake_failed(format!(
                "server selected a {what} that was not offered"
            )));
        }
    }
    Ok(())
}

/// Perform the WebSocket upgrade handshake (RFC 6455 §4.1) on `conn`. Sends `headers` verbatim,
/// then checks the 101 response: `Upgrade: websocket`, `Connection: Upgrade`, the
/// `Sec-WebSocket-Accept` for `key`, and no extension or subprotocol the client did not offer.
/// Returns the socket and the response headers (for Set-Cookie).
pub(crate) async fn connect(
    mut conn: BoxedIo,
    uri: &Uri,
    headers: Vec<(String, String)>,
    key: &str,
) -> Result<(WebSocket, Vec<(String, String)>), Error> {
    let target = uri.path_and_query().map_or("/", |pq| pq.as_str());
    http1::write_request(&mut conn, &Method::GET, target, &headers, None).await?;
    let response = http1::read_response_headers(&mut conn).await?;

    if response.status != 101 {
        return Err(handshake_failed(format!(
            "server returned {}",
            response.status
        )));
    }
    let value = |name: &str| {
        response
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if !value("upgrade").is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket")) {
        return Err(handshake_failed("missing Upgrade: websocket".into()));
    }
    if !value("connection").is_some_and(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    }) {
        return Err(handshake_failed("missing Connection: Upgrade".into()));
    }
    let expected = tungstenite::handshake::derive_accept_key(key.as_bytes());
    match value("sec-websocket-accept") {
        Some(accept) if accept.trim() == expected => {}
        Some(accept) => {
            return Err(handshake_failed(format!(
                "invalid Sec-WebSocket-Accept {accept}"
            )));
        }
        None => return Err(handshake_failed("missing Sec-WebSocket-Accept".into())),
    }
    check_selected(&headers, value)?;

    let prefixed: BoxedIo = Box::new(PrefixedStream::new(response.leftover, conn));
    let ws = WsStream::from_raw_socket(prefixed, Role::Client, None).await;
    Ok((WebSocket::new(ws), response.headers))
}

/// Complete the WebSocket handshake of an extended CONNECT (RFC 8441 §5): the response to `offered`
/// must be a 200 that selects no extension or subprotocol the client did not offer (there is no
/// `Sec-WebSocket-Accept` over HTTP/2). Returns the socket and the response headers (for
/// Set-Cookie).
pub(crate) async fn connect_h2(
    response: http::response::Parts,
    send: http2::SendStream<Bytes>,
    recv: http2::RecvStream,
    offered: &[(String, String)],
    close: H2Close,
) -> Result<(WebSocket, Vec<(String, String)>), Error> {
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    // Dropped on failure, which resets the stream.
    let stream = H2Stream {
        send: Some(send),
        recv: Some(recv),
        unread: Bytes::new(),
        ended: false,
        end_sent: false,
        close,
        sent: FrameScan::default(),
        received: FrameScan::default(),
    };
    if response.status != http::StatusCode::OK {
        return Err(handshake_failed(format!(
            "server returned {}",
            response.status.as_u16()
        )));
    }
    check_selected(offered, |name| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    })?;
    let ws = WsStream::from_raw_socket(Box::new(stream), Role::Client, None).await;
    Ok((WebSocket::new(ws), headers))
}

/// Follows a WebSocket frame stream (RFC 6455 §5.2) to note Close frames.
#[derive(Clone, Default)]
struct FrameScan {
    header: [u8; 14],
    header_len: usize,
    /// Payload bytes of the current frame still to come.
    payload_left: u64,
    saw_close: bool,
}

impl FrameScan {
    fn scan(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.payload_left > 0 {
                let n = usize::try_from(self.payload_left)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                self.payload_left -= n as u64;
                bytes = &bytes[n..];
                continue;
            }
            self.header[self.header_len] = bytes[0];
            self.header_len += 1;
            bytes = &bytes[1..];
            if self.header_len < 2 {
                continue;
            }
            let h = &self.header;
            let extended = match h[1] & 0x7f {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let mask = if h[1] & 0x80 != 0 { 4 } else { 0 };
            if self.header_len < 2 + extended + mask {
                continue;
            }
            self.payload_left = match extended {
                0 => u64::from(h[1] & 0x7f),
                2 => u64::from(u16::from_be_bytes([h[2], h[3]])),
                _ => u64::from_be_bytes([h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9]]),
            };
            if h[0] & 0x0f == 0x8 {
                self.saw_close = true;
            }
            self.header_len = 0;
        }
    }

    /// Whether a Close frame has been seen whole: the stream is at a frame boundary after it.
    fn close_complete(&self) -> bool {
        self.saw_close && self.header_len == 0 && self.payload_left == 0
    }
}

/// The HTTP/2 stream of a WebSocket as the byte stream of its frames, with the browser's end of the
/// stream: see [`H2Close`].
struct H2Stream {
    /// `None` once dropped.
    send: Option<http2::SendStream<Bytes>>,
    recv: Option<http2::RecvStream>,
    /// Received bytes not read yet.
    unread: Bytes,
    /// The server ended the stream, and the client's half has been dealt with (with
    /// [`ClosingBehavior::EndStreamWithClose`]: is left to the Close frame).
    ended: bool,
    /// The client's END_STREAM went out with its Close frame.
    end_sent: bool,
    close: H2Close,
    /// The frames sent and received, for the closing handshake.
    sent: FrameScan,
    received: FrameScan,
}

impl H2Stream {
    /// The server ended the stream: end or forget the client's half. Safari still answers a Close
    /// frame, then resets the stream; Chromium 155 answers it with a Close frame that ends its
    /// half.
    fn on_end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        if self.close.behavior == ClosingBehavior::EndStreamWithClose {
            return;
        }
        if self.close.behavior == ClosingBehavior::ResetAfterClose {
            self.reset_when_closed();
        } else if let Some(send) = self.send.as_mut() {
            end_send_half(send, self.close);
        }
    }

    /// Safari: RST_STREAM(NO_ERROR) once its Close frame is out and the server's came or the server
    /// ended the stream, after the frames still queued.
    fn reset_when_closed(&mut self) {
        if self.sent.saw_close && (self.received.saw_close || self.ended) {
            if let Some(mut send) = self.send.take() {
                send.send_reset_after_data(http2::Reason::NO_ERROR);
            }
        }
    }

    /// Safari's reply to the server's Close frame, `frame`, as three DATA frames (header, masking
    /// key, payload) when the window takes it whole; `Ready(Ok(false))` when it isn't a masked
    /// control frame at all, so the caller falls back to the usual write path. Unlike that path,
    /// this waits for the window to grow enough for the whole frame rather than sending less than
    /// it, since a split reply must go out as one piece to match the capture: `Pending` while the
    /// server hasn't granted enough, same as the caller's own capacity wait below.
    fn send_split_close_reply(
        &mut self,
        frame: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Ok(false));
        };
        // A masked control frame: 2 header bytes (payload up to 125), a 4-byte key, the payload.
        let whole = frame.len() >= 6
            && frame[0] & 0x0f == 0x8
            && frame[1] & 0x80 != 0
            && usize::from(frame[1] & 0x7f) == frame.len() - 6;
        if !whole {
            return Poll::Ready(Ok(false));
        }
        while send.capacity() < frame.len() {
            send.reserve_capacity(frame.len());
            match ready!(send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(h2_io_error(e))),
                None => return Poll::Ready(Ok(false)),
            }
        }
        for part in [&frame[..2], &frame[2..6], &frame[6..]] {
            if !part.is_empty() {
                send.send_data(Bytes::copy_from_slice(part), false)
                    .map_err(h2_io_error)?;
            }
        }
        self.sent.scan(frame);
        Poll::Ready(Ok(true))
    }
}

/// After the server's END_STREAM: answer it, or forget the stream without a frame (see
/// [`ClosingBehavior::AnswerEndStream`]).
fn end_send_half(send: &mut http2::SendStream<Bytes>, close: H2Close) {
    if close.behavior == ClosingBehavior::AnswerEndStream {
        let _ = send.send_data(Bytes::new(), true);
    } else {
        send.abandon();
    }
}

fn h2_io_error(e: http2::Error) -> io::Error {
    if e.is_io() {
        return e
            .into_io()
            .unwrap_or_else(|| io::Error::other("HTTP/2 I/O error"));
    }
    let kind = if e.is_reset() {
        io::ErrorKind::ConnectionReset
    } else {
        io::ErrorKind::ConnectionAborted
    };
    io::Error::new(kind, e)
}

fn stream_ended() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "the server ended the WebSocket's HTTP/2 stream",
    )
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.unread.is_empty() {
                let n = this.unread.len().min(buf.remaining());
                buf.put_slice(&this.unread.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if this.ended {
                return Poll::Ready(Ok(()));
            }
            let Some(recv) = this.recv.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    if !data.is_empty() {
                        let _ = recv.flow_control().release_capacity(data.len());
                    }
                    this.received.scan(&data);
                    this.unread = data;
                }
                Some(Err(e)) => return Poll::Ready(Err(h2_io_error(e))),
                None => {
                    this.on_end();
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    /// Each write goes out as one DATA frame (split only by flow control and the frame size), as
    /// browsers write one per WebSocket frame. Once the server has ended the stream nothing more is
    /// sent, not even the reply to its Close frame: Chromium up to 154 and Firefox treat END_STREAM
    /// as the end of the connection. Safari still answers a Close frame, split in three
    /// ([`ClosingBehavior::ResetAfterClose`]), and then resets the stream. Chromium 155 still sends
    /// its Close frame, which carries END_STREAM ([`ClosingBehavior::EndStreamWithClose`]), and
    /// nothing after it.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.ended
            && this
                .recv
                .as_ref()
                .is_some_and(http2::RecvStream::is_end_stream)
        {
            this.on_end();
        }
        let may_answer = matches!(
            this.close.behavior,
            ClosingBehavior::ResetAfterClose | ClosingBehavior::EndStreamWithClose
        );
        if (this.ended && !may_answer) || this.end_sent || this.send.is_none() {
            return Poll::Ready(Err(stream_ended()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.close.behavior == ClosingBehavior::ResetAfterClose
            && this.received.saw_close
            && !this.sent.saw_close
        {
            match this.send_split_close_reply(buf, cx) {
                Poll::Ready(Ok(true)) => {
                    this.reset_when_closed();
                    return Poll::Ready(Ok(buf.len()));
                }
                Poll::Ready(Ok(false)) => {} // not (or no longer) a whole control frame: fall through
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let Some(send) = this.send.as_mut() else {
            return Poll::Ready(Err(stream_ended()));
        };
        loop {
            let capacity = send.capacity();
            if capacity > 0 {
                let n = capacity.min(buf.len());
                let mut sent = this.sent.clone();
                sent.scan(&buf[..n]);
                let end = this.close.behavior == ClosingBehavior::EndStreamWithClose
                    && sent.close_complete();
                send.send_data(Bytes::copy_from_slice(&buf[..n]), end)
                    .map_err(h2_io_error)?;
                this.sent = sent;
                this.end_sent = end;
                if this.close.behavior == ClosingBehavior::ResetAfterClose {
                    this.reset_when_closed();
                }
                return Poll::Ready(Ok(n));
            }
            send.reserve_capacity(buf.len());
            match ready!(send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(h2_io_error(e))),
                None => return Poll::Ready(Err(stream_ended())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The connection's task writes the frames.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The stream ends when it is dropped.
        Poll::Ready(Ok(()))
    }
}

/// The end of the stream when the socket is dropped: after the server's END_STREAM as
/// [`ClosingBehavior::AnswerEndStream`] says; after the closing handshake a wait of
/// [`H2Close::linger`] for that END_STREAM, then RST_STREAM(CANCEL), or at once
/// RST_STREAM(NO_ERROR) with [`ClosingBehavior::ResetAfterClose`]; a socket dropped before its
/// closing handshake is reset with CANCEL at once. With [`ClosingBehavior::EndStreamWithClose`] the
/// Close frame has ended the client's half, and a stream not closed on both ends is reset with
/// CANCEL (after the linger time once the closing handshake is complete).
impl Drop for H2Stream {
    fn drop(&mut self) {
        let (Some(mut send), Some(recv)) = (self.send.take(), self.recv.take()) else {
            return;
        };
        if self.close.behavior == ClosingBehavior::ResetAfterClose {
            let closed = (self.sent.saw_close && self.received.saw_close)
                || self.ended
                || recv.is_end_stream();
            if closed {
                send.send_reset_after_data(http2::Reason::NO_ERROR);
            } else {
                send.send_reset(http2::Reason::CANCEL);
            }
            return;
        }
        if self.close.behavior == ClosingBehavior::EndStreamWithClose {
            if self.end_sent && (self.ended || recv.is_end_stream()) {
                return;
            }
            if self.end_sent && self.received.saw_close {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(linger(send, recv, self.close));
                    return;
                }
            }
            send.send_reset(http2::Reason::CANCEL);
            return;
        }
        if self.ended {
            return;
        }
        if recv.is_end_stream() {
            end_send_half(&mut send, self.close);
            return;
        }
        if self.sent.saw_close && self.received.saw_close {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(linger(send, recv, self.close));
                return;
            }
        }
        send.send_reset(http2::Reason::CANCEL);
    }
}

/// Wait for the server to end the stream after the closing handshake.
async fn linger(mut send: http2::SendStream<Bytes>, mut recv: http2::RecvStream, close: H2Close) {
    let ended = tokio::time::timeout(close.linger, async {
        while let Some(data) = recv.data().await {
            match data {
                Ok(data) if !data.is_empty() => {
                    let _ = recv.flow_control().release_capacity(data.len());
                }
                Ok(_) => {}
                // Reset by the server: nothing left to end.
                Err(_) => return false,
            }
        }
        true
    })
    .await;
    match ended {
        // The Close frame ended the client's half already.
        Ok(true) if close.behavior == ClosingBehavior::EndStreamWithClose => {}
        Ok(true) => end_send_half(&mut send, close),
        Ok(false) => {}
        Err(_) => send.send_reset(http2::Reason::CANCEL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sec_websocket_accept_validation() {
        // RFC 6455 example: key "dGhlIHNhbXBsZSBub25jZQ==" should produce accept
        // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn frame_scan_finds_close_frames_across_writes() {
        // A masked text frame with a 126-byte payload (16-bit length), then a masked Close frame,
        // fed in pieces that split both headers.
        let mut text = vec![0x81, 0xfe, 0x00, 0x7e, 1, 2, 3, 4];
        text.extend(std::iter::repeat_n(0u8, 126));
        let close = [0x88, 0x82, 9, 9, 9, 9, 0x03, 0xe8];
        let mut scan = FrameScan::default();
        scan.scan(&text[..3]);
        scan.scan(&text[3..40]);
        assert!(!scan.saw_close);
        scan.scan(&text[40..]);
        scan.scan(&close[..1]);
        assert!(!scan.saw_close);
        scan.scan(&close[1..]);
        assert!(scan.saw_close);

        // Unmasked (server) frames: an empty ping, then a Close.
        let mut scan = FrameScan::default();
        scan.scan(&[0x89, 0x00, 0x88, 0x02, 0x03, 0xe8]);
        assert!(scan.saw_close);
    }

    #[test]
    fn policies_follow_the_browser() {
        use crate::profile::{Chrome, Edge, Firefox, Opera, Os, Safari};
        let chrome = |v| policy(&Chrome::version(v, Os::Windows).unwrap());
        assert_eq!(chrome(153).over_h2, OverH2::ExistingConnection);
        assert_eq!(chrome(153).close.behavior, ClosingBehavior::Wait);
        assert_eq!(chrome(154).close.behavior, ClosingBehavior::AnswerEndStream);
        assert_eq!(chrome(154).close.linger, Duration::from_secs(2));
        assert_eq!(
            chrome(155).close.behavior,
            ClosingBehavior::EndStreamWithClose
        );
        assert_eq!(chrome(155).close.linger, Duration::from_secs(2));
        // Edge 153 and Opera run Chromium below 154.
        assert_eq!(
            policy(&Edge::version(153, Os::Windows).unwrap())
                .close
                .behavior,
            ClosingBehavior::Wait
        );
        let opera = policy(&Opera::latest());
        assert_eq!(opera.over_h2, OverH2::ExistingConnection);
        assert_eq!(opera.close.behavior, ClosingBehavior::Wait);

        let firefox = policy(&Firefox::latest());
        assert_eq!(firefox.over_h2, OverH2::OwnConnections);
        assert_eq!(firefox.close.linger, Duration::from_secs(1));
        assert_eq!(firefox.close.behavior, ClosingBehavior::Wait);

        // Safari from macOS 26 and iOS 26 on.
        let safari = |v, os| policy(&Safari::version(v, os).unwrap());
        for (version, os) in [("27.0", Os::MacOS), ("26.0", Os::Ios)] {
            let tahoe = safari(version, os);
            assert_eq!(tahoe.over_h2, OverH2::ExistingConnection, "{version}");
            assert_eq!(tahoe.close.behavior, ClosingBehavior::ResetAfterClose);
        }
        for (version, os) in [("18.3", Os::MacOS), ("18.3", Os::Ios), ("17.0", Os::Ios)] {
            assert_eq!(safari(version, os).over_h2, OverH2::Never, "{version}");
        }
        assert_eq!(
            policy(&crate::profile::OkHttp::latest()).over_h2,
            OverH2::Never
        );
    }
}
