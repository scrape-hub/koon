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
use tungstenite::error::ProtocolError;
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
                    *guard = None;
                    if let Some(mut sink) = self.sink.lock().await.take() {
                        let _ = sink.close().await;
                    }
                    return Ok(None);
                }
                Some(Ok(_)) => continue,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverH2 {
    Never,
    ExistingConnection,
    OwnConnections,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosingBehavior {
    Wait,
    AnswerEndStream,
    EndStreamWithClose,
    ResetAfterClose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H2Close {
    pub linger: Duration,
    pub behavior: ClosingBehavior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    pub over_h2: OverH2,
    pub close: H2Close,
}

const CHROMIUM_END_STREAM_REPLY_VERSION: u32 = 154;

const CHROMIUM_END_STREAM_WITH_CLOSE_VERSION: u32 = 155;

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

fn refused(status: http::StatusCode, headers: &[(String, String)]) -> Error {
    let mut response = http::Response::new(None);
    *response.status_mut() = status;
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    tungstenite::Error::Http(response).into()
}

fn invalid(e: ProtocolError) -> Error {
    tungstenite::Error::Protocol(e).into()
}

fn check_selected<'a>(
    offered: &[(String, String)],
    value: impl Fn(&str) -> Option<&'a str>,
) -> Result<(), Error> {
    let was_offered = |name: &str| offered.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    for name in ["sec-websocket-extensions", "sec-websocket-protocol"] {
        if value(name).is_some_and(|v| !v.trim().is_empty()) && !was_offered(name) {
            return Err(invalid(ProtocolError::InvalidHeader(
                http::HeaderName::from_static(name),
            )));
        }
    }
    Ok(())
}

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
        let status =
            http::StatusCode::from_u16(response.status).unwrap_or(http::StatusCode::BAD_GATEWAY);
        return Err(refused(status, &response.headers));
    }
    let value = |name: &str| {
        response
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if !value("upgrade").is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket")) {
        return Err(invalid(ProtocolError::MissingUpgradeWebSocketHeader));
    }
    if !value("connection").is_some_and(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    }) {
        return Err(invalid(ProtocolError::MissingConnectionUpgradeHeader));
    }
    let expected = tungstenite::handshake::derive_accept_key(key.as_bytes());
    match value("sec-websocket-accept") {
        Some(accept) if accept.trim() == expected => {}
        _ => return Err(invalid(ProtocolError::SecWebSocketAcceptKeyMismatch)),
    }
    check_selected(&headers, value)?;

    let prefixed: BoxedIo = Box::new(PrefixedStream::new(response.leftover, conn));
    let ws = WsStream::from_raw_socket(prefixed, Role::Client, None).await;
    Ok((WebSocket::new(ws), response.headers))
}

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
        return Err(refused(response.status, &headers));
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

#[derive(Clone, Default)]
struct FrameScan {
    header: [u8; 14],
    header_len: usize,
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

    fn close_complete(&self) -> bool {
        self.saw_close && self.header_len == 0 && self.payload_left == 0
    }
}

struct H2Stream {
    send: Option<http2::SendStream<Bytes>>,
    recv: Option<http2::RecvStream>,
    unread: Bytes,
    ended: bool,
    end_sent: bool,
    close: H2Close,
    sent: FrameScan,
    received: FrameScan,
}

impl H2Stream {
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

    fn reset_when_closed(&mut self) {
        if self.sent.saw_close && (self.received.saw_close || self.ended) {
            if let Some(mut send) = self.send.take() {
                send.send_reset_after_data(http2::Reason::NO_ERROR);
            }
        }
    }

    fn send_split_close_reply(
        &mut self,
        frame: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Ok(false));
        };
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
                Poll::Ready(Ok(false)) => {}
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
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

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

async fn linger(mut send: http2::SendStream<Bytes>, mut recv: http2::RecvStream, close: H2Close) {
    let ended = tokio::time::timeout(close.linger, async {
        while let Some(data) = recv.data().await {
            match data {
                Ok(data) if !data.is_empty() => {
                    let _ = recv.flow_control().release_capacity(data.len());
                }
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        true
    })
    .await;
    match ended {
        Ok(true) if close.behavior == ClosingBehavior::EndStreamWithClose => {}
        Ok(true) => end_send_half(&mut send, close),
        Ok(false) => {}
        Err(_) => send.send_reset(http2::Reason::CANCEL),
    }
}
