use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring2::SslStream;
use tungstenite::protocol::Role;

use crate::error::Error;
use crate::http1;

/// A WebSocket message (text or binary).
#[derive(Debug, Clone)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
}

/// A WebSocket connection with browser-fingerprinted TLS.
///
/// The underlying TLS handshake uses the same BoringSSL fingerprint as HTTP
/// requests, so TLS fingerprinting services (JA3/JA4) see a real browser.
/// The HTTP/1.1 Upgrade handshake preserves header order from the profile.
pub struct WebSocket {
    inner: tokio_tungstenite::WebSocketStream<PrefixedStream<SslStream<TcpStream>>>,
}

impl WebSocket {
    /// Send a text message.
    pub async fn send_text(&mut self, text: &str) -> Result<(), Error> {
        use futures_util::SinkExt;
        self.inner
            .send(tungstenite::Message::Text(text.into()))
            .await?;
        Ok(())
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
        use futures_util::SinkExt;
        self.inner
            .send(tungstenite::Message::Binary(data.into()))
            .await?;
        Ok(())
    }

    /// Receive the next message. Returns `None` if the connection is closed.
    pub async fn receive(&mut self) -> Result<Option<Message>, Error> {
        use futures_util::StreamExt;
        loop {
            match self.inner.next().await {
                Some(Ok(tungstenite::Message::Text(t))) => {
                    return Ok(Some(Message::Text(t)));
                }
                Some(Ok(tungstenite::Message::Binary(b))) => {
                    return Ok(Some(Message::Binary(b)));
                }
                Some(Ok(tungstenite::Message::Ping(_))) => {
                    // Pong is sent automatically by tungstenite
                    continue;
                }
                Some(Ok(tungstenite::Message::Pong(_))) => {
                    continue;
                }
                Some(Ok(tungstenite::Message::Close(_))) => {
                    return Ok(None);
                }
                Some(Ok(tungstenite::Message::Frame(_))) => {
                    continue;
                }
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(None),
            }
        }
    }

    /// Close the WebSocket connection with an optional close code and reason.
    pub async fn close(&mut self, code: Option<u16>, reason: Option<String>) -> Result<(), Error> {
        use futures_util::SinkExt;
        let close_frame = code.map(|c| {
            tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::from(c),
                reason: reason.unwrap_or_default().into(),
            }
        });
        self.inner
            .send(tungstenite::Message::Close(close_frame))
            .await?;
        Ok(())
    }
}

/// Perform the WebSocket upgrade handshake over an existing TLS stream.
///
/// 1. Generates Sec-WebSocket-Key
/// 2. Sends HTTP/1.1 Upgrade request (with profile header order)
/// 3. Reads 101 Switching Protocols response
/// 4. Validates Sec-WebSocket-Accept
/// 5. Wraps the stream with tokio-tungstenite for frame codec
pub(crate) async fn connect(
    mut stream: SslStream<TcpStream>,
    uri: &Uri,
    headers: &HeaderMap,
    timeout: Duration,
) -> Result<WebSocket, Error> {
    // 1. Generate WebSocket key
    let key = tungstenite::handshake::client::generate_key();

    // 2. Build upgrade request headers
    let mut upgrade_headers = HeaderMap::new();

    // Copy all profile headers first (preserves order from caller)
    for (name, value) in headers.iter() {
        upgrade_headers.insert(name.clone(), value.clone());
    }

    // Add WebSocket-specific headers
    upgrade_headers.insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    upgrade_headers.insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("Upgrade"),
    );
    upgrade_headers.insert(
        HeaderName::from_static("sec-websocket-key"),
        HeaderValue::from_str(&key)
            .map_err(|_| Error::InvalidHeader("Invalid WebSocket key".into()))?,
    );
    upgrade_headers.insert(
        HeaderName::from_static("sec-websocket-version"),
        HeaderValue::from_static("13"),
    );

    // 3. Send upgrade request
    http1::write_request(&mut stream, &Method::GET, uri, &upgrade_headers, None).await?;

    // 4. Read response headers (stop at \r\n\r\n, no body)
    let upgrade_resp =
        tokio::time::timeout(timeout, http1::read_response_headers(&mut stream))
            .await
            .map_err(|_| Error::Timeout)??;

    // 5. Validate 101 status
    if upgrade_resp.status != 101 {
        return Err(Error::ConnectionFailed(format!(
            "WebSocket upgrade failed: server returned {}",
            upgrade_resp.status
        )));
    }

    // 6. Validate Sec-WebSocket-Accept
    let expected_accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    let actual_accept = upgrade_resp
        .headers
        .iter()
        .find(|(k, _)| k == "sec-websocket-accept")
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| {
            Error::ConnectionFailed("Missing Sec-WebSocket-Accept header".into())
        })?;

    if actual_accept != expected_accept {
        return Err(Error::ConnectionFailed(format!(
            "Invalid Sec-WebSocket-Accept: expected {expected_accept}, got {actual_accept}"
        )));
    }

    // 7. Wrap stream with leftover bytes
    let prefixed = PrefixedStream::new(upgrade_resp.leftover, stream);

    // 8. Create WebSocket stream from raw socket
    let ws_stream =
        tokio_tungstenite::WebSocketStream::from_raw_socket(prefixed, Role::Client, None).await;

    Ok(WebSocket { inner: ws_stream })
}

/// A stream wrapper that replays leftover bytes before reading from the inner stream.
///
/// After `read_response_headers()`, some bytes past `\r\n\r\n` may already have been
/// read into our buffer. These are WebSocket frame data that the codec needs to see.
/// `PrefixedStream` feeds those bytes first, then delegates to the inner stream.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // First, drain the prefix buffer
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.offset += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Then delegate to inner stream
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: Unpin> Unpin for PrefixedStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_prefixed_stream_read() {
        let prefix = b"leftover data".to_vec();
        let inner_data = b"inner stream data";
        let inner = &inner_data[..];

        let mut stream = PrefixedStream::new(prefix.clone(), inner);

        // Read should first return prefix bytes
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"leftover data");

        // Then inner stream bytes
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"inner stream data");

        // Then EOF
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_prefixed_stream_empty_prefix() {
        let inner_data = b"hello";
        let inner = &inner_data[..];

        let mut stream = PrefixedStream::new(Vec::new(), inner);

        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn test_sec_websocket_accept_validation() {
        // RFC 6455 example: key "dGhlIHNhbXBsZSBub25jZQ==" should produce
        // accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
