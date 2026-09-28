use std::io::ErrorKind;

use http::Method;

use crate::error::Error;
use crate::http1::{self, BodyReader, BodyState};
use crate::pool::{ConnInfo, PoolKey};

use super::body::{BodyStream, ExchangeError, Http1Body, PoolReturn, ResponseParts};
use super::connection::BoxedIo;
use super::request_body::{Body, already_sent};
use super::response::estimate_headers_size;

/// What [`Client::send_h1`] needs beyond the connection and the body.
pub(super) struct SendContext<'a> {
    pub info: ConnInfo,
    pub reused: bool,
    pub pool_key: PoolKey,
    pub method: &'a Method,
    /// The request target: the path, or the absolute URL when talking to an HTTP proxy.
    pub target: &'a str,
    /// Written verbatim.
    pub headers: Vec<(String, String)>,
}

impl super::Client {
    /// Send one HTTP/1.1 request on `conn` and read the response head. A reusable connection
    /// returns to the pool once its body has been read.
    ///
    /// A `reused` connection that turns out to be closed before any byte of the response arrived
    /// was most likely closed by the server while it sat idle, before the request reached it: the
    /// failure is [`ExchangeError::NotSent`] for every method, as in Chrome
    /// (`HttpNetworkTransaction::ShouldResendRequest`).
    pub(super) async fn send_h1(
        &self,
        mut conn: BoxedIo,
        ctx: SendContext<'_>,
        body: &Body,
    ) -> Result<ResponseParts, ExchangeError> {
        let SendContext {
            info,
            reused,
            pool_key,
            method,
            target,
            headers,
        } = ctx;
        let bytes_sent = if body.is_stream() {
            let stream = body
                .take_stream()
                .ok_or_else(|| ExchangeError::Sent(already_sent()))?;
            let length = body.content_length();
            http1::write_streaming_request(&mut conn, method, target, &headers, stream, length)
                .await
        } else {
            let bytes = body.bytes().map(|b| &b[..]);
            http1::write_request(&mut conn, method, target, &headers, bytes).await
        }
        .map_err(|e| {
            if reused && closed_before_response(&e, false) {
                ExchangeError::NotSent(e)
            } else {
                ExchangeError::Sent(e)
            }
        })?;

        let mut reader = BodyReader::new(conn);
        let head = match reader.read_head().await {
            Ok(head) => head,
            Err(e) if reused && closed_before_response(&e, reader.received()) => {
                return Err(ExchangeError::NotSent(e));
            }
            Err(e) => return Err(ExchangeError::Sent(e)),
        };
        let framing = head.framing(method).map_err(ExchangeError::Sent)?;
        let keep_alive = head.keep_alive(framing);
        let head_bytes = estimate_headers_size(&head.headers);

        let reuse = keep_alive.then(|| PoolReturn {
            pool: self.pool.clone(),
            key: pool_key,
            info: info.clone(),
        });
        let state = BodyState::new(framing);
        let body = if matches!(state, BodyState::Done) {
            // Nothing to read: the connection is free right away.
            if let Some(ret) = reuse {
                let (conn, rest) = reader.into_parts();
                if rest.is_empty() {
                    ret.pool.put_h1(ret.key, conn, ret.info);
                }
            }
            BodyStream::Empty
        } else {
            BodyStream::Http1(Box::new(Http1Body {
                reader,
                state,
                reuse,
            }))
        };

        Ok(ResponseParts {
            status: head.status,
            headers: head.headers,
            version: "HTTP/1.1",
            request_headers: headers,
            info,
            connection_reused: reused,
            bytes_sent,
            head_bytes,
            body,
        })
    }
}

/// Whether `e` means the connection was closed before the response head (Chrome's resend errors:
/// `ERR_CONNECTION_RESET`, `_CLOSED`, `_ABORTED`, `ERR_SOCKET_NOT_CONNECTED`, and
/// `ERR_EMPTY_RESPONSE` for a close before any byte of the response).
fn closed_before_response(e: &Error, response_started: bool) -> bool {
    let Error::Io(io) = e else {
        return false;
    };
    match io.kind() {
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::BrokenPipe => true,
        ErrorKind::UnexpectedEof => !response_started,
        _ => false,
    }
}
