use std::future::Future;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use tokio::task::JoinHandle;

use crate::error::Error;
use crate::http1::{BodyReader, BodyState};
use crate::pool::{ConnInfo, ConnectionPool, PoolKey};

use super::connection::BoxedIo;
use super::h3::H3Lease;

/// Most bytes a Content-Length reserves up front when a body is collected; a longer body grows the
/// buffer as it arrives.
const MAX_PREALLOCATED_BODY: u64 = 8 * 1024 * 1024;

/// Where a request failed, which decides whether it may be replayed on a new connection.
pub enum ExchangeError {
    /// The request never reached the server (dead pooled connection, refused stream, failed
    /// connection setup): safe to replay for any method.
    NotSent(Error),
    /// The request may have been processed: only idempotent requests may be replayed.
    Sent(Error),
    /// The request could not be built (an invalid header): no connection can send it, so it is
    /// never replayed.
    Invalid(Error),
}

impl ExchangeError {
    pub fn error(&self) -> &Error {
        match self {
            Self::NotSent(e) | Self::Sent(e) | Self::Invalid(e) => e,
        }
    }

    pub fn into_error(self) -> Error {
        match self {
            Self::NotSent(e) | Self::Sent(e) | Self::Invalid(e) => e,
        }
    }
}

/// A request that failed on an HTTP/2 or HTTP/3 connection.
pub struct MuxFailure {
    pub error: ExchangeError,
    /// The connection itself failed (I/O error, GOAWAY, closed) rather than just the request's
    /// stream: it cannot carry further requests.
    pub connection_failed: bool,
}

/// An HTTP/1.1 connection to hand back to the pool once its body is read.
pub struct PoolReturn {
    pub pool: Arc<ConnectionPool>,
    pub key: PoolKey,
    pub info: ConnInfo,
}

/// An HTTP/1.1 body being read from its connection.
pub struct Http1Body {
    pub reader: BodyReader<BoxedIo>,
    pub state: BodyState,
    pub reuse: Option<PoolReturn>,
}

/// A request body upload running beside the exchange (HTTP/2, HTTP/3). It stops when its response
/// is dropped or read to the end.
pub struct Upload(JoinHandle<Result<(), Error>>);

impl Upload {
    pub fn spawn(upload: impl Future<Output = Result<(), Error>> + Send + 'static) -> Self {
        Self(tokio::spawn(upload))
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Which side of an exchange with an upload failed.
pub enum UploadOr<E> {
    /// The request body stream.
    Upload(Error),
    Response(E),
}

/// Wait for the response head while `upload` runs. A failing body stream decides the error; any
/// other upload failure (the stream was reset) is left to the response. An upload still running
/// when the head arrives goes on; a finished one is removed from `upload`, so that waiting for the
/// next head (after an interim 1xx response) does not wait for it again.
pub async fn with_upload<T, E>(
    response: impl Future<Output = Result<T, E>>,
    upload: &mut Option<Upload>,
) -> Result<T, UploadOr<E>> {
    tokio::pin!(response);
    if let Some(Upload(handle)) = upload.as_mut() {
        let finished = tokio::select! {
            result = &mut response => return result.map_err(UploadOr::Response),
            finished = handle => finished,
        };
        // A JoinHandle must not be polled again once it has completed.
        *upload = None;
        if let Ok(Err(e @ Error::Body(..))) = finished {
            return Err(UploadOr::Upload(e));
        }
    }
    response.await.map_err(UploadOr::Response)
}

/// An HTTP/2 body being read from its stream.
pub struct Http2Body {
    pub recv: http2::RecvStream,
    pub _upload: Option<Upload>,
}

/// An HTTP/3 body being read from its request stream.
pub struct Http3Body {
    pub stream: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    pub _upload: Option<Upload>,
    /// Keeps the connection open until the body is read.
    pub _conn: H3Lease,
}

/// A response body that is read on demand.
pub enum BodyStream {
    Empty,
    Http1(Box<Http1Body>),
    Http2(Box<Http2Body>),
    Http3(Box<Http3Body>),
}

impl BodyStream {
    /// Read the next piece of the body; `None` once it is complete.
    pub async fn next(&mut self) -> Result<Option<Bytes>, Error> {
        match self {
            Self::Empty => Ok(None),
            Self::Http1(body) => {
                let Http1Body { reader, state, .. } = body.as_mut();
                if let Some(chunk) = reader.next_body_chunk(state).await? {
                    return Ok(Some(chunk));
                }
                // Body complete: the connection can serve the next request, unless the server sent
                // bytes beyond the response.
                if let Self::Http1(body) = std::mem::replace(self, Self::Empty) {
                    if let Some(ret) = body.reuse {
                        let (conn, rest) = body.reader.into_parts();
                        if rest.is_empty() {
                            ret.pool.put_h1(ret.key, conn, ret.info);
                        }
                    }
                }
                Ok(None)
            }
            Self::Http2(body) => match body.recv.data().await {
                Some(Ok(data)) => {
                    let _ = body.recv.flow_control().release_capacity(data.len());
                    Ok(Some(data))
                }
                Some(Err(e)) => Err(Error::Http2(e)),
                None => {
                    *self = Self::Empty;
                    Ok(None)
                }
            },
            Self::Http3(body) => match body.stream.recv_data().await {
                Ok(Some(mut buf)) => Ok(Some(buf.copy_to_bytes(buf.remaining()))),
                Ok(None) => {
                    *self = Self::Empty;
                    Ok(None)
                }
                Err(e) => Err(Error::Http3(
                    format!("reading H3 body: {e}"),
                    crate::error::boxed(e),
                )),
            },
        }
    }

    /// Read the rest of the body into memory. `size_hint` is the Content-Length, if known; `max` is
    /// the byte ceiling ([`ClientBuilder::max_response_body`](super::ClientBuilder::max_response_body)),
    /// checked after every chunk so a body that never ends (or ends far past `max`) is caught as soon
    /// as it crosses the limit, not only once fully read.
    ///
    /// # Errors
    /// [`Error::Body`] if the body exceeds `max` bytes, or whatever reading the connection fails
    /// with.
    pub async fn collect(&mut self, size_hint: Option<u64>, max: u64) -> Result<Vec<u8>, Error> {
        let capacity = size_hint.map_or(0, |n| n.min(max).min(MAX_PREALLOCATED_BODY) as usize);
        let mut out = Vec::with_capacity(capacity);
        let mut total: u64 = 0;
        while let Some(chunk) = self.next().await? {
            total += chunk.len() as u64;
            if total > max {
                return Err(Error::Body(
                    format!("response body exceeded {max} bytes"),
                    None,
                ));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// Response head plus unread body, as produced by one request/response exchange on a connection.
pub struct ResponseParts {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// "HTTP/1.1", "h2" or "h3".
    pub version: &'static str,
    /// The headers sent, in wire order and casing, pseudo-headers first.
    pub request_headers: Vec<(String, String)>,
    pub info: ConnInfo,
    pub connection_reused: bool,
    pub bytes_sent: u64,
    /// Estimated size of the response head.
    pub head_bytes: u64,
    pub body: BodyStream,
}

impl ResponseParts {
    /// The Content-Length of the response, if it has a valid one.
    pub fn content_length(&self) -> Option<u64> {
        super::headers::header_value(&self.headers, "content-length")?
            .trim()
            .parse()
            .ok()
    }
}
