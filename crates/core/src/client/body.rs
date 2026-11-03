use std::future::Future;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use tokio::task::JoinHandle;

use crate::error::{Error, Phase};
use crate::http1::{BodyReader, BodyState};
use crate::pool::{ConnInfo, ConnectionPool, PoolKey};

use super::connection::BoxedIo;
use super::h3::H3Lease;

const MAX_PREALLOCATED_BODY: u64 = 8 * 1024 * 1024;

pub enum ExchangeError {
    NotSent(Error),
    Sent(Error),
    Received(Error),
    Invalid(Error),
}

impl ExchangeError {
    pub fn error(&self) -> &Error {
        match self {
            Self::NotSent(e) | Self::Sent(e) | Self::Received(e) | Self::Invalid(e) => e,
        }
    }

    pub fn into_error(self) -> Error {
        match self {
            Self::NotSent(e) | Self::Sent(e) | Self::Received(e) | Self::Invalid(e) => e,
        }
    }

    pub fn into_phased_error(self) -> Error {
        match self {
            Self::NotSent(e) => e.in_phase(Phase::Connect),
            Self::Sent(e) => e.in_phase(Phase::Request),
            Self::Received(e) => e.in_phase(Phase::Body),
            Self::Invalid(e) => e,
        }
    }
}

pub struct MuxFailure {
    pub error: ExchangeError,
    pub connection_failed: bool,
}

pub struct PoolReturn {
    pub pool: Arc<ConnectionPool>,
    pub key: PoolKey,
    pub info: ConnInfo,
}

pub struct Http1Body {
    pub _slot: Option<tokio::sync::OwnedSemaphorePermit>,
    pub reader: BodyReader<BoxedIo>,
    pub state: BodyState,
    pub reuse: Option<PoolReturn>,
}

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

pub enum UploadOr<E> {
    Upload(Error),
    Response(E),
}

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
        *upload = None;
        if let Ok(Err(e @ Error::Body(..))) = finished {
            return Err(UploadOr::Upload(e));
        }
    }
    response.await.map_err(UploadOr::Response)
}

pub struct Http2Body {
    pub recv: http2::RecvStream,
    pub _upload: Option<Upload>,
}

pub struct Http3Body {
    pub stream: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    pub _upload: Option<Upload>,
    pub _conn: H3Lease,
}

pub enum BodyStream {
    Empty,
    Http1(Box<Http1Body>),
    Http2(Box<Http2Body>),
    Http3(Box<Http3Body>),
}

impl BodyStream {
    pub async fn next(&mut self) -> Result<Option<Bytes>, Error> {
        match self {
            Self::Empty => Ok(None),
            Self::Http1(body) => {
                let Http1Body { reader, state, .. } = body.as_mut();
                if let Some(chunk) = reader.next_body_chunk(state).await? {
                    return Ok(Some(chunk));
                }
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

    pub async fn collect(&mut self, size_hint: Option<u64>, max: u64) -> Result<Vec<u8>, Error> {
        let capacity = size_hint.map_or(0, |n| n.min(max).min(MAX_PREALLOCATED_BODY) as usize);
        let mut out = Vec::with_capacity(capacity);
        let mut total: u64 = 0;
        while let Some(chunk) = self.next().await? {
            total += chunk.len() as u64;
            if total > max {
                return Err(Error::ResponseTooLarge(max));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

pub struct ResponseParts {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub version: &'static str,
    pub request_headers: Vec<(String, String)>,
    pub info: ConnInfo,
    pub connection_reused: bool,
    pub bytes_sent: u64,
    pub head_bytes: u64,
    pub body: BodyStream,
}

impl ResponseParts {
    pub fn content_length(&self) -> Option<u64> {
        super::headers::header_value(&self.headers, "content-length")?
            .trim()
            .parse()
            .ok()
    }
}
