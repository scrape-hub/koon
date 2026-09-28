use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::client::ContentDecoder;
use crate::client::body::{BodyStream, ResponseParts};
use crate::error::Error;

/// A streaming HTTP response that delivers the body in chunks. Unlike
/// [`HttpResponse`](crate::client::HttpResponse), the body is not buffered: each
/// [`next_chunk()`](StreamingResponse::next_chunk) reads from the connection, so a slow consumer
/// applies backpressure to the server. Dropping the response closes (HTTP/1.1) or resets (HTTP/2,
/// HTTP/3) the stream. Redirects are followed and cookies stored before the response is returned,
/// like for buffered requests; the body arrives as sent, not decompressed, unless
/// [`decode_content()`](StreamingResponse::decode_content) is called.
pub struct StreamingResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// HTTP version used (e.g. "h2", "HTTP/1.1", "h3").
    pub version: String,
    /// The final URL after following redirects.
    pub url: String,
    /// Remote IP address of the peer (the proxy when one is used).
    pub remote_address: Option<String>,
    /// Whether the TLS handshake of the connection resumed a session.
    pub tls_resumed: bool,
    /// Whether an existing pooled connection was reused.
    pub connection_reused: bool,
    /// Headers of the final request as sent, in wire order and casing.
    pub request_headers: Vec<(String, String)>,
    body: BodyStream,
    /// Longest wait for the next chunk.
    idle_timeout: Duration,
    bytes_sent: u64,
    bytes_received: u64,
    total_received: Arc<AtomicU64>,
    /// Decodes the chunks after [`decode_content()`](Self::decode_content).
    decoder: Option<ContentDecoder>,
    /// Cap on a decoded body (see [`ClientBuilder::max_response_body`](crate::client::ClientBuilder::max_response_body)),
    /// applied by [`decode_content()`](Self::decode_content) and [`collect_body()`](Self::collect_body).
    max_body: u64,
}

impl StreamingResponse {
    pub(crate) fn new(
        parts: ResponseParts,
        url: String,
        idle_timeout: Duration,
        total_received: Arc<AtomicU64>,
        max_body: u64,
    ) -> Self {
        Self {
            status: parts.status,
            headers: parts.headers,
            version: parts.version.to_string(),
            url,
            remote_address: parts.info.peer_addr,
            tls_resumed: parts.info.tls_resumed,
            connection_reused: parts.connection_reused,
            request_headers: parts.request_headers,
            body: parts.body,
            idle_timeout,
            bytes_sent: parts.bytes_sent,
            bytes_received: parts.head_bytes,
            total_received,
            decoder: None,
            max_body,
        }
    }

    /// Approximate bytes sent for this request (headers + body).
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Approximate bytes received for this response so far (headers + body chunks read).
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Decode the body's Content-Encoding (gzip, deflate, br, zstd and stacked codings) from now
    /// on: [`next_chunk()`](Self::next_chunk) and [`collect_body()`](Self::collect_body) then
    /// return decoded data, and fail with [`Error::Io`] on data that does not decode or a
    /// compressed stream cut off. Call before reading the first chunk; `headers` stay as received.
    /// Returns whether there is anything to decode: `false` without a Content-Encoding (or only
    /// `identity`) and for a coding koon does not know, whose body then arrives as is.
    pub fn decode_content(&mut self) -> bool {
        self.decoder = ContentDecoder::for_headers(&self.headers).map(|d| d.limit(self.max_body));
        self.decoder.is_some()
    }

    /// Receive the next body chunk. Returns `None` when the body is complete. Fails with
    /// [`Error::Timeout`] if no data arrives within the client's timeout.
    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, Error>> {
        loop {
            let chunk = match tokio::time::timeout(self.idle_timeout, self.body.next()).await {
                Err(_) => return Some(Err(Error::Timeout)),
                Ok(Err(e)) => return Some(Err(e)),
                Ok(Ok(None)) => {
                    // The end of the body, and of what the decoder holds back.
                    return match self.decoder.take()?.finish() {
                        Ok(rest) if rest.is_empty() => None,
                        rest => Some(rest),
                    };
                }
                Ok(Ok(Some(chunk))) => chunk,
            };
            self.bytes_received += chunk.len() as u64;
            self.total_received
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            let Some(decoder) = &mut self.decoder else {
                return Some(Ok(Vec::from(chunk)));
            };
            match decoder.decode(&chunk) {
                // Nothing decoded from this piece yet: read the next one.
                Ok(decoded) if decoded.is_empty() => {}
                result => return Some(result),
            }
        }
    }

    /// Read the rest of the body into a single buffer, capped like
    /// [`ClientBuilder::max_response_body`](crate::client::ClientBuilder::max_response_body) (past
    /// it, [`Error::Body`]) whether or not [`decode_content()`](Self::decode_content) was called. The
    /// response stays available, e.g. for [`bytes_received()`](Self::bytes_received). Errors
    /// ([`Error::Timeout`]) if no data arrives within the client's timeout, or with whatever
    /// [`decode_content()`](Self::decode_content) fails with.
    pub async fn collect_body(&mut self) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        let mut total: u64 = 0;
        while let Some(chunk) = self.next_chunk().await {
            let chunk = chunk?;
            total += chunk.len() as u64;
            if total > self.max_body {
                return Err(Error::Body(
                    format!("response body exceeded {} bytes", self.max_body),
                    None,
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
