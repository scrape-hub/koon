use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::error::Error;

/// A streaming HTTP response that delivers the body in chunks.
///
/// Unlike [`HttpResponse`](crate::client::HttpResponse), the body is not buffered
/// in memory. Instead, chunks arrive via an internal channel.
///
/// Streaming responses do **not** follow redirects — the caller must handle 3xx
/// responses manually (similar to `fetch(redirect: 'manual')`).
pub struct StreamingResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// HTTP version used (e.g. "h2", "HTTP/1.1", "h3").
    pub version: String,
    /// The request URL.
    pub url: String,
    /// Channel receiver for body chunks.
    body_rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
    /// Approximate bytes sent for this request.
    bytes_sent_val: u64,
    /// Shared counter for bytes received (incremented as chunks arrive).
    bytes_received_counter: Arc<AtomicU64>,
}

impl StreamingResponse {
    /// Create a new StreamingResponse.
    pub(crate) fn new(
        status: u16,
        headers: Vec<(String, String)>,
        version: String,
        url: String,
        body_rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
        bytes_sent: u64,
        bytes_received_counter: Arc<AtomicU64>,
    ) -> Self {
        StreamingResponse {
            status,
            headers,
            version,
            url,
            body_rx,
            bytes_sent_val: bytes_sent,
            bytes_received_counter,
        }
    }

    /// Approximate bytes sent for this request (headers + body).
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent_val
    }

    /// Approximate bytes received so far (headers + body chunks read).
    /// This value increases as chunks are consumed via [`next_chunk()`].
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received_counter.load(Ordering::Relaxed)
    }

    /// Receive the next body chunk.
    /// Returns `None` when the body is complete.
    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, Error>> {
        let result = self.body_rx.recv().await;
        if let Some(Ok(ref data)) = result {
            self.bytes_received_counter
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        result
    }

    /// Collect the entire body into a single buffer.
    /// Consumes the streaming response.
    pub async fn collect_body(mut self) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        while let Some(chunk) = self.body_rx.recv().await {
            let data = chunk?;
            self.bytes_received_counter
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            body.extend_from_slice(&data);
        }
        Ok(body)
    }
}
