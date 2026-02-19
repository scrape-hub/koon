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
}

impl StreamingResponse {
    /// Create a new StreamingResponse.
    pub(crate) fn new(
        status: u16,
        headers: Vec<(String, String)>,
        version: String,
        url: String,
        body_rx: mpsc::Receiver<Result<Vec<u8>, Error>>,
    ) -> Self {
        StreamingResponse {
            status,
            headers,
            version,
            url,
            body_rx,
        }
    }

    /// Receive the next body chunk.
    /// Returns `None` when the body is complete.
    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, Error>> {
        self.body_rx.recv().await
    }

    /// Collect the entire body into a single buffer.
    /// Consumes the streaming response.
    pub async fn collect_body(mut self) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        while let Some(chunk) = self.body_rx.recv().await {
            body.extend_from_slice(&chunk?);
        }
        Ok(body)
    }
}
