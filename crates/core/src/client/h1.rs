use http::{HeaderName, HeaderValue, Method, Uri};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_boring2::SslStream;

use crate::error::Error;
use crate::http1;
use crate::streaming::StreamingResponse;

use super::headers;
use super::response::{HttpResponse, decompress_body};

impl super::Client {
    /// Send an HTTP/1.1 request on an existing TLS stream.
    /// Returns the response and whether the connection supports keep-alive.
    pub(super) async fn send_on_h1(
        &self,
        stream: &mut SslStream<TcpStream>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<(HttpResponse, bool), Error> {
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

        let headers = headers::build_request_headers(
            &self.profile.headers,
            &self.custom_headers,
            extra_headers,
            cookie_header,
            &["host", "cookie"],
            Some(authority),
            true,
            Some(uri),
        );

        // Write request
        let body_ref = body.as_deref();
        let bytes_sent = http1::write_request(stream, &method, uri, &headers, body_ref).await?;

        // Read response (with timeout)
        let raw = tokio::time::timeout(self.timeout, http1::read_response(stream))
            .await
            .map_err(|_| Error::Timeout)??;

        // Check keep-alive from response
        let keep_alive = !raw
            .headers
            .iter()
            .any(|(k, v)| k == "connection" && v.eq_ignore_ascii_case("close"));

        // bytes_received = raw body (pre-decompression) + header estimate
        let raw_body_len = raw.body.len() as u64;
        let header_size = super::response::estimate_headers_size(&raw.headers);
        let bytes_received = raw_body_len + header_size;

        // Decompress body
        let content_encoding = raw
            .headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(raw.body, content_encoding)?;

        let response = HttpResponse {
            status: raw.status,
            headers: raw.headers,
            body,
            version: "HTTP/1.1".to_string(),
            url: uri.to_string(),
            bytes_sent,
            bytes_received,
        };

        Ok((response, keep_alive))
    }

    /// Send an H1 request and return a streaming response.
    /// The TLS stream is moved into a background task that streams body chunks.
    pub(super) async fn send_on_h1_streaming(
        &self,
        mut stream: SslStream<TcpStream>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<StreamingResponse, Error> {
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

        let headers = headers::build_request_headers(
            &self.profile.headers,
            &self.custom_headers,
            extra_headers,
            cookie_header,
            &["host", "cookie"],
            Some(authority),
            true,
            Some(uri),
        );

        let body_ref = body.as_deref();
        let bytes_sent =
            http1::write_request(&mut stream, &method, uri, &headers, body_ref).await?;

        // Read only headers
        let (status, resp_headers, remaining) = tokio::time::timeout(
            self.timeout,
            http1::read_response_for_streaming(&mut stream),
        )
        .await
        .map_err(|_| Error::Timeout)??;

        let header_size = super::response::estimate_headers_size(&resp_headers);

        let is_chunked = resp_headers
            .iter()
            .any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));
        let content_length: Option<usize> = resp_headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.trim().parse().ok());

        let (tx, rx) = mpsc::channel(16);

        // Spawn background task to stream body — connection is NOT returned to pool
        let bytes_received_counter = self.bytes_received_counter();
        // Track header bytes immediately
        bytes_received_counter.fetch_add(header_size, std::sync::atomic::Ordering::Relaxed);
        self.bytes_sent_counter()
            .fetch_add(bytes_sent, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            if is_chunked {
                http1::stream_chunked_body(&mut stream, &remaining, tx).await;
            } else if let Some(len) = content_length {
                http1::stream_content_length_body(&mut stream, &remaining, len, tx).await;
            } else {
                http1::stream_until_close(&mut stream, &remaining, tx).await;
            }
        });

        Ok(StreamingResponse::new(
            status,
            resp_headers,
            "HTTP/1.1".to_string(),
            uri.to_string(),
            rx,
            bytes_sent,
            bytes_received_counter,
        ))
    }

    /// Send an H1 request with raw (passthrough) headers.
    pub(super) async fn send_on_h1_raw(
        &self,
        stream: &mut SslStream<TcpStream>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        raw_headers: &[(String, String)],
    ) -> Result<(HttpResponse, bool), Error> {
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

        let mut headers = http::HeaderMap::new();

        // Host header
        if let Ok(hv) = HeaderValue::from_str(authority) {
            headers.insert(http::header::HOST, hv);
        }

        // Raw headers from proxy client
        for (name, value) in raw_headers {
            let lower = name.to_lowercase();
            if lower == "host" {
                continue; // Already set above
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Ensure connection: keep-alive
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );

        let body_ref = body.as_deref();
        let bytes_sent = http1::write_request(stream, &method, uri, &headers, body_ref).await?;

        let raw = tokio::time::timeout(self.timeout, http1::read_response(stream))
            .await
            .map_err(|_| Error::Timeout)??;

        let keep_alive = !raw
            .headers
            .iter()
            .any(|(k, v)| k == "connection" && v.eq_ignore_ascii_case("close"));

        let raw_body_len = raw.body.len() as u64;
        let header_size = super::response::estimate_headers_size(&raw.headers);
        let bytes_received = raw_body_len + header_size;

        let content_encoding = raw
            .headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(raw.body, content_encoding)?;

        let response = HttpResponse {
            status: raw.status,
            headers: raw.headers,
            body,
            version: "HTTP/1.1".to_string(),
            url: uri.to_string(),
            bytes_sent,
            bytes_received,
        };

        Ok((response, keep_alive))
    }
}
