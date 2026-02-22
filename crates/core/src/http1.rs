use std::fmt::Write as FmtWrite;

use http::{HeaderMap, Method, Uri};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Error;

const INITIAL_BUF_SIZE: usize = 8192;
const MAX_HEADER_SIZE: usize = 65536;
const MAX_HEADERS: usize = 128;

pub(crate) struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Write an HTTP/1.1 request to the stream.
///
/// Headers are written in iterator order — caller must ensure correct order
/// (profile-sorted via `sort_headers_by_profile()`).
pub(crate) async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<(), Error> {
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Build request into a single buffer to minimize write syscalls
    let mut buf = String::with_capacity(512);

    // Request line
    write!(buf, "{} {} HTTP/1.1\r\n", method, path)
        .map_err(|e| Error::ConnectionFailed(format!("Failed to format request line: {e}")))?;

    // Headers in iterator order
    for (name, value) in headers.iter() {
        let val = value.to_str().unwrap_or("");
        write!(buf, "{}: {}\r\n", name, val)
            .map_err(|e| Error::ConnectionFailed(format!("Failed to format header: {e}")))?;
    }

    // Content-Length for body
    if let Some(b) = body {
        write!(buf, "content-length: {}\r\n", b.len())
            .map_err(|e| Error::ConnectionFailed(format!("Failed to format content-length: {e}")))?;
    }

    // End of headers
    buf.push_str("\r\n");

    // Write headers
    stream.write_all(buf.as_bytes()).await?;

    // Write body if present
    if let Some(b) = body {
        stream.write_all(b).await?;
    }

    stream.flush().await?;

    Ok(())
}

/// Internal: Read and parse HTTP/1.1 response headers from a stream.
/// Returns (status, headers, leftover bytes after `\r\n\r\n`).
///
/// Shared by `read_response`, `read_response_headers`, and `read_response_for_streaming`.
async fn read_raw_headers<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Error> {
    let mut buf = Vec::with_capacity(INITIAL_BUF_SIZE);
    let mut tmp = [0u8; 4096];

    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::ConnectionFailed(
                "Connection closed before headers complete".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }

        if buf.len() > MAX_HEADER_SIZE {
            return Err(Error::ConnectionFailed(
                "Response headers exceed 64KB limit".into(),
            ));
        }
    }

    let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut parsed_headers);

    let parse_result = response
        .parse(&buf[..header_end + 4])
        .map_err(|e| Error::ConnectionFailed(format!("HTTP/1.1 parse error: {e}")))?;

    if parse_result.is_partial() {
        return Err(Error::ConnectionFailed(
            "Incomplete HTTP/1.1 response headers".into(),
        ));
    }

    let status = response.code.unwrap_or(0);
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_lowercase(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect();

    let body_start = header_end + 4;
    let remaining = buf[body_start..].to_vec();

    Ok((status, headers, remaining))
}

/// Read an HTTP/1.1 response from the stream.
///
/// Phase 1: Read headers (up to `\r\n\r\n`).
/// Phase 2: Read body based on Transfer-Encoding or Content-Length.
pub(crate) async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<RawResponse, Error> {
    let (status, headers, remaining) = read_raw_headers(stream).await?;

    // Phase 2: Read body
    let is_chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));

    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.trim().parse().ok());

    let body = if is_chunked {
        read_chunked_body(stream, &remaining).await?
    } else if let Some(len) = content_length {
        read_content_length_body(stream, &remaining, len).await?
    } else {
        read_until_close(stream, &remaining).await?
    };

    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

/// Read exactly `content_length` bytes of body.
async fn read_content_length_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    initial: &[u8],
    content_length: usize,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(initial);

    if body.len() >= content_length {
        body.truncate(content_length);
        return Ok(body);
    }

    let remaining = content_length - body.len();
    let mut limited = stream.take(remaining as u64);
    tokio::io::copy(&mut limited, &mut body).await?;

    if body.len() < content_length {
        return Err(Error::ConnectionFailed(format!(
            "Connection closed after {} bytes, expected {}",
            body.len(),
            content_length
        )));
    }

    Ok(body)
}

/// Read chunked transfer-encoding body.
///
/// Format: `<hex-size>\r\n<data>\r\n ... 0\r\n\r\n`
async fn read_chunked_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    initial: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::from(initial);
    let mut body = Vec::new();
    let mut pos = 0;

    loop {
        // Ensure we have a chunk-size line
        loop {
            if let Some(crlf) = find_crlf(&buf[pos..]) {
                let line = &buf[pos..pos + crlf];
                let size_str = std::str::from_utf8(line)
                    .map_err(|_| Error::ConnectionFailed("Invalid chunk size encoding".into()))?
                    .trim();

                // Parse chunk size (may have chunk-extension after ';')
                let size_hex = size_str.split(';').next().unwrap_or("0").trim();
                let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|_| {
                    Error::ConnectionFailed(format!("Invalid chunk size: {size_hex}"))
                })?;

                pos += crlf + 2; // skip size line + \r\n

                if chunk_size == 0 {
                    // Terminal chunk — done
                    return Ok(body);
                }

                // Ensure we have the full chunk data + trailing \r\n
                let needed = pos + chunk_size + 2;
                while buf.len() < needed {
                    let mut tmp = [0u8; 8192];
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(Error::ConnectionFailed(
                            "Connection closed during chunked body".into(),
                        ));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                body.extend_from_slice(&buf[pos..pos + chunk_size]);
                pos += chunk_size + 2; // skip data + \r\n

                break; // continue outer loop for next chunk
            }

            // Need more data for chunk size line
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed before chunk size".into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

/// Read until connection close (fallback when no Content-Length or chunked).
async fn read_until_close<S: AsyncRead + Unpin>(
    stream: &mut S,
    initial: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::from(initial);
    let mut tmp = [0u8; 8192];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    Ok(body)
}

/// Find the position of `\r\n\r\n` in a byte slice.
/// Returns the index of the first `\r` if found.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Find the position of `\r\n` in a byte slice.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Response from reading only the HTTP headers (used for WebSocket upgrade).
/// Stops reading at `\r\n\r\n` and returns any leftover bytes.
pub(crate) struct UpgradeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub leftover: Vec<u8>,
}

/// Read only the HTTP/1.1 response headers, stopping at `\r\n\r\n`.
///
/// Unlike `read_response()`, this does NOT read the body. Any bytes read
/// past the header boundary are returned as `leftover` — critical for
/// WebSocket where those bytes may already be WebSocket frames.
pub(crate) async fn read_response_headers<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<UpgradeResponse, Error> {
    let (status, headers, leftover) = read_raw_headers(stream).await?;
    Ok(UpgradeResponse {
        status,
        headers,
        leftover,
    })
}

/// Stream a chunked transfer-encoded body through a channel.
/// Each decoded chunk is sent individually.
pub(crate) async fn stream_chunked_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    initial: &[u8],
    tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, crate::error::Error>>,
) {
    let mut buf = Vec::from(initial);
    let mut pos = 0;

    loop {
        // Ensure we have a chunk-size line
        loop {
            if let Some(crlf) = find_crlf(&buf[pos..]) {
                let line = &buf[pos..pos + crlf];
                let size_str = match std::str::from_utf8(line) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => {
                        let _ = tx
                            .send(Err(crate::error::Error::ConnectionFailed(
                                "Invalid chunk size encoding".into(),
                            )))
                            .await;
                        return;
                    }
                };

                let size_hex = size_str.split(';').next().unwrap_or("0").trim();
                let chunk_size = match usize::from_str_radix(size_hex, 16) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = tx
                            .send(Err(crate::error::Error::ConnectionFailed(
                                format!("Invalid chunk size: {size_hex}"),
                            )))
                            .await;
                        return;
                    }
                };

                pos += crlf + 2;

                if chunk_size == 0 {
                    return; // Terminal chunk
                }

                // Ensure we have the full chunk data + trailing \r\n
                let needed = pos + chunk_size + 2;
                while buf.len() < needed {
                    let mut tmp = [0u8; 8192];
                    match stream.read(&mut tmp).await {
                        Ok(0) => {
                            let _ = tx
                                .send(Err(crate::error::Error::ConnectionFailed(
                                    "Connection closed during chunked body".into(),
                                )))
                                .await;
                            return;
                        }
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(e) => {
                            let _ = tx.send(Err(crate::error::Error::Io(e))).await;
                            return;
                        }
                    }
                }

                let chunk = buf[pos..pos + chunk_size].to_vec();
                pos += chunk_size + 2;

                if tx.send(Ok(chunk)).await.is_err() {
                    return; // Receiver dropped
                }

                break;
            }

            // Need more data
            let mut tmp = [0u8; 4096];
            match stream.read(&mut tmp).await {
                Ok(0) => {
                    let _ = tx
                        .send(Err(crate::error::Error::ConnectionFailed(
                            "Connection closed before chunk size".into(),
                        )))
                        .await;
                    return;
                }
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) => {
                    let _ = tx.send(Err(crate::error::Error::Io(e))).await;
                    return;
                }
            }
        }
    }
}

/// Stream a content-length body through a channel in 8KB chunks.
pub(crate) async fn stream_content_length_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    initial: &[u8],
    content_length: usize,
    tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, crate::error::Error>>,
) {
    let mut sent = 0usize;

    // Send initial bytes
    if !initial.is_empty() {
        let to_send = initial.len().min(content_length);
        if tx.send(Ok(initial[..to_send].to_vec())).await.is_err() {
            return;
        }
        sent += to_send;
    }

    // Read remaining
    let mut tmp = [0u8; 8192];
    while sent < content_length {
        let to_read = (content_length - sent).min(tmp.len());
        match stream.read(&mut tmp[..to_read]).await {
            Ok(0) => {
                let _ = tx
                    .send(Err(crate::error::Error::ConnectionFailed(format!(
                        "Connection closed after {sent} bytes, expected {content_length}"
                    ))))
                    .await;
                return;
            }
            Ok(n) => {
                sent += n;
                if tx.send(Ok(tmp[..n].to_vec())).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(crate::error::Error::Io(e))).await;
                return;
            }
        }
    }
}

/// Stream body until connection close through a channel.
pub(crate) async fn stream_until_close<S: AsyncRead + Unpin>(
    stream: &mut S,
    initial: &[u8],
    tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, crate::error::Error>>,
) {
    if !initial.is_empty() && tx.send(Ok(initial.to_vec())).await.is_err() {
        return;
    }

    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) => return,
            Ok(n) => {
                if tx.send(Ok(tmp[..n].to_vec())).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(crate::error::Error::Io(e))).await;
                return;
            }
        }
    }
}

/// Read HTTP/1.1 response headers and return parsed headers + leftover body bytes.
/// This is like `read_response` but stops after headers — for streaming.
pub(crate) async fn read_response_for_streaming<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Error> {
    read_raw_headers(stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

    #[tokio::test]
    async fn test_write_simple_get() {
        let uri: Uri = "https://example.com/path?q=1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );
        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("*/*"),
        );

        let mut buf = Vec::new();
        write_request(&mut buf, &Method::GET, &uri, &headers, None)
            .await
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(output.contains("host: example.com\r\n"));
        assert!(output.contains("accept: */*\r\n"));
        assert!(output.ends_with("\r\n\r\n"));
        // No content-length for GET without body
        assert!(!output.contains("content-length"));
    }

    #[tokio::test]
    async fn test_write_post_with_body() {
        let uri: Uri = "https://example.com/api".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );

        let body = b"hello world";
        let mut buf = Vec::new();
        write_request(&mut buf, &Method::POST, &uri, &headers, Some(body))
            .await
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("POST /api HTTP/1.1\r\n"));
        assert!(output.contains("content-length: 11\r\n"));
        assert!(output.ends_with("hello world"));
    }

    #[tokio::test]
    async fn test_parse_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                     content-type: text/plain\r\n\
                     content-length: 5\r\n\
                     \r\n\
                     hello";

        let mut cursor = &raw[..];
        let resp = read_response(&mut cursor).await.unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(resp.headers[0], ("content-type".to_string(), "text/plain".to_string()));
        assert_eq!(resp.headers[1], ("content-length".to_string(), "5".to_string()));
        assert_eq!(resp.body, b"hello");
    }

    #[tokio::test]
    async fn test_parse_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                     transfer-encoding: chunked\r\n\
                     \r\n\
                     5\r\nhello\r\n\
                     6\r\n world\r\n\
                     0\r\n\r\n";

        let mut cursor = &raw[..];
        let resp = read_response(&mut cursor).await.unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
    }

    #[tokio::test]
    async fn test_parse_empty_body() {
        let raw = b"HTTP/1.1 204 No Content\r\n\
                     content-length: 0\r\n\
                     \r\n";

        let mut cursor = &raw[..];
        let resp = read_response(&mut cursor).await.unwrap();

        assert_eq!(resp.status, 204);
        assert_eq!(resp.body, b"");
    }

    #[tokio::test]
    async fn test_parse_304_no_body() {
        let raw = b"HTTP/1.1 304 Not Modified\r\n\
                     content-length: 0\r\n\
                     \r\n";

        let mut cursor = &raw[..];
        let resp = read_response(&mut cursor).await.unwrap();

        assert_eq!(resp.status, 304);
        assert_eq!(resp.body, b"");
    }
}
