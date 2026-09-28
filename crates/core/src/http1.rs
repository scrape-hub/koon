use std::fmt::Write as FmtWrite;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use http::Method;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::request_body::{ByteStream, LengthCheck, stream_error};
use crate::error::Error;

/// Space reserved for reading from the connection; a read into less free space than
/// [`MIN_READ_SPACE`] reserves a new block of this size.
const READ_BUF_SIZE: usize = 32 * 1024;
const MIN_READ_SPACE: usize = 4 * 1024;
/// Largest request whose head and body go out in one write (Chromium's
/// `kMaxMergedHeaderAndBodySize`).
const MAX_MERGED_HEAD_AND_BODY: usize = 1400;
/// Largest response head (and trailer section), as in Chrome's `HttpStreamParser`
/// (`kMaxHeaderBufSize`).
pub const MAX_HEADER_SIZE: usize = 256 * 1024;
/// Longest accepted chunk-size line, chunk extensions included.
const MAX_CHUNK_LINE: usize = 4096;

/// Status line and headers of a response.
pub struct ResponseHead {
    pub status: u16,
    /// Minor HTTP version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub minor_version: u8,
    pub headers: Vec<(String, String)>,
}

/// How the body of a response is delimited (RFC 9112 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body: HEAD responses, 1xx, 204 and 304.
    Empty,
    Chunked,
    Length(u64),
    /// Body ends when the server closes the connection.
    UntilClose,
}

impl ResponseHead {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Comma-separated tokens of all instances of a header, lowercased.
    fn tokens(&self, name: &str) -> Vec<String> {
        self.header_values(name)
            .flat_map(|v| v.split(','))
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    }

    /// Determine the body framing for a response to `method`.
    pub(crate) fn framing(&self, method: &Method) -> Result<BodyFraming, Error> {
        if *method == Method::HEAD
            || (100..200).contains(&self.status)
            || self.status == 204
            || self.status == 304
        {
            return Ok(BodyFraming::Empty);
        }

        let codings = self.tokens("transfer-encoding");
        if !codings.is_empty() {
            // Transfer-Encoding overrides Content-Length. Only a final `chunked` coding delimits
            // the body; anything else runs until the connection closes.
            return Ok(if codings.last().map(String::as_str) == Some("chunked") {
                BodyFraming::Chunked
            } else {
                BodyFraming::UntilClose
            });
        }

        let mut length: Option<u64> = None;
        for value in self.header_values("content-length") {
            // A list of identical values ("5, 5") is tolerated, as browsers do.
            for part in value.split(',') {
                let part = part.trim();
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Protocol(
                        format!("invalid Content-Length: {value}"),
                        None,
                    ));
                }
                let parsed: u64 = part.parse().map_err(|e| {
                    let message = format!("invalid Content-Length: {value}");
                    Error::Protocol(message, crate::error::boxed(e))
                })?;
                match length {
                    Some(existing) if existing != parsed => {
                        return Err(Error::Protocol(
                            "conflicting Content-Length values".into(),
                            None,
                        ));
                    }
                    _ => length = Some(parsed),
                }
            }
        }

        Ok(match length {
            Some(len) => BodyFraming::Length(len),
            None => BodyFraming::UntilClose,
        })
    }

    /// Whether the connection can be reused after this response (RFC 9112 §9.3).
    pub(crate) fn keep_alive(&self, framing: BodyFraming) -> bool {
        if framing == BodyFraming::UntilClose || self.status == 101 {
            return false;
        }
        // Transfer-Encoding together with Content-Length hints at request smuggling; the client
        // must close the connection afterwards.
        let has_te = self.header_values("transfer-encoding").next().is_some();
        let has_cl = self.header_values("content-length").next().is_some();
        if has_te && has_cl {
            return false;
        }
        let connection = self.tokens("connection");
        if connection.iter().any(|t| t == "close") {
            return false;
        }
        self.minor_version >= 1 || connection.iter().any(|t| t == "keep-alive")
    }
}

/// How the body of a request is delimited on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestFraming {
    /// No body.
    None,
    /// Content-Length.
    Length(u64),
    /// Transfer-Encoding: chunked.
    Chunked,
}

/// The request line and headers. Headers are written verbatim in the given order and casing; the
/// caller builds them to match the browser, including Host, Connection and Content-Length. A body
/// whose framing header is missing gets one appended (Content-Length, or Transfer-Encoding:
/// chunked), so it stays delimited.
fn request_head(
    method: &Method,
    target: &str,
    headers: &[(String, String)],
    framing: RequestFraming,
) -> Vec<u8> {
    let mut head = String::with_capacity(512);
    let _ = write!(head, "{method} {target} HTTP/1.1\r\n");
    let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    match framing {
        RequestFraming::Length(len) if !has("content-length") => {
            let _ = write!(head, "content-length: {len}\r\n");
        }
        RequestFraming::Chunked if !has("transfer-encoding") => {
            head.push_str("transfer-encoding: chunked\r\n");
        }
        _ => {}
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// Write an HTTP/1.1 request with an in-memory body to the stream. `target` is the request target:
/// the path, or the absolute URL when talking to an HTTP proxy (RFC 9112 §3.2.2). See
/// [`request_head`] for the headers. Like Chromium, a request whose head and body together fit in
/// [`MAX_MERGED_HEAD_AND_BODY`] bytes goes out in a single write (one TLS record); otherwise the
/// head and the body are written separately.
pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    method: &Method,
    target: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<u64, Error> {
    let framing = body.map_or(RequestFraming::None, |b| {
        RequestFraming::Length(b.len() as u64)
    });
    let mut head = request_head(method, target, headers, framing);
    let body = body.unwrap_or_default();
    let total = head.len() + body.len();
    if !body.is_empty() && total <= MAX_MERGED_HEAD_AND_BODY {
        head.extend_from_slice(body);
        stream.write_all(&head).await?;
    } else {
        stream.write_all(&head).await?;
        stream.write_all(body).await?;
    }
    stream.flush().await?;

    Ok(total as u64)
}

/// Write an HTTP/1.1 request whose body is read from `body` as the connection takes it: with
/// Content-Length when `length` is known, chunked otherwise. The head goes out on its own, as in
/// Chromium. Returns the bytes written.
pub async fn write_streaming_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    method: &Method,
    target: &str,
    headers: &[(String, String)],
    mut body: ByteStream,
    length: Option<u64>,
) -> Result<u64, Error> {
    let framing = length.map_or(RequestFraming::Chunked, RequestFraming::Length);
    let head = request_head(method, target, headers, framing);
    stream.write_all(&head).await?;
    let mut written = head.len() as u64;

    let mut check = LengthCheck::new(length);
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(stream_error)?;
        // An empty chunk would end a chunked body.
        if chunk.is_empty() {
            continue;
        }
        check.chunk(chunk.len())?;
        if framing == RequestFraming::Chunked {
            // Size line, data and CRLF in one write, like Chromium.
            let mut encoded = Vec::with_capacity(chunk.len() + 20);
            let _ = std::io::Write::write_fmt(&mut encoded, format_args!("{:x}\r\n", chunk.len()));
            encoded.extend_from_slice(&chunk);
            encoded.extend_from_slice(b"\r\n");
            stream.write_all(&encoded).await?;
            written += encoded.len() as u64;
        } else {
            stream.write_all(&chunk).await?;
            written += chunk.len() as u64;
        }
    }
    check.end()?;
    if framing == RequestFraming::Chunked {
        stream.write_all(b"0\r\n\r\n").await?;
        written += 5;
    }
    stream.flush().await?;
    Ok(written)
}

/// Buffered reader over a stream. Keeps bytes that were read past the point the parser consumed, so
/// a message can be parsed across several reads. Every read is cancellation-safe: bytes are
/// consumed from the buffer only once the piece they belong to is complete, so a caller may abandon
/// a read (a timeout) and try again later.
pub struct BodyReader<S> {
    stream: S,
    buf: BytesMut,
    /// Whether any byte came from the stream.
    received: bool,
}

impl<S: AsyncRead + Unpin> BodyReader<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self::with_buffer(stream, BytesMut::new())
    }

    /// A reader that first consumes `buffered`, bytes already read from `stream`.
    pub(crate) fn with_buffer(stream: S, buffered: BytesMut) -> Self {
        Self {
            stream,
            received: !buffered.is_empty(),
            buf: buffered,
        }
    }

    /// Read more bytes from the stream into the buffer. Returns false on EOF.
    async fn fill(&mut self) -> Result<bool, Error> {
        if self.buf.capacity() - self.buf.len() < MIN_READ_SPACE {
            self.buf.reserve(READ_BUF_SIZE);
        }
        let read = self.stream.read_buf(&mut self.buf).await?;
        self.received |= read > 0;
        Ok(read > 0)
    }

    /// Whether any byte of the response came from the stream.
    pub(crate) fn received(&self) -> bool {
        self.received
    }

    /// Up to `max` buffered bytes, without copying.
    fn take(&mut self, max: u64) -> Bytes {
        let n = usize::try_from(max)
            .unwrap_or(usize::MAX)
            .min(self.buf.len());
        self.buf.split_to(n).freeze()
    }

    /// Read one line (LF or CRLF terminated) of at most `max` bytes, without its line ending. Only
    /// the tail added by the last [`fill`](Self::fill) is scanned for the terminator: `\n` is a
    /// single byte, so nothing already scanned without a match needs re-checking.
    async fn read_line(&mut self, max: usize, what: &str) -> Result<Vec<u8>, Error> {
        let mut scanned = 0usize;
        loop {
            if let Some(lf) = self.buf[scanned..].iter().position(|&b| b == b'\n') {
                let lf = scanned + lf;
                let mut line = self.buf[..lf].to_vec();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.buf.advance(lf + 1);
                return Ok(line);
            }
            scanned = self.buf.len();
            if scanned > max {
                return Err(Error::Protocol(format!("{what} line too long"), None));
            }
            if !self.fill().await? {
                return Err(unexpected_eof(what));
            }
        }
    }

    /// Read a response head, skipping interim 1xx responses (except 101).
    pub(crate) async fn read_head(&mut self) -> Result<ResponseHead, Error> {
        loop {
            let head = self.read_one_head().await?;
            if (100..200).contains(&head.status) && head.status != 101 {
                continue;
            }
            return Ok(head);
        }
    }

    async fn read_one_head(&mut self) -> Result<ResponseHead, Error> {
        // Only the tail since the last unsuccessful scan is rescanned, rewound 3 bytes so a
        // terminator split across two `fill()` calls is still found: rescanning the whole buffer
        // from the start on every added byte would be O(n²) work for a server that trickles the
        // head in slowly.
        let mut scanned = 0usize;
        let end = loop {
            let from = scanned.saturating_sub(3);
            let end = find_header_end(&self.buf[from..]).map(|e| from + e);
            if end.unwrap_or(self.buf.len()) > MAX_HEADER_SIZE {
                return Err(Error::Protocol(
                    "response headers exceed 256 KB".into(),
                    None,
                ));
            }
            if let Some(end) = end {
                break end;
            }
            scanned = self.buf.len();
            if !self.fill().await? {
                return Err(unexpected_eof("response headers"));
            }
        };

        let head = parse_head(&self.buf[..end]).map_err(|e| {
            let message = format!("HTTP/1.1 parse error: {e}");
            Error::Protocol(message, crate::error::boxed(e))
        })?;
        self.buf.advance(end);
        Ok(ResponseHead {
            status: head.status,
            minor_version: head.minor_version,
            headers: head.headers,
        })
    }

    /// Read the next piece of a body. Returns `None` once the body is done. `state` tracks progress
    /// across calls; create it with [`BodyState::new`] from the response's framing.
    pub(crate) async fn next_body_chunk(
        &mut self,
        state: &mut BodyState,
    ) -> Result<Option<Bytes>, Error> {
        loop {
            match state {
                BodyState::Done => return Ok(None),
                BodyState::Length(remaining) => {
                    if self.buf.is_empty() && !self.fill().await? {
                        return Err(unexpected_eof("response body"));
                    }
                    let chunk = self.take(*remaining);
                    *remaining -= chunk.len() as u64;
                    if *remaining == 0 {
                        *state = BodyState::Done;
                    }
                    return Ok(Some(chunk));
                }
                BodyState::UntilClose => {
                    if self.buf.is_empty() && !self.fill().await? {
                        *state = BodyState::Done;
                        return Ok(None);
                    }
                    return Ok(Some(self.buf.split().freeze()));
                }
                BodyState::Chunked(chunk) => match *chunk {
                    Chunk::Size => {
                        let line = self.read_line(MAX_CHUNK_LINE, "chunk size").await?;
                        *chunk = match parse_chunk_size(&line)? {
                            0 => Chunk::Trailers(0),
                            size => Chunk::Data(size),
                        };
                    }
                    Chunk::Data(remaining) => {
                        if self.buf.is_empty() && !self.fill().await? {
                            return Err(unexpected_eof("chunked body"));
                        }
                        let data = self.take(remaining);
                        *chunk = match remaining - data.len() as u64 {
                            0 => Chunk::DataEnd,
                            left => Chunk::Data(left),
                        };
                        return Ok(Some(data));
                    }
                    Chunk::DataEnd => {
                        let line = self.read_line(MAX_CHUNK_LINE, "chunk terminator").await?;
                        if !line.is_empty() {
                            return Err(Error::Protocol(
                                "missing CRLF after chunk data".into(),
                                None,
                            ));
                        }
                        *chunk = Chunk::Size;
                    }
                    Chunk::Trailers(read) => {
                        let line = self.read_line(MAX_HEADER_SIZE, "trailer").await?;
                        if line.is_empty() {
                            *state = BodyState::Done;
                            return Ok(None);
                        }
                        let read = read + line.len();
                        if read > MAX_HEADER_SIZE {
                            return Err(Error::Protocol(
                                "trailer section exceeds 256 KB".into(),
                                None,
                            ));
                        }
                        *chunk = Chunk::Trailers(read);
                    }
                },
            }
        }
    }

    /// The stream, and the bytes read from it but not consumed.
    pub(crate) fn into_parts(self) -> (S, Bytes) {
        (self.stream, self.buf.freeze())
    }
}

/// Progress through a response body.
pub enum BodyState {
    /// Remaining bytes of a Content-Length body.
    Length(u64),
    Chunked(Chunk),
    UntilClose,
    Done,
}

/// What comes next in a chunked body. Each step is complete before the next begins, so an abandoned
/// read resumes where it stopped.
#[derive(Clone, Copy)]
pub enum Chunk {
    /// A chunk-size line.
    Size,
    /// Data of the current chunk, with this many bytes left.
    Data(u64),
    /// The CRLF after a chunk's data.
    DataEnd,
    /// The trailer section, of which this many bytes were read.
    Trailers(usize),
}

impl BodyState {
    pub(crate) fn new(framing: BodyFraming) -> Self {
        match framing {
            BodyFraming::Empty | BodyFraming::Length(0) => Self::Done,
            BodyFraming::Length(n) => Self::Length(n),
            BodyFraming::Chunked => Self::Chunked(Chunk::Size),
            BodyFraming::UntilClose => Self::UntilClose,
        }
    }
}

/// Parse a chunk-size line: hex digits, optionally followed by chunk extensions after `;` (RFC 9112
/// §7.1.1).
fn parse_chunk_size(line: &[u8]) -> Result<u64, Error> {
    let size = line.split(|&b| b == b';').next().unwrap_or(&[]);
    let size = trim_ows(size);
    // 15 hex digits keep the value far below u64::MAX, so later additions cannot overflow.
    if size.is_empty() || size.len() > 15 || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Protocol(
            format!("invalid chunk size: {}", String::from_utf8_lossy(line)),
            None,
        ));
    }
    let digits = std::str::from_utf8(size).expect("hex digits are ASCII");
    Ok(u64::from_str_radix(digits, 16).expect("validated hex"))
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = bytes.iter().position(|b| !is_ows(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_ows(b))
        .map_or(start, |p| p + 1);
    &bytes[start..end]
}

fn unexpected_eof(what: &str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        format!("connection closed while reading {what}"),
    ))
}

/// A parsed response head.
pub struct ParsedHead {
    pub status: u16,
    pub minor_version: u8,
    pub reason: String,
    /// Names in lowercase; values decoded lossily, folded lines joined.
    pub headers: Vec<(String, String)>,
}

/// Parse a complete response head (up to and including the blank line) as leniently as browsers do:
/// whitespace after header names, several spaces in the status line, whitespace before the first
/// header, obsolete line folding (joined with spaces, as Chrome's `HttpUtil::AssembleRawHeaders`
/// does), and malformed header lines, which are skipped. There is no limit on the number of headers
/// besides [`MAX_HEADER_SIZE`].
pub fn parse_head(head: &[u8]) -> Result<ParsedHead, httparse::Error> {
    let mut config = httparse::ParserConfig::default();
    config
        .allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .allow_space_before_first_header_name(true)
        .allow_obsolete_multiline_headers_in_responses(true)
        .ignore_invalid_headers_in_responses(true);
    // Every header takes at least one line.
    let lines = head.iter().filter(|&&b| b == b'\n').count();
    let mut slots = vec![httparse::EMPTY_HEADER; lines.max(1)];
    let mut response = httparse::Response::new(&mut slots);
    if config.parse_response(&mut response, head)?.is_partial() {
        return Err(httparse::Error::Token);
    }
    let headers = response
        .headers
        .iter()
        .map(|h| {
            let value = String::from_utf8_lossy(h.value);
            let value = if value.contains(['\r', '\n']) {
                let folded: Vec<&str> = value.split(['\r', '\n']).map(str::trim).collect();
                folded
                    .into_iter()
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                value.into_owned()
            };
            (h.name.to_ascii_lowercase(), value)
        })
        .collect();
    Ok(ParsedHead {
        status: response.code.unwrap_or(0),
        minor_version: response.version.unwrap_or(1),
        reason: response.reason.unwrap_or("").to_string(),
        headers,
    })
}

/// Find the end of the header section (index just past the blank line).
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Response from reading only the HTTP headers (used for WebSocket upgrade). Stops reading at the
/// end of the header section and returns any leftover bytes.
pub struct UpgradeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub leftover: Bytes,
}

/// Read only the HTTP/1.1 response headers. The body is not read. Bytes read past the header
/// section are returned as `leftover`: after a WebSocket upgrade they may already be frames.
pub async fn read_response_headers<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<UpgradeResponse, Error> {
    let mut reader = BodyReader::new(stream);
    let head = reader.read_head().await?;
    let (_, leftover) = reader.into_parts();
    Ok(UpgradeResponse {
        status: head.status,
        headers: head.headers,
        leftover,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use http::Method;

    struct RawResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        keep_alive: bool,
    }

    /// Read a complete HTTP/1.1 response to a request with `method`.
    async fn read_response<S: AsyncRead + Unpin>(
        stream: &mut S,
        method: &Method,
    ) -> Result<RawResponse, Error> {
        let mut reader = BodyReader::new(stream);
        let head = reader.read_head().await?;
        let framing = head.framing(method)?;

        let mut body = match framing {
            BodyFraming::Length(n) => Vec::with_capacity((n as usize).min(1 << 20)),
            _ => Vec::new(),
        };
        let mut state = BodyState::new(framing);
        while let Some(chunk) = reader.next_body_chunk(&mut state).await? {
            body.extend_from_slice(&chunk);
        }

        Ok(RawResponse {
            status: head.status,
            keep_alive: head.keep_alive(framing),
            headers: head.headers,
            body,
        })
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    async fn parse(raw: &[u8], method: Method) -> Result<RawResponse, Error> {
        let mut cursor = raw;
        read_response(&mut cursor, &method).await
    }

    /// Heads browsers accept: whitespace after a header name, several spaces in the status line, a
    /// folded header, a malformed line (skipped) and more headers than a fixed array would hold.
    #[tokio::test]
    async fn lenient_response_heads_parse() {
        let mut raw = b"HTTP/1.1  200  OK\r\nContent-Type : text/plain\r\nX-Folded: a\r\n  b\r\nnot a header\r\n".to_vec();
        for i in 0..300 {
            raw.extend_from_slice(format!("x-h{i}: {i}\r\n").as_bytes());
        }
        raw.extend_from_slice(b"Content-Length: 2\r\n\r\nok");
        let resp = parse(&raw, Method::GET).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        let get = |name: &str| {
            resp.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("content-type"), Some("text/plain"));
        assert_eq!(get("x-folded"), Some("a b"));
        assert_eq!(get("x-h299"), Some("299"));
        assert_eq!(resp.headers.len(), 303);
    }

    /// Response heads up to 256 KB are read, larger ones fail.
    #[tokio::test]
    async fn response_heads_up_to_256_kb() {
        let big = |size: usize| {
            let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nx-big: ".to_vec();
            raw.resize(size, b'a');
            raw.extend_from_slice(b"\r\n\r\n");
            raw
        };
        assert_eq!(
            parse(&big(200 * 1024), Method::GET).await.unwrap().status,
            200
        );
        assert!(parse(&big(300 * 1024), Method::GET).await.is_err());
    }

    /// A reader that yields at most one byte per `poll_read`, regardless of the buffer offered:
    /// the worst-case pacing a hostile or merely slow server can force on `fill()`.
    struct OneByteAtATime(std::io::Cursor<Vec<u8>>);

    impl AsyncRead for OneByteAtATime {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let mut byte = [0u8; 1];
            let n = std::io::Read::read(&mut self.0, &mut byte).unwrap();
            if n > 0 {
                buf.put_slice(&byte[..n]);
            }
            Poll::Ready(Ok(()))
        }
    }

    /// A response head arriving one byte at a time is still parsed correctly (the terminator's
    /// bytes each land in a separate `fill()` call), and the whole read stays roughly linear in the
    /// head's size: rescanning the accumulated buffer from the start on every added byte (the O(n²)
    /// bug this guards against) would turn this into tens of billions of comparisons.
    #[tokio::test]
    async fn response_head_arriving_one_byte_at_a_time_is_linear_time() {
        let mut raw = b"HTTP/1.1 200 OK\r\nx-big: ".to_vec();
        raw.resize(raw.len() + 200 * 1024, b'a');
        raw.extend_from_slice(b"\r\n\r\n");

        let mut reader = BodyReader::new(OneByteAtATime(std::io::Cursor::new(raw)));
        let started = std::time::Instant::now();
        let head = reader.read_head().await.unwrap();
        assert_eq!(head.status, 200);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}: looks like the header buffer is rescanned from the start on every byte",
            started.elapsed()
        );
    }

    /// Same pacing, but for the trailer section's line-by-line reader (`read_line`), which has the
    /// same rescan hazard.
    #[tokio::test]
    async fn chunked_trailer_arriving_one_byte_at_a_time_is_linear_time() {
        let mut raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n0\r\nx-big: ".to_vec();
        raw.resize(raw.len() + 200 * 1024, b'a');
        raw.extend_from_slice(b"\r\n\r\n");

        let mut reader = BodyReader::new(OneByteAtATime(std::io::Cursor::new(raw)));
        let head = reader.read_head().await.unwrap();
        let mut state = BodyState::new(head.framing(&Method::GET).unwrap());
        let started = std::time::Instant::now();
        assert!(reader.next_body_chunk(&mut state).await.unwrap().is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}: looks like the trailer buffer is rescanned from the start on every byte",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn test_write_simple_get() {
        let hdrs = headers(&[("Host", "example.com"), ("Accept", "*/*")]);

        let mut buf = Vec::new();
        let bytes_sent = write_request(&mut buf, &Method::GET, "/path?q=1", &hdrs, None)
            .await
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        );
        assert_eq!(bytes_sent, output.len() as u64);
    }

    #[tokio::test]
    async fn test_write_post_adds_missing_content_length() {
        let hdrs = headers(&[("Host", "example.com")]);
        let mut buf = Vec::new();
        write_request(&mut buf, &Method::POST, "/api", &hdrs, Some(b"hello world"))
            .await
            .unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("content-length: 11\r\n"));
        assert!(output.ends_with("\r\n\r\nhello world"));
    }

    #[tokio::test]
    async fn test_write_keeps_caller_content_length() {
        let hdrs = headers(&[("Host", "example.com"), ("Content-Length", "2")]);
        let mut buf = Vec::new();
        write_request(&mut buf, &Method::POST, "/api", &hdrs, Some(b"ok"))
            .await
            .unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.matches("ontent-").count(), 1);
    }

    /// Records every write separately.
    #[derive(Default)]
    struct Writes(Vec<Vec<u8>>);

    impl AsyncWrite for Writes {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.get_mut().0.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_small_body_goes_out_with_the_head() {
        let hdrs = headers(&[("Host", "example.com")]);
        let mut writes = Writes::default();
        write_request(&mut writes, &Method::POST, "/", &hdrs, Some(b"a=1"))
            .await
            .unwrap();
        assert_eq!(writes.0.len(), 1);
        assert!(writes.0[0].ends_with(b"\r\n\r\na=1"));

        // Head and body above 1400 bytes together: two writes.
        let body = vec![b'x'; 1400];
        let mut writes = Writes::default();
        let sent = write_request(&mut writes, &Method::POST, "/", &hdrs, Some(&body))
            .await
            .unwrap();
        assert_eq!(writes.0.len(), 2);
        assert_eq!(writes.0[1], body);
        assert_eq!(sent, (writes.0[0].len() + body.len()) as u64);
    }

    #[tokio::test]
    async fn test_chunked_body_survives_abandoned_reads() {
        let (mut server, client) = tokio::io::duplex(4096);
        let mut reader = BodyReader::new(client);
        server
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello")
            .await
            .unwrap();
        let head = reader.read_head().await.unwrap();
        let mut state = BodyState::new(head.framing(&Method::GET).unwrap());
        let wait = Duration::from_millis(50);

        // A chunk is returned without waiting for the CRLF after it.
        let chunk = tokio::time::timeout(wait, reader.next_body_chunk(&mut state))
            .await
            .expect("chunk data does not wait for its CRLF")
            .unwrap();
        assert_eq!(chunk.as_deref(), Some(&b"hello"[..]));

        // The CRLF is late: the read is abandoned, then resumed.
        assert!(
            tokio::time::timeout(wait, reader.next_body_chunk(&mut state))
                .await
                .is_err()
        );
        server
            .write_all(b"\r\n6\r\n world\r\n0\r\nx-trailer: 1\r\n")
            .await
            .unwrap();
        let chunk = reader.next_body_chunk(&mut state).await.unwrap();
        assert_eq!(chunk.as_deref(), Some(&b" world"[..]));

        // The end of the trailer section is late as well.
        assert!(
            tokio::time::timeout(wait, reader.next_body_chunk(&mut state))
                .await
                .is_err()
        );
        server.write_all(b"\r\n").await.unwrap();
        assert!(reader.next_body_chunk(&mut state).await.unwrap().is_none());
        assert!(reader.into_parts().1.is_empty());
    }

    #[tokio::test]
    async fn test_parse_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello";
        let resp = parse(raw, Method::GET).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(resp.body, b"hello");
        assert!(resp.keep_alive);
    }

    #[tokio::test]
    async fn test_parse_chunked_response_with_extensions_and_trailers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n\
                    5;name=value\r\nhello\r\n6\r\n world\r\n0\r\nx-trailer: 1\r\n\r\n";
        let resp = parse(raw, Method::GET).await.unwrap();
        assert_eq!(resp.body, b"hello world");
        assert!(resp.keep_alive);
    }

    #[tokio::test]
    async fn test_chunk_size_overflow_is_an_error_not_a_panic() {
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nffffffffffffffff\r\nx";
        assert!(matches!(
            parse(raw, Method::GET).await,
            Err(Error::Protocol(..))
        ));
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
        assert!(matches!(
            parse(raw, Method::GET).await,
            Err(Error::Protocol(..))
        ));
    }

    #[tokio::test]
    async fn test_huge_content_length_does_not_preallocate() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 1099511627776\r\n\r\nabc";
        // Must fail with EOF instead of aborting on allocation.
        assert!(matches!(parse(raw, Method::GET).await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_head_response_has_no_body() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 1234\r\ncontent-encoding: br\r\n\r\n";
        let resp = parse(raw, Method::HEAD).await.unwrap();
        assert!(resp.body.is_empty());
        assert!(resp.keep_alive);
    }

    #[tokio::test]
    async fn test_304_and_204_without_length_do_not_read_until_close() {
        for status in ["304 Not Modified", "204 No Content"] {
            let raw = format!("HTTP/1.1 {status}\r\netag: \"x\"\r\n\r\n");
            let resp = parse(raw.as_bytes(), Method::GET).await.unwrap();
            assert!(resp.body.is_empty());
            assert!(resp.keep_alive, "{status}");
        }
    }

    #[tokio::test]
    async fn test_interim_responses_are_skipped() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\n\
                    HTTP/1.1 103 Early Hints\r\nlink: </a.css>; rel=preload\r\n\r\n\
                    HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
        let resp = parse(raw, Method::GET).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
    }

    #[tokio::test]
    async fn test_keep_alive_rules() {
        let resp = parse(
            b"HTTP/1.1 200 OK\r\nconnection: keep-alive, close\r\ncontent-length: 0\r\n\r\n",
            Method::GET,
        )
        .await
        .unwrap();
        assert!(!resp.keep_alive);

        let resp = parse(b"HTTP/1.0 200 OK\r\ncontent-length: 0\r\n\r\n", Method::GET)
            .await
            .unwrap();
        assert!(!resp.keep_alive);

        let resp = parse(
            b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\ncontent-length: 0\r\n\r\n",
            Method::GET,
        )
        .await
        .unwrap();
        assert!(resp.keep_alive);

        // Delimited by close: never reusable.
        let resp = parse(b"HTTP/1.1 200 OK\r\n\r\nbody", Method::GET)
            .await
            .unwrap();
        assert_eq!(resp.body, b"body");
        assert!(!resp.keep_alive);

        // Transfer-Encoding plus Content-Length: must close afterwards.
        let resp = parse(
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
            Method::GET,
        )
        .await
        .unwrap();
        assert_eq!(resp.body, b"ok");
        assert!(!resp.keep_alive);
    }

    #[tokio::test]
    async fn test_conflicting_content_length_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 3\r\n\r\nok";
        assert!(matches!(
            parse(raw, Method::GET).await,
            Err(Error::Protocol(..))
        ));
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 2, 2\r\n\r\nok";
        assert_eq!(parse(raw, Method::GET).await.unwrap().body, b"ok");
    }

    #[tokio::test]
    async fn test_truncated_body_is_eof() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort";
        assert!(matches!(parse(raw, Method::GET).await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_upgrade_headers_keep_leftover() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\r\n\x81\x02hi";
        let mut cursor = &raw[..];
        let resp = read_response_headers(&mut cursor).await.unwrap();
        assert_eq!(resp.status, 101);
        assert_eq!(resp.leftover, &b"\x81\x02hi"[..]);
    }
}
