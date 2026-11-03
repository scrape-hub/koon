use std::fmt::Write as FmtWrite;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use http::Method;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::request_body::{ByteStream, LengthCheck, stream_error};
use crate::error::Error;

const READ_BUF_SIZE: usize = 32 * 1024;
const MIN_READ_SPACE: usize = 4 * 1024;
const MAX_MERGED_HEAD_AND_BODY: usize = 1400;
pub const MAX_HEADER_SIZE: usize = 256 * 1024;
const MAX_CHUNK_LINE: usize = 4096;

pub struct ResponseHead {
    pub status: u16,
    pub minor_version: u8,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    Empty,
    Chunked,
    Length(u64),
    UntilClose,
}

impl ResponseHead {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn tokens(&self, name: &str) -> Vec<String> {
        self.header_values(name)
            .flat_map(|v| v.split(','))
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    }

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
            return Ok(if codings.last().map(String::as_str) == Some("chunked") {
                BodyFraming::Chunked
            } else {
                BodyFraming::UntilClose
            });
        }

        let mut length: Option<u64> = None;
        for value in self.header_values("content-length") {
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

    pub(crate) fn keep_alive(&self, framing: BodyFraming) -> bool {
        if framing == BodyFraming::UntilClose || self.status == 101 {
            return false;
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestFraming {
    None,
    Length(u64),
    Chunked,
}

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
        if chunk.is_empty() {
            continue;
        }
        check.chunk(chunk.len())?;
        if framing == RequestFraming::Chunked {
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

pub struct BodyReader<S> {
    stream: S,
    buf: BytesMut,
    received: bool,
}

impl<S: AsyncRead + Unpin> BodyReader<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self::with_buffer(stream, BytesMut::new())
    }

    pub(crate) fn with_buffer(stream: S, buffered: BytesMut) -> Self {
        Self {
            stream,
            received: !buffered.is_empty(),
            buf: buffered,
        }
    }

    async fn fill(&mut self) -> Result<bool, Error> {
        if self.buf.capacity() - self.buf.len() < MIN_READ_SPACE {
            self.buf.reserve(READ_BUF_SIZE);
        }
        let read = self.stream.read_buf(&mut self.buf).await?;
        self.received |= read > 0;
        Ok(read > 0)
    }

    pub(crate) fn received(&self) -> bool {
        self.received
    }

    fn take(&mut self, max: u64) -> Bytes {
        let n = usize::try_from(max)
            .unwrap_or(usize::MAX)
            .min(self.buf.len());
        self.buf.split_to(n).freeze()
    }

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

    pub(crate) fn into_parts(self) -> (S, Bytes) {
        (self.stream, self.buf.freeze())
    }
}

pub enum BodyState {
    Length(u64),
    Chunked(Chunk),
    UntilClose,
    Done,
}

#[derive(Clone, Copy)]
pub enum Chunk {
    Size,
    Data(u64),
    DataEnd,
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

fn parse_chunk_size(line: &[u8]) -> Result<u64, Error> {
    let size = line.split(|&b| b == b';').next().unwrap_or(&[]);
    let size = trim_ows(size);
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

pub struct ParsedHead {
    pub status: u16,
    pub minor_version: u8,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

pub fn parse_head(head: &[u8]) -> Result<ParsedHead, httparse::Error> {
    let mut config = httparse::ParserConfig::default();
    config
        .allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .allow_space_before_first_header_name(true)
        .allow_obsolete_multiline_headers_in_responses(true)
        .ignore_invalid_headers_in_responses(true);
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

pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

pub struct UpgradeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub leftover: Bytes,
}

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
