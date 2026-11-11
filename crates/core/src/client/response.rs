use std::borrow::Cow;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;

use super::headers::header_value;

/// HTTP response with fully buffered body.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 404, 301).
    pub status: u16,
    /// Response headers as (name, value) pairs in wire order.
    pub headers: Vec<(String, String)>,
    /// Response body (decompressed).
    pub body: Vec<u8>,
    /// HTTP version used (e.g. `"h2"`, `"HTTP/1.1"`, `"h3"`).
    pub version: String,
    /// The final URL after following redirects.
    pub url: String,
    /// Approximate bytes sent for this request (headers + body, pre-TLS).
    pub bytes_sent: u64,
    /// Approximate bytes received for this response (headers + body, pre-decompression).
    pub bytes_received: u64,
    /// Whether the TLS handshake of the connection that carried this request resumed a session. A
    /// request on a reused connection reports that connection's handshake; only a new connection
    /// can be resumed.
    pub tls_resumed: bool,
    /// Whether an existing pooled connection was reused.
    pub connection_reused: bool,
    /// Remote IP address of the peer (the proxy when one is used).
    pub remote_address: Option<String>,
    /// Headers of the final request as sent, in wire order and casing. HTTP/2 and HTTP/3
    /// pseudo-headers come first.
    pub request_headers: Vec<(String, String)>,
    /// The redirect this response asks for when the client did not follow it, to follow it with
    /// [`RequestOptions::redirect`](crate::RequestOptions::redirect).
    pub redirect: Option<crate::Redirect>,
}

impl HttpResponse {
    /// Decode the response body as text: the Content-Type charset, else UTF-8.
    ///
    /// A valid UTF-8 body is borrowed, not copied.
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        decode_body_text(&self.body, header_value(&self.headers, "content-type"))
    }

    /// The bot protection that answered instead of the page, or `None` for the page itself: see
    /// [`blocked_by`](crate::blocked_by) for the values.
    #[must_use]
    pub fn blocked_by(&self) -> Option<&'static str> {
        super::blocked::blocked_by(self.status, &self.headers, &self.body, &self.url)
    }

    /// Extract the charset from the Content-Type header (e.g. `"utf-8"` from `"text/html;
    /// charset=utf-8"`). Returns `None` if no charset is specified.
    #[must_use]
    pub fn charset(&self) -> Option<&str> {
        parse_charset(header_value(&self.headers, "content-type")?)
    }
}

/// Decode a response body as text using `content_type`'s charset, falling back to UTF-8 if it has
/// none or an unknown one. A body that is valid UTF-8 (without a BOM) is borrowed; anything else is
/// decoded into a new string.
pub fn decode_body_text<'a>(body: &'a [u8], content_type: Option<&str>) -> Cow<'a, str> {
    let charset = content_type.and_then(parse_charset);
    let label = charset.unwrap_or("utf-8");
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::UTF_8);
    let (decoded, _, _) = encoding.decode(body);
    decoded
}

fn parse_charset(content_type: &str) -> Option<&str> {
    content_type.split(';').find_map(|part| {
        let part = part.trim();
        if part.len() > 8 && part[..8].eq_ignore_ascii_case("charset=") {
            Some(part[8..].trim().trim_matches('"'))
        } else {
            None
        }
    })
}

pub(crate) fn estimate_headers_size(headers: &[(String, String)]) -> u64 {
    let mut size: u64 = 32;
    for (name, value) in headers {
        size += name.len() as u64 + value.len() as u64 + 4;
    }
    size
}

/// Exported session data (cookies + TLS sessions): serialize to JSON to persist a client's session
/// across process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExport {
    /// Cookie jar contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<Vec<crate::cookie::Cookie>>,
    /// TLS session tickets: base64-encoded DER by cache key (`host:port`, plus `|proxy` for
    /// sessions through a proxy: its scheme, user name, host and port). Loading a key of another
    /// form fails.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_tls_sessions"
    )]
    pub tls_sessions: Option<HashMap<String, String>>,
}

fn deserialize_tls_sessions<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<HashMap<String, String>>, D::Error> {
    let sessions = Option::<HashMap<String, String>>::deserialize(deserializer)?;
    let invalid = sessions
        .iter()
        .flat_map(HashMap::keys)
        .find(|key| !crate::tls::session_cache::is_session_key(key));
    match invalid {
        Some(key) => Err(serde::de::Error::custom(format!(
            "invalid TLS session key `{key}`: expected `host:port`, optionally followed by \
             `|` and a proxy without password"
        ))),
        None => Ok(sessions),
    }
}

pub(crate) fn decompress_body(
    data: Vec<u8>,
    encoding: Option<&str>,
    max: u64,
) -> Result<Vec<u8>, Error> {
    let Some(mut decoder) = encoding.and_then(ContentDecoder::new).map(|d| d.limit(max)) else {
        return Ok(data);
    };
    let mut body = decoder.decode(&data)?;
    body.extend(decoder.finish()?);
    Ok(body)
}

/// Decodes a response body piece by piece for its Content-Encoding: `gzip` (also `x-gzip`),
/// `deflate` (zlib-wrapped or raw), `br` and `zstd`, including stacked codings like `gzip, br`
/// (undone in reverse order).
///
/// [`HttpResponse`] and [`StreamingResponse`](crate::StreamingResponse) use this internally; by
/// hand, pass each piece to [`decode`](Self::decode) and call [`finish`](Self::finish) at the end.
pub struct ContentDecoder {
    stages: Vec<Stage>,
    started: bool,
    max: u64,
}

impl ContentDecoder {
    /// A decoder for a Content-Encoding header value, or `None` when there is nothing to decode (no
    /// coding, or only `identity`) or a coding is unknown; the body is then used as it is. Uncapped
    /// (see [`limit`](Self::limit)) until told otherwise.
    #[must_use]
    pub fn new(content_encoding: &str) -> Option<Self> {
        let codings: Vec<String> = content_encoding
            .split(',')
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty() && c != "identity")
            .collect();
        if codings.is_empty() {
            return None;
        }
        let stages = codings
            .iter()
            .rev()
            .map(|coding| Stage::new(coding))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            stages,
            started: false,
            max: u64::MAX,
        })
    }

    /// A decoder for the Content-Encoding in `headers` (see [`new`](Self::new)).
    #[must_use]
    pub fn for_headers(headers: &[(String, String)]) -> Option<Self> {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
            .and_then(|(_, value)| Self::new(value))
    }

    /// Caps the total decoded size at `max` bytes across every [`decode`](Self::decode) and
    /// [`finish`](Self::finish) call; past it they fail with [`Error::ResponseTooLarge`] instead of
    /// decoding further, which also catches a decompression bomb whose compressed size is far under
    /// `max`.
    #[must_use]
    pub fn limit(mut self, max: u64) -> Self {
        self.max = max;
        for stage in &mut self.stages {
            stage.set_limit(max);
        }
        self
    }

    /// Decode the next piece of the body, returning what it decodes to so far (may be empty).
    ///
    /// # Errors
    /// [`Error::Io`] on data that does not decode, [`Error::ResponseTooLarge`] once the total
    /// decoded so far (see [`limit`](Self::limit)) exceeds `max`.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        self.started = true;
        let (first, later) = self
            .stages
            .split_first_mut()
            .expect("a decoder has a stage per coding");
        let max = self.max;
        let mut decoded = first.decode(data).map_err(|e| first.error(e, max))?;
        for stage in later {
            decoded = stage.decode(&decoded).map_err(|e| stage.error(e, max))?;
        }
        Ok(decoded)
    }

    /// End the body, returning the rest of what it decodes to.
    ///
    /// # Errors
    /// [`Error::Io`] if a gzip, brotli or zstd stream is incomplete (cut off);
    /// [`Error::ResponseTooLarge`] once the total decoded (see [`limit`](Self::limit)) exceeds
    /// `max`.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if !self.started {
            return Ok(Vec::new());
        }
        let max = self.max;
        let mut rest = Vec::new();
        for stage in &mut self.stages {
            let mut out = stage.decode(&rest).map_err(|e| stage.error(e, max))?;
            out.extend(stage.finish().map_err(|e| stage.error(e, max))?);
            rest = out;
        }
        Ok(rest)
    }
}

struct Capped {
    buf: Vec<u8>,
    written: u64,
    max: u64,
    exceeded: bool,
}

impl Capped {
    const fn new(max: u64) -> Self {
        Self {
            buf: Vec::new(),
            written: 0,
            max,
            exceeded: false,
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

impl std::io::Write for Capped {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.written.saturating_add(data.len() as u64);
        if written > self.max {
            self.exceeded = true;
            return Err(std::io::Error::other("decoding limit reached"));
        }
        self.written = written;
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum Stage {
    Gzip(flate2::write::MultiGzDecoder<Capped>),
    Deflate(Deflate),
    Brotli(Box<brotli::DecompressorWriter<Capped>>),
    Zstd(Box<zstd::stream::zio::Writer<Capped, zstd::stream::raw::Decoder<'static>>>),
}

impl Stage {
    fn new(coding: &str) -> Option<Self> {
        let sink = Capped::new(u64::MAX);
        Some(match coding {
            "gzip" | "x-gzip" => Self::Gzip(flate2::write::MultiGzDecoder::new(sink)),
            "deflate" => Self::Deflate(Deflate::Undecided(Vec::new(), u64::MAX)),
            "br" => Self::Brotli(Box::new(brotli::DecompressorWriter::new(sink, 8192))),
            "zstd" => Self::Zstd(Box::new(zstd::stream::zio::Writer::new(
                sink,
                zstd::stream::raw::Decoder::new().ok()?,
            ))),
            _ => return None,
        })
    }

    fn sink(&mut self) -> Option<&mut Capped> {
        match self {
            Self::Gzip(decoder) => Some(decoder.get_mut()),
            Self::Deflate(deflate) => deflate.sink(),
            Self::Brotli(decoder) => Some(decoder.get_mut()),
            Self::Zstd(decoder) => Some(decoder.writer_mut()),
        }
    }

    fn set_limit(&mut self, max: u64) {
        if let Self::Deflate(Deflate::Undecided(_, limit)) = self {
            *limit = max;
        } else if let Some(sink) = self.sink() {
            sink.max = max;
        }
    }

    fn error(&mut self, e: std::io::Error, max: u64) -> Error {
        if self.sink().is_some_and(|sink| sink.exceeded) {
            Error::ResponseTooLarge(max)
        } else {
            Error::Io(e)
        }
    }

    fn decode(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write;
        match self {
            Self::Gzip(decoder) => {
                feed(decoder, data)?;
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
            Self::Deflate(deflate) => deflate.decode(data),
            Self::Brotli(decoder) => {
                feed(decoder.as_mut(), data)?;
                Ok(decoder.get_mut().take())
            }
            Self::Zstd(decoder) => {
                feed(decoder.as_mut(), data)?;
                decoder.flush()?;
                Ok(decoder.writer_mut().take())
            }
        }
    }

    fn finish(&mut self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Gzip(decoder) => {
                decoder.try_finish()?;
                Ok(decoder.get_mut().take())
            }
            Self::Deflate(deflate) => deflate.finish(),
            Self::Brotli(decoder) => {
                decoder.close()?;
                Ok(decoder.get_mut().take())
            }
            Self::Zstd(decoder) => {
                decoder.finish()?;
                Ok(decoder.writer_mut().take())
            }
        }
    }
}

fn feed(decoder: &mut impl std::io::Write, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match decoder.write(data) {
            Ok(0) => break,
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

enum Deflate {
    Undecided(Vec<u8>, u64),
    Zlib(flate2::write::ZlibDecoder<Capped>),
    Raw(flate2::write::DeflateDecoder<Capped>),
}

impl Deflate {
    fn sink(&mut self) -> Option<&mut Capped> {
        match self {
            Self::Undecided(..) => None,
            Self::Zlib(decoder) => Some(decoder.get_mut()),
            Self::Raw(decoder) => Some(decoder.get_mut()),
        }
    }

    fn decode(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write;
        match self {
            Self::Undecided(head, max) => {
                head.extend_from_slice(data);
                if head.len() < 2 {
                    return Ok(Vec::new());
                }
                let head = std::mem::take(head);
                let sink = Capped::new(*max);
                let (cmf, flg) = (u16::from(head[0]), u16::from(head[1]));
                *self = if cmf & 0x0f == 8 && ((cmf << 8) | flg) % 31 == 0 {
                    Self::Zlib(flate2::write::ZlibDecoder::new(sink))
                } else {
                    Self::Raw(flate2::write::DeflateDecoder::new(sink))
                };
                self.decode(&head)
            }
            Self::Zlib(decoder) => {
                feed(decoder, data)?;
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
            Self::Raw(decoder) => {
                feed(decoder, data)?;
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
        }
    }

    fn finish(&mut self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Undecided(head, max) => {
                let head = std::mem::take(head);
                *self = Self::Raw(flate2::write::DeflateDecoder::new(Capped::new(*max)));
                let mut out = self.decode(&head)?;
                out.extend(self.finish()?);
                Ok(out)
            }
            Self::Zlib(decoder) => {
                decoder.try_finish()?;
                Ok(decoder.get_mut().take())
            }
            Self::Raw(decoder) => {
                decoder.try_finish()?;
                Ok(decoder.get_mut().take())
            }
        }
    }
}
