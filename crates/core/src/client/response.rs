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
}

impl HttpResponse {
    /// Decode the response body as text: the Content-Type charset, else UTF-8.
    ///
    /// A valid UTF-8 body is borrowed, not copied.
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        decode_body_text(&self.body, header_value(&self.headers, "content-type"))
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

/// Parse the charset value from a Content-Type header string. E.g. `"text/html; charset=shift_jis"`
/// → `Some("shift_jis")`.
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

/// Estimate the serialized size of HTTP headers.
///
/// Each header contributes `name.len() + ": ".len() + value.len() + "\r\n".len()`.
/// Adds a fixed overhead for the status line / pseudo-headers (~32 bytes).
pub(crate) fn estimate_headers_size(headers: &[(String, String)]) -> u64 {
    let mut size: u64 = 32; // status line / pseudo-header overhead
    for (name, value) in headers {
        size += name.len() as u64 + value.len() as u64 + 4; // ": " + "\r\n"
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

/// Undo the content codings of a response body (RFC 9110 §8.4) with a [`ContentDecoder`]. An empty
/// body (HEAD, 204, 304) is returned as is, and so is a body with a coding koon cannot decode. `max`
/// caps the decoded size (see [`ContentDecoder::limit`]) — a decompression bomb is then caught by
/// its decoded size, independent of how small the compressed `data` is.
///
/// # Errors
/// [`Error::Body`] once decoding crosses `max` bytes, [`Error::Io`] for data that does not decode.
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
    /// One stage per coding, in decoding order (the last coding applied first).
    stages: Vec<Stage>,
    /// Whether any of the body has arrived: an empty body (HEAD, 204, 304) is no truncated stream.
    started: bool,
    /// Bytes decoded so far, checked against `max` after every [`decode`](Self::decode)/
    /// [`finish`](Self::finish) call.
    decoded: u64,
    /// Set with [`limit`](Self::limit); `u64::MAX` (no cap) otherwise.
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
            decoded: 0,
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
    /// [`finish`](Self::finish) call; past it they fail with [`Error::Body`] instead of decoding
    /// further, which also catches a decompression bomb whose compressed size is far under `max`.
    #[must_use]
    pub fn limit(mut self, max: u64) -> Self {
        self.max = max;
        self
    }

    /// Decode the next piece of the body, returning what it decodes to so far (may be empty).
    ///
    /// # Errors
    /// [`Error::Io`] on data that does not decode, [`Error::Body`] once the total decoded so far
    /// (see [`limit`](Self::limit)) exceeds `max`.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        self.started = true;
        let (first, later) = self
            .stages
            .split_first_mut()
            .expect("a decoder has a stage per coding");
        let mut decoded = first.decode(data)?;
        for stage in later {
            decoded = stage.decode(&decoded)?;
        }
        self.check_limit(decoded.len())?;
        Ok(decoded)
    }

    /// Accounts for `len` more decoded bytes; [`Error::Body`] once the running total exceeds `max`.
    fn check_limit(&mut self, len: usize) -> Result<(), Error> {
        self.decoded += len as u64;
        if self.decoded > self.max {
            return Err(Error::Body(
                format!("decompressed response body exceeded {} bytes", self.max),
                None,
            ));
        }
        Ok(())
    }

    /// End the body, returning the rest of what it decodes to.
    ///
    /// # Errors
    /// [`Error::Io`] if a gzip, brotli or zstd stream is incomplete (cut off); [`Error::Body`] once
    /// the total decoded (see [`limit`](Self::limit)) exceeds `max`.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if !self.started {
            return Ok(Vec::new());
        }
        let mut rest = Vec::new();
        for stage in &mut self.stages {
            let mut out = stage.decode(&rest)?;
            out.extend(stage.finish()?);
            rest = out;
        }
        self.check_limit(rest.len())?;
        Ok(rest)
    }
}

/// The decoder for one content coding. Each writes into its own buffer, which is emptied after
/// every call.
enum Stage {
    Gzip(flate2::write::MultiGzDecoder<Vec<u8>>),
    Deflate(Deflate),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(Box<zstd::stream::zio::Writer<Vec<u8>, zstd::stream::raw::Decoder<'static>>>),
}

impl Stage {
    fn new(coding: &str) -> Option<Self> {
        Some(match coding {
            "gzip" | "x-gzip" => Self::Gzip(flate2::write::MultiGzDecoder::new(Vec::new())),
            "deflate" => Self::Deflate(Deflate::Undecided(Vec::new())),
            "br" => Self::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 8192))),
            "zstd" => Self::Zstd(Box::new(zstd::stream::zio::Writer::new(
                Vec::new(),
                zstd::stream::raw::Decoder::new().ok()?,
            ))),
            _ => return None,
        })
    }

    fn decode(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write;
        match self {
            Self::Gzip(decoder) => {
                feed(decoder, data)?;
                decoder.flush()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Deflate(deflate) => deflate.decode(data),
            Self::Brotli(decoder) => {
                feed(decoder.as_mut(), data)?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Zstd(decoder) => {
                feed(decoder.as_mut(), data)?;
                decoder.flush()?;
                Ok(std::mem::take(decoder.writer_mut()))
            }
        }
    }

    /// The output still pending at the end of the stream; an error if the stream is incomplete.
    fn finish(&mut self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Gzip(decoder) => {
                decoder.try_finish()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Deflate(deflate) => deflate.finish(),
            Self::Brotli(decoder) => {
                decoder.close()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Zstd(decoder) => {
                decoder.finish()?;
                Ok(std::mem::take(decoder.writer_mut()))
            }
        }
    }
}

/// Write `data` to a decoder up to the end of its stream: once the stream is complete, it takes no
/// more, and what follows is ignored (as reading decoders ignore it).
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

/// HTTP `deflate`: zlib-wrapped (RFC 1950) as specified, or raw deflate as some servers send it,
/// told apart by the zlib header in the first two bytes.
enum Deflate {
    /// Fewer than two bytes have arrived.
    Undecided(Vec<u8>),
    Zlib(flate2::write::ZlibDecoder<Vec<u8>>),
    Raw(flate2::write::DeflateDecoder<Vec<u8>>),
}

impl Deflate {
    fn decode(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write;
        match self {
            Self::Undecided(head) => {
                head.extend_from_slice(data);
                if head.len() < 2 {
                    return Ok(Vec::new());
                }
                let head = std::mem::take(head);
                let (cmf, flg) = (u16::from(head[0]), u16::from(head[1]));
                *self = if cmf & 0x0f == 8 && ((cmf << 8) | flg) % 31 == 0 {
                    Self::Zlib(flate2::write::ZlibDecoder::new(Vec::new()))
                } else {
                    Self::Raw(flate2::write::DeflateDecoder::new(Vec::new()))
                };
                self.decode(&head)
            }
            Self::Zlib(decoder) => {
                feed(decoder, data)?;
                decoder.flush()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Raw(decoder) => {
                feed(decoder, data)?;
                decoder.flush()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
        }
    }

    fn finish(&mut self) -> std::io::Result<Vec<u8>> {
        match self {
            // A single byte is no zlib stream.
            Self::Undecided(head) => {
                let head = std::mem::take(head);
                *self = Self::Raw(flate2::write::DeflateDecoder::new(Vec::new()));
                let mut out = self.decode(&head)?;
                out.extend(self.finish()?);
                Ok(out)
            }
            Self::Zlib(decoder) => {
                decoder.try_finish()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Raw(decoder) => {
                decoder.try_finish()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// [`decompress_body`] without a cap, for tests that aren't about the cap itself.
    fn decompress(data: Vec<u8>, encoding: Option<&str>) -> Result<Vec<u8>, Error> {
        decompress_body(data, encoding, u64::MAX)
    }

    #[test]
    fn test_empty_body_with_encoding_is_not_an_error() {
        for enc in ["gzip", "br", "zstd", "deflate"] {
            assert_eq!(decompress(Vec::new(), Some(enc)).unwrap(), b"");
        }
    }

    #[test]
    fn test_encoding_name_is_case_insensitive_and_trimmed() {
        assert_eq!(decompress(gzip(b"hi"), Some(" GZIP ")).unwrap(), b"hi");
        assert_eq!(decompress(gzip(b"hi"), Some("x-gzip")).unwrap(), b"hi");
    }

    #[test]
    fn test_stacked_codings_are_undone_in_reverse() {
        let twice = gzip(&gzip(b"payload"));
        assert_eq!(decompress(twice, Some("gzip, gzip")).unwrap(), b"payload");
    }

    #[test]
    fn test_unknown_coding_leaves_body() {
        assert_eq!(
            decompress(b"raw".to_vec(), Some("compress")).unwrap(),
            b"raw"
        );
        assert!(ContentDecoder::new("gzip, compress").is_none());
        assert!(ContentDecoder::new("identity").is_none());
        assert!(ContentDecoder::new("").is_none());
    }

    /// A small compressed body that decodes past the cap fails, whether the cap is crossed within
    /// one `decode()` call or only once `finish()` releases what a stream held back.
    #[test]
    fn test_decompress_body_enforces_the_cap_on_decoded_size() {
        let text = b"x".repeat(1 << 16); // compresses to well under 100 bytes
        for (encoding, encoded) in encodings(&text) {
            assert!(encoded.len() < 200, "{encoding}: {}", encoded.len());
            let err = decompress_body(encoded, Some(encoding), 100).unwrap_err();
            assert_eq!(err.code(), "BODY_ERROR", "{encoding}");
        }
        // Under the cap: still decodes fully.
        assert_eq!(
            decompress_body(gzip(b"hi"), Some("gzip"), 2).unwrap(),
            b"hi"
        );
        assert!(decompress_body(gzip(b"hi"), Some("gzip"), 1).is_err());
    }

    /// `text` in every coding koon decodes, with the Content-Encoding value.
    fn encodings(text: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(text).unwrap();
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(text).unwrap();
        let mut br = Vec::new();
        brotli::BrotliCompress(&mut &text[..], &mut br, &Default::default()).unwrap();
        vec![
            ("gzip", gzip(text)),
            ("deflate", zlib.finish().unwrap()),
            ("deflate", raw.finish().unwrap()),
            ("zstd", zstd::encode_all(text, 3).unwrap()),
            ("br", br),
        ]
    }

    #[test]
    fn test_content_decoder_decodes_every_coding_piece_by_piece() {
        let text = b"hello hello hello hello decoder".repeat(50);
        for (encoding, encoded) in encodings(&text) {
            let mut decoder = ContentDecoder::new(encoding).unwrap();
            let mut decoded = Vec::new();
            // One byte at a time, like the worst possible chunking.
            for byte in &encoded {
                decoded.extend(decoder.decode(&[*byte]).unwrap());
            }
            decoded.extend(decoder.finish().unwrap());
            assert_eq!(decoded, text, "{encoding}");

            assert_eq!(
                decompress(encoded, Some(encoding)).unwrap(),
                text,
                "{encoding}"
            );
        }
    }

    #[test]
    fn test_truncated_body_fails() {
        let text = b"a body that is cut off before its end".repeat(20);
        for (encoding, encoded) in encodings(&text) {
            // zlib and raw deflate have no end marker the decoder insists on.
            if encoding == "deflate" {
                continue;
            }
            let cut = encoded[..encoded.len() - 4].to_vec();
            assert!(decompress(cut, Some(encoding)).is_err(), "{encoding}");
        }
    }

    #[test]
    fn test_for_headers_finds_the_content_encoding() {
        let headers = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Content-Encoding".to_string(), "GZIP".to_string()),
        ];
        let mut decoder = ContentDecoder::for_headers(&headers).unwrap();
        let mut body = decoder.decode(&gzip(b"hi")).unwrap();
        body.extend(decoder.finish().unwrap());
        assert_eq!(body, b"hi");
        assert!(ContentDecoder::for_headers(&headers[..1]).is_none());
    }
}
