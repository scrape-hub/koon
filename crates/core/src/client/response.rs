use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;

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
    /// Whether TLS session resumption was used for this connection.
    pub tls_resumed: bool,
    /// Whether an existing pooled connection was reused.
    pub connection_reused: bool,
    /// Remote IP address of the peer (e.g. "1.2.3.4" or "::1"). None for H3/QUIC.
    pub remote_address: Option<String>,
}

impl HttpResponse {
    /// Decode the response body as text, respecting the charset from the Content-Type header.
    /// Falls back to UTF-8 if no charset is specified or the charset is unknown.
    pub fn text(&self) -> String {
        let ct = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str());
        decode_body_text(&self.body, ct)
    }

    /// Extract the charset from the Content-Type header (e.g. `"utf-8"` from
    /// `"text/html; charset=utf-8"`). Returns `None` if no charset is specified.
    pub fn charset(&self) -> Option<&str> {
        let ct = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())?;
        parse_charset(ct)
    }
}

/// Decode a response body as text using the charset from the Content-Type header value.
/// Falls back to UTF-8 if `content_type` is `None`, has no charset parameter,
/// or specifies an unknown encoding.
pub fn decode_body_text(body: &[u8], content_type: Option<&str>) -> String {
    let charset = content_type.and_then(parse_charset);
    let label = charset.unwrap_or("utf-8");
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::UTF_8);
    let (decoded, _, _) = encoding.decode(body);
    decoded.into_owned()
}

/// Parse the charset value from a Content-Type header string.
/// E.g. `"text/html; charset=shift_jis"` → `Some("shift_jis")`.
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

/// Exported session data (cookies + TLS sessions) for save/load.
///
/// Serialize this to JSON to persist a client's cookies and TLS session
/// tickets across process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExport {
    /// Cookie jar contents as JSON value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<serde_json::Value>,
    /// TLS session tickets: hostname to base64-encoded DER.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_sessions: Option<HashMap<String, String>>,
}

impl super::Client {
    /// Decompress an HTTP/3 response body.
    pub(super) fn decompress_response(
        &self,
        response: HttpResponse,
    ) -> Result<HttpResponse, Error> {
        let content_encoding = response
            .headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(response.body, content_encoding)?;
        Ok(HttpResponse { body, ..response })
    }
}

/// Decompress response body based on Content-Encoding header.
pub(super) fn decompress_body(data: Vec<u8>, encoding: Option<&str>) -> Result<Vec<u8>, Error> {
    match encoding {
        Some("gzip") => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        Some("deflate") => {
            // HTTP "deflate" is zlib-wrapped (RFC 1950), but some servers send raw deflate.
            // Try zlib first, fall back to raw deflate.
            use std::io::Read;
            let mut decoder = flate2::read::ZlibDecoder::new(&data[..]);
            let mut out = Vec::new();
            match decoder.read_to_end(&mut out) {
                Ok(_) => Ok(out),
                Err(_) => {
                    let mut decoder = flate2::read::DeflateDecoder::new(&data[..]);
                    let mut out = Vec::new();
                    decoder.read_to_end(&mut out).map_err(Error::Io)?;
                    Ok(out)
                }
            }
        }
        Some("br") => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(&data), &mut out)
                .map_err(Error::Io)?;
            Ok(out)
        }
        Some("zstd") => {
            use std::io::Read;
            let mut decoder = zstd::Decoder::new(&data[..]).map_err(Error::Io)?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        _ => Ok(data),
    }
}
